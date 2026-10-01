#!/usr/bin/env python3
"""Persistent external D6 peer fixture, never part of the appliance image.

Run on the separately disposable peer VM as root. Configuration and client
private material enter through SSH stdin, never argv or the HTTP registration
service. Namespace resources are UUID-owned and retained on failure/restart.
Only exact owned resources can be reused; this program never adopts or deletes
other resources and never changes the host firewall or global sysctls.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import select
import signal
import socketserver
import stat
import struct
import subprocess  # nosec B404
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path('/var/lib')
MAX_BODY = 4096
MAX_STATE = 65536
ENDPOINTS = {'a': '192.0.0.9', 'b': '192.0.0.10'}
ADDRESSES = {'mullvad': '10.64.0.2/32', 'pia': '10.65.0.2/32', 'proton': '10.66.0.2/32'}
ROLES = ('a', 'b', 'client', 'target')
ROUTES = ('192.0.0.9/32', '192.0.0.10/32', '1.1.1.1/32',
          '10.64.0.1/32', '10.65.0.1/32', '10.66.0.1/32')
ERROR_CODES = frozenset({'fixture_configuration_invalid', 'fixture_request_invalid', 'fixture_command_failed',
                         'fixture_state_unsafe', 'fixture_resource_conflict', 'fixture_host_forwarding_required',
                         'fixture_registration_limit', 'fixture_client_invalid', 'fixture_namespace_required',
                         'fixture_service_failed'})


class FixtureError(RuntimeError):
    """Fixed identifiers only: subprocess output and secrets never escape."""


def run_id(value):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise FixtureError('fixture_configuration_invalid') from None
    if str(parsed) != value:
        raise FixtureError('fixture_configuration_invalid')
    return value


def private_address(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise FixtureError('fixture_configuration_invalid') from None
    if (not address.is_private or address.is_loopback or address.is_unspecified
            or address.is_link_local or address.is_multicast):
        raise FixtureError('fixture_configuration_invalid')
    return str(address)


def configuration(value):
    required = {'run_id', 'candidate_vm_address', 'peer_vm_address', 'token'}
    if not isinstance(value, dict) or set(value) not in (required, required | {'port'}):
        raise FixtureError('fixture_configuration_invalid')
    result = dict(value)
    result['run_id'] = run_id(value['run_id'])
    for key in ('candidate_vm_address', 'peer_vm_address'):
        result[key] = private_address(value[key])
    if result['candidate_vm_address'] == result['peer_vm_address']:
        raise FixtureError('fixture_configuration_invalid')
    if not isinstance(value['token'], str) or re.fullmatch('[0-9a-f]{64}', value['token']) is None:
        raise FixtureError('fixture_configuration_invalid')
    result.setdefault('port', 8991)
    if type(result['port']) is not int or not 1024 <= result['port'] <= 65535:
        raise FixtureError('fixture_configuration_invalid')
    return result


def public_key(value):
    if not isinstance(value, str) or re.fullmatch('[A-Za-z0-9+/]{43}=', value) is None:
        raise FixtureError('fixture_request_invalid')
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise FixtureError('fixture_request_invalid') from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode() != value:
        raise FixtureError('fixture_request_invalid')
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def decode(raw, maximum=MAX_BODY):
    try:
        if not raw or len(raw) > maximum:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_pairs)
        if not isinstance(value, dict):
            raise TypeError
        return value
    except (ValueError, UnicodeError, TypeError):
        raise FixtureError('fixture_request_invalid') from None


def command(arguments, *, data=None):
    """Bounded argv execution; no shell, captured output never in exceptions."""
    try:
        # Validated fixed argv, no shell.
        result = subprocess.run(arguments, input=data, capture_output=True, timeout=10, check=False)  # nosec B603
    except (OSError, subprocess.TimeoutExpired):
        raise FixtureError('fixture_command_failed') from None
    if result.returncode or len(result.stdout) > MAX_STATE or len(result.stderr) > MAX_STATE:
        raise FixtureError('fixture_command_failed')
    return result.stdout


class Store:
    def __init__(self, identifier, *, root=ROOT):
        self.identifier = run_id(identifier)
        self.path = root / ('exitlane-d6-' + self.identifier)

    def directory(self, *, create=False):
        if create:
            self.path.mkdir(mode=0o700, exist_ok=False)
        try:
            facts = self.path.lstat()
            if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != os.geteuid() or stat.S_IMODE(facts.st_mode) != 0o700:
                raise FixtureError('fixture_state_unsafe')
        except OSError:
            raise FixtureError('fixture_state_unsafe') from None

    def read(self, name):
        self.directory()
        fd = None
        try:
            # A FIFO can block at open before fstat rejects it. Nonblocking
            # open preserves the regular-file gate without waiting on a writer.
            fd = os.open(self.path / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            facts = os.fstat(fd)
            if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid()
                    or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_size > MAX_STATE):
                raise FixtureError('fixture_state_unsafe')
            with os.fdopen(fd, 'rb') as stream:
                fd = None
                return decode(stream.read(MAX_STATE + 1), MAX_STATE)
        except OSError:
            raise FixtureError('fixture_state_unsafe') from None
        finally:
            if fd is not None:
                os.close(fd)

    def write(self, name, value):
        self.directory()
        raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_STATE:
            raise FixtureError('fixture_state_unsafe')
        temporary = self.path / ('.' + name + '.new')
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            destination = self.path / name
            if os.path.lexists(destination):
                self.read(name)  # Refuse unsafe existing state, including symlinks.
            os.replace(temporary, destination)
            directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            raise FixtureError('fixture_state_unsafe') from None
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    @contextlib.contextmanager
    def lock(self, *, daemon=False):
        self.directory()
        fd = os.open(self.path / ('daemon.lock' if daemon else 'state.lock'),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            facts = os.fstat(fd)
            if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid() or stat.S_IMODE(facts.st_mode) != 0o600:
                raise FixtureError('fixture_state_unsafe')
            fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if daemon else 0))
            yield
        except OSError:
            raise FixtureError('fixture_resource_conflict') from None
        finally:
            os.close(fd)


class Network:
    def __init__(self, config, store, *, execute=command):
        self.config, self.store, self.execute = config, store, execute
        short = config['run_id'].replace('-', '')[:10]
        self.names = {role: 'ed6-' + short + '-' + role for role in ROLES}
        self.links = {role: 'e' + short + role[0] for role in ROLES}
        self.ownership = None
        self._validated_interfaces = None
        self.daemon_lock = None

    def ns(self, role, *args, data=None):
        return self.execute(['ip', 'netns', 'exec', self.names[role], *args], data=data)

    def _inode(self, role):
        facts = (Path('/run/netns') / self.names[role]).stat()
        return [facts.st_dev, facts.st_ino]

    def _ifindex(self, name):
        values = json.loads(self.execute(['ip', '-j', 'link', 'show', 'dev', name]))
        if len(values) != 1 or values[0]['ifname'] != name:
            raise FixtureError('fixture_resource_conflict')
        return values[0]['ifindex']

    def _namespace_links(self, role):
        values = json.loads(self.ns(role, 'ip', '-j', 'link', 'show'))
        return {value['ifname']: value['ifindex'] for value in values}

    def validate_owned(self):
        facts = self.store.read('ownership.json')
        if (set(facts) != {'names', 'links', 'inodes', 'ifindexes', 'namespace_ifindexes'}
                or facts['names'] != self.names or facts['links'] != self.links):
            raise FixtureError('fixture_resource_conflict')
        try:
            validated = {}
            for role in ROLES:
                if self._inode(role) != facts['inodes'][role] or self._ifindex(self.links[role]) != facts['ifindexes'][role]:
                    raise FixtureError('fixture_resource_conflict')
                current = self._namespace_links(role)
                expected = dict(facts['namespace_ifindexes'][role])
                if role == 'client' and os.path.lexists(self.store.path / 'client.json'):
                    client = self.store.read('client.json')
                    if set(client) != {'ifindex'} or type(client['ifindex']) is not int or client['ifindex'] <= 0:
                        raise FixtureError('fixture_resource_conflict')
                    expected['wg-client'] = client['ifindex']
                if current != expected:
                    raise FixtureError('fixture_resource_conflict')
                validated[role] = expected
        except (OSError, KeyError, ValueError, TypeError):
            raise FixtureError('fixture_resource_conflict') from None
        self.ownership = facts
        self._validated_interfaces = validated

    def ownership_projection(self, role):
        """Read-only launch receipt; never includes keys or the HTTP bearer."""
        if role not in ROLES:
            raise FixtureError('fixture_request_invalid')
        self.validate_owned()
        return {'run_id': self.config['run_id'], 'role': role, 'namespace': self.names[role],
                'namespace_inode': self.ownership['inodes'][role], 'host_link': self.links[role],
                'host_ifindex': self.ownership['ifindexes'][role],
                'interface_ifindexes': dict(self._validated_interfaces[role])}

    def preflight(self):
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
            raise FixtureError('fixture_host_forwarding_required')
        # Debian iproute2 may emit zero bytes, rather than [], for no namespaces.
        # The argv executor already required exit success; only this empty list
        # response has that compatibility meaning.
        existing = json.loads(self.execute(['ip', '-j', 'netns', 'list']) or b'[]')
        if any(value['name'] in self.names.values() for value in existing):
            raise FixtureError('fixture_resource_conflict')
        links = json.loads(self.execute(['ip', '-j', 'link', 'show']))
        if any(value['ifname'] in self.links.values() for value in links):
            raise FixtureError('fixture_resource_conflict')
        routes = json.loads(self.execute(['ip', '-j', 'route', 'show', 'table', 'all']))
        reserved = [ipaddress.ip_network(value) for value in ROUTES]
        reserved += [ipaddress.ip_network(f'169.254.{number}.0/30') for number in range(241, 245)]
        for route in routes:
            destination = route.get('dst', 'default')
            if destination == 'default':
                continue
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError:
                raise FixtureError('fixture_resource_conflict') from None
            if network.version == 4 and any(network.overlaps(item) for item in reserved):
                raise FixtureError('fixture_resource_conflict')

    def setup(self):
        self.preflight()
        for role in ROLES:
            self.execute(['ip', 'netns', 'add', self.names[role]])
            self.ns(role, 'ip', 'link', 'set', 'lo', 'up')
        for number, role in enumerate(ROLES, 241):
            host = self.links[role]
            self.execute(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', host + 'n'])
            self.execute(['ip', 'link', 'set', host + 'n', 'netns', self.names[role]])
            self.ns(role, 'ip', 'link', 'set', host + 'n', 'name', 'uplink')
            self.execute(['ip', 'address', 'add', f'169.254.{number}.1/30', 'dev', host])
            self.execute(['ip', 'link', 'set', host, 'up'])
            self.ns(role, 'ip', 'address', 'add', f'169.254.{number}.2/30', 'dev', 'uplink')
            self.ns(role, 'ip', 'link', 'set', 'uplink', 'up')
            source = []
            if role in ENDPOINTS:
                self.ns(role, 'ip', 'address', 'add', ENDPOINTS[role] + '/32', 'dev', 'lo')
                source = ['src', ENDPOINTS[role]]
            self.ns(role, 'ip', 'route', 'add', self.config['candidate_vm_address'] + '/32',
                    'via', f'169.254.{number}.1', 'dev', 'uplink', *source)
        for number, role in enumerate(('a', 'b'), 251):
            # The target links are namespace-local, with no upstream gateway.
            link = 'p' + role
            self.ns(role, 'ip', 'link', 'add', 'target', 'type', 'veth', 'peer', 'name', link)
            self.ns(role, 'ip', 'link', 'set', link, 'netns', self.names['target'])
            self.ns(role, 'ip', 'address', 'add', f'169.254.{number}.1/30', 'dev', 'target')
            self.ns(role, 'ip', 'link', 'set', 'target', 'up')
            self.ns('target', 'ip', 'address', 'add', f'169.254.{number}.2/30', 'dev', link)
            self.ns('target', 'ip', 'link', 'set', link, 'up')
            self.ns(role, 'ip', 'route', 'add', '1.1.1.1/32', 'via', f'169.254.{number}.2')
            self.execute(['ip', 'route', 'add', ENDPOINTS[role] + '/32',
                          'via', f'169.254.{number - 10}.2', 'dev', self.links[role]])
            self.ns(role, 'ip', 'link', 'add', 'wg-peer', 'type', 'wireguard')
            for subnet in (64, 65, 66):
                self.ns(role, 'ip', 'address', 'add', f'10.{subnet}.0.1/24', 'dev', 'wg-peer')
            self.ns(role, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1')
            candidate = self.config['candidate_vm_address']
            policy = (f'table inet d6_fixture {{ chain output {{ type filter hook output priority 0; policy drop; '
                      f'oifname "lo" accept; oifname "wg-peer" accept; oifname "target" ip daddr 1.1.1.1 accept; '
                      f'oifname "uplink" ip daddr {candidate} udp sport 51820 accept; }}; '
                      'chain forward { type filter hook forward priority 0; policy drop; '
                      'iifname "wg-peer" oifname "target" ip daddr 1.1.1.1 accept; '
                      'iifname "target" oifname "wg-peer" ct state established,related accept; }; }\n'
                      'table ip d6_fixture_nat { chain postrouting { type nat hook postrouting priority srcnat; '
                      'policy accept; iifname "wg-peer" oifname "target" ip daddr 1.1.1.1 masquerade; }; }\n')
            self.ns(role, 'nft', '-f', '/dev/stdin', data=policy.encode())
        self.ns('target', 'ip', 'address', 'add', '1.1.1.1/32', 'dev', 'lo')
        self.ns('target', 'ip', '-6', 'address', 'add', 'fd99::1/128', 'dev', 'lo')
        self.execute(['ip', 'route', 'add', '1.1.1.1/32', 'via', '169.254.244.2', 'dev', self.links['target']])
        # A forbidden plaintext DNS fallback also reaches the independently
        # captured fixture WAN, rather than disappearing toward a real router.
        for address in ('10.64.0.1', '10.65.0.1', '10.66.0.1'):
            self.ns('target', 'ip', 'address', 'add', address + '/32', 'dev', 'lo')
            self.execute(['ip', 'route', 'add', address + '/32', 'via', '169.254.244.2',
                          'dev', self.links['target']])
        target_policy = ('table inet d6_fixture { chain output { type filter hook output priority 0; '
                         'policy drop; oifname "lo" accept; ct state established,related accept; }; '
                         'chain forward { type filter hook forward priority 0; policy drop; }; }\n')
        self.ns('target', 'nft', '-f', '/dev/stdin', data=target_policy.encode())
        client_policy = (f'table inet d6_fixture {{ chain output {{ type filter hook output priority 0; policy drop; '
                         f'oifname "lo" accept; oifname "wg-client" accept; '
                         f'oifname "uplink" ip daddr {self.config["candidate_vm_address"]} udp dport 51820 accept; }}; '
                         'chain forward { type filter hook forward priority 0; policy drop; }; }\n')
        self.ns('client', 'nft', '-f', '/dev/stdin', data=client_policy.encode())
        self.ownership = {'names': self.names, 'links': self.links,
                          'inodes': {role: self._inode(role) for role in ROLES},
                          'ifindexes': {role: self._ifindex(self.links[role]) for role in ROLES},
                          'namespace_ifindexes': {role: self._namespace_links(role) for role in ROLES}}
        self.store.write('ownership.json', self.ownership)

    def apply_keys(self, state):
        self.validate_owned()
        fault_state(self.store)
        for role in ('a', 'b'):
            peers = {}
            for provider, entries in state['registrations'].items():
                for entry in entries:
                    if role in entry['peers']:
                        peers.setdefault(public_key(entry['public_key']), set()).add(ADDRESSES[provider])
            private = public_key(state['keys'][role]['private_key'])
            payload = f'[Interface]\nPrivateKey = {private}\nListenPort = 51820\n'
            for key, addresses in sorted(peers.items()):
                payload += f'[Peer]\nPublicKey = {key}\nAllowedIPs = {",".join(sorted(addresses))}\n'
            self.ns(role, 'wg', 'setconf', 'wg-peer', '/dev/stdin', data=payload.encode())
            self.ns(role, 'ip', 'link', 'set', 'wg-peer', 'up')


def fault_state(store):
    """Desired state is durable so a registration cannot undo a test fault."""
    if not os.path.lexists(store.path / 'faults.json'):
        return {role: {'handshake_off': False, 'dataplane_off': False, 'dns_off': False, 'policy': None}
                for role in ENDPOINTS}
    state = store.read('faults.json')
    if set(state) != set(ENDPOINTS):
        raise FixtureError('fixture_state_unsafe')
    for value in state.values():
        if not isinstance(value, dict) or set(value) != {'handshake_off', 'dataplane_off', 'dns_off', 'policy'}:
            raise FixtureError('fixture_state_unsafe')
        if any(type(value[key]) is not bool for key in ('handshake_off', 'dataplane_off', 'dns_off')):
            raise FixtureError('fixture_state_unsafe')
        policy = value['policy']
        if policy is not None and (not isinstance(policy, dict) or set(policy) != {'handle', 'sha256'}
                                   or type(policy['handle']) is not int or policy['handle'] <= 0
                                   or not isinstance(policy['sha256'], str)
                                   or re.fullmatch('[0-9a-f]{64}', policy['sha256']) is None):
            raise FixtureError('fixture_state_unsafe')
        if (policy is not None) != (value['handshake_off'] or value['dataplane_off'] or value['dns_off']):
            raise FixtureError('fixture_state_unsafe')
    return state


class FaultController:
    """Fixed synthetic failures; never modifies the primary fixture policy."""

    def __init__(self, network):
        self.network = network
        self.store = network.store
        self.table = 'd6_fault_' + network.config['run_id'].replace('-', '')[:10]

    def _policy(self, role):
        try:
            ruleset = json.loads(self.network.ns(role, 'nft', '-j', 'list', 'ruleset'))
            if not isinstance(ruleset, dict) or set(ruleset) != {'nftables'} or not isinstance(ruleset['nftables'], list):
                raise ValueError
            items = []
            tables = []
            for item in ruleset['nftables']:
                if not isinstance(item, dict) or len(item) != 1:
                    raise ValueError
                kind, value = next(iter(item.items()))
                if not isinstance(value, dict):
                    raise TypeError
                if value.get('family') == 'inet' and (value.get('table') == self.table
                                                       or kind == 'table' and value.get('name') == self.table):
                    items.append(item)
                    if kind == 'table':
                        tables.append(value)
            if not items:
                return None
            if len(tables) != 1 or type(tables[0].get('handle')) is not int or tables[0]['handle'] <= 0:
                raise ValueError
            raw = json.dumps(items, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            return {'handle': tables[0]['handle'], 'sha256': hashlib.sha256(raw).hexdigest()}
        except (ValueError, TypeError, KeyError):
            raise FixtureError('fixture_resource_conflict') from None

    def _script(self, previous, desired):
        lines = [f'delete table inet {self.table}'] if previous is not None else []
        if desired['handshake_off'] or desired['dataplane_off'] or desired['dns_off']:
            lines += [f'create table inet {self.table}',
                      f'add chain inet {self.table} input {{ type filter hook input priority -10; policy accept; }}',
                      f'add chain inet {self.table} forward {{ type filter hook forward priority -10; policy accept; }}',
                      f'add chain inet {self.table} output {{ type filter hook output priority -10; policy accept; }}']
            if desired['handshake_off']:
                lines += [f'add rule inet {self.table} input udp dport 51820 drop',
                          f'add rule inet {self.table} output udp sport 51820 drop']
            if desired['dns_off']:
                lines += [f'add rule inet {self.table} input udp dport 53 drop',
                          f'add rule inet {self.table} input tcp dport 53 drop']
            if desired['dataplane_off']:
                # Keep encrypted endpoint traffic on uplink usable, but deny
                # both local inner services (including DNS) and forwarding.
                lines += [f'add rule inet {self.table} input iifname "wg-peer" drop',
                          f'add rule inet {self.table} forward iifname "wg-peer" oifname "target" ip daddr 1.1.1.1 drop']
        return ('\n'.join(lines) + '\n').encode() if lines else None

    def _link_up(self, role):
        try:
            values = json.loads(self.network.ns(role, 'ip', '-j', 'link', 'show', 'dev', 'wg-peer'))
            if (len(values) != 1 or values[0].get('ifname') != 'wg-peer'
                    or values[0].get('ifindex') != self.network._validated_interfaces[role].get('wg-peer')
                    or not isinstance(values[0].get('flags'), list)
                    or not all(isinstance(flag, str) for flag in values[0]['flags'])):
                raise ValueError
            return 'UP' in values[0]['flags']
        except (ValueError, TypeError, KeyError):
            raise FixtureError('fixture_resource_conflict') from None

    def apply(self, request):
        actions = {'handshake_off', 'handshake_on', 'dataplane_off', 'dataplane_on', 'dns_off', 'dns_on'}
        if (not isinstance(request, dict) or set(request) != {'run_id', 'role', 'action'}
                or request['run_id'] != self.network.config['run_id']
                or request['role'] not in ENDPOINTS or request['action'] not in actions):
            raise FixtureError('fixture_request_invalid')
        role = request['role']
        with self.store.lock():
            self.network.validate_owned()
            state = fault_state(self.store)
            previous = self._policy(role)
            if previous != state[role]['policy']:
                raise FixtureError('fixture_resource_conflict')
            if not self._link_up(role):
                raise FixtureError('fixture_resource_conflict')
            component, selected = request['action'].rsplit('_', 1)
            desired = dict(state[role])
            desired[component + '_off'] = selected == 'off'
            # Repeated identical actions observe existing owned state; no broad
            # delete/recreate cycle and no extra mutation is needed.
            if desired != state[role]:
                self.network.validate_owned()
                script = self._script(previous, desired)
                if script is not None and (desired['handshake_off'], desired['dataplane_off'], desired['dns_off']) != (
                        state[role]['handshake_off'], state[role]['dataplane_off'], state[role]['dns_off']):
                    self.network.ns(role, 'nft', '-f', '/dev/stdin', data=script)
                desired['policy'] = self._policy(role)
                if (desired['policy'] is not None) != (desired['handshake_off'] or desired['dataplane_off'] or desired['dns_off']):
                    raise FixtureError('fixture_resource_conflict')
                state[role] = desired
                self.store.write('faults.json', state)
            self.network.validate_owned()
            if not self._link_up(role):
                raise FixtureError('fixture_resource_conflict')
            return {'run_id': request['run_id'], 'role': role,
                    'faults': {key: state[role][key] for key in ('handshake_off', 'dataplane_off', 'dns_off')}}


class UpstreamFixture:
    def __init__(self, config, store, network):
        self.config, self.store, self.network = config, store, network
        self.lock = threading.RLock()
        self.state = store.read('state.json')

    def _save_apply(self, state):
        # Persist desired public registrations before apply; retries/restart are
        # idempotent and can reconcile a partially applied owned namespace.
        self.store.write('state.json', state)
        self.state = state
        self.network.apply_keys(state)

    def register(self, provider, key, peers):
        key = public_key(key)
        entries = self.state['registrations'][provider]
        existing = next((item for item in entries if item['public_key'] == key), None)
        if existing is None:
            if len(entries) >= 8:
                raise FixtureError('fixture_registration_limit')
            existing = {'public_key': key, 'peers': peers,
                        'id': str(uuid.uuid5(uuid.UUID(self.config['run_id']), provider + key))}
            if provider == 'mullvad':
                # A synthetic Mullvad device uses one shared key on both peers.
                self.state['registrations'][provider] = [existing]
            else:
                entries.append(existing)
        else:
            existing['peers'] = sorted(set(existing['peers']) | set(peers))
        if provider in {'pia', 'proton'}:
            # Independent peer namespaces can retain different client keys for
            # the same provider address. Registering B must not revoke A's key:
            # a genuine failed switch still needs the previous A generation.
            for entry in entries:
                if entry is not existing:
                    entry['peers'] = sorted(set(entry['peers']) - set(peers))
            self.state['registrations'][provider] = [entry for entry in entries if entry['peers']]
        self._save_apply(self.state)
        return existing

    @staticmethod
    def device(entry):
        return {'id': entry['id'], 'name': 'Disposable D6 device', 'pubkey': entry['public_key'],
                'ipv4_address': ADDRESSES['mullvad'], 'ipv6_address': None}

    def request(self, payload):
        if not isinstance(payload, dict):
            raise FixtureError('fixture_request_invalid')
        action = payload.get('action')
        contracts = {'mullvad_devices': set(), 'mullvad_relays': set(), 'pia_token': set(),
                     'pia_catalog': set(), 'mullvad_register': {'public_key'},
                     'mullvad_delete': {'device_id'}, 'pia_register': {'public_key', 'peer'},
                     'clock': {'run_id'}, 'select_catalog': {'mullvad', 'pia'}, 'selected_catalog': set()}
        if action not in contracts or set(payload) != {'action'} | contracts[action]:
            raise FixtureError('fixture_request_invalid')
        if action == 'clock':
            if payload['run_id'] != self.config['run_id']:
                raise FixtureError('fixture_request_invalid')
            boot = run_id(Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            return {'reference_ns': time.time_ns(), 'boot_id': boot}
        with self.lock, self.store.lock():
            self.state = self.store.read('state.json')
            if action == 'select_catalog':
                if any(payload[provider] not in {'a', 'b', 'both'} for provider in ('mullvad', 'pia')):
                    raise FixtureError('fixture_request_invalid')
                selection = {provider: list(ENDPOINTS) if payload[provider] == 'both' else [payload[provider]]
                             for provider in ('mullvad', 'pia')}
                self.store.write('catalogs.json', selection)
                return {'run_id': self.config['run_id'], 'catalogs': selection}
            catalogs = self.store.read('catalogs.json') if os.path.lexists(self.store.path / 'catalogs.json') else {
                provider: list(ENDPOINTS) for provider in ('mullvad', 'pia')}
            if (not isinstance(catalogs, dict) or set(catalogs) != {'mullvad', 'pia'}
                    or any(not isinstance(roles, list) or roles not in [['a'], ['b'], ['a', 'b']]
                           for roles in catalogs.values())):
                raise FixtureError('fixture_resource_conflict')
            if action == 'selected_catalog':
                return {'run_id': self.config['run_id'], 'catalogs': catalogs}
            if action == 'mullvad_devices':
                return [self.device(entry) for entry in self.state['registrations']['mullvad']]
            if action == 'mullvad_register':
                return self.device(self.register('mullvad', payload['public_key'], ['a', 'b']))
            if action == 'mullvad_delete':
                identifier = payload['device_id']
                if not isinstance(identifier, str) or re.fullmatch('[a-z0-9-]{36}', identifier) is None:
                    raise FixtureError('fixture_request_invalid')
                self.state['registrations']['mullvad'] = [entry for entry in self.state['registrations']['mullvad']
                                                        if entry['id'] != identifier]
                self._save_apply(self.state)
                return {}
            if action == 'mullvad_relays':
                return [{'type': 'wireguard', 'active': True, 'hostname': f'nl-ams-wg-{role}',
                         'country_code': 'nl', 'city_code': 'ams', 'country_name': 'Netherlands',
                         'city_name': 'Amsterdam', 'ipv4_addr_in': endpoint,
                         'pubkey': self.state['keys'][role]['public_key']} for role, endpoint in ENDPOINTS.items()
                        if role in catalogs['mullvad']]
            if action == 'pia_token':
                return {'available': True}
            if action == 'pia_catalog':
                return [{'region': {'id': role, 'name': f'Synthetic {role}', 'country': 'NL'},
                         'server': {'ip': endpoint, 'cn': f'synthetic-{role}'}, 'address': endpoint}
                        for role, endpoint in ENDPOINTS.items() if role in catalogs['pia']]
            role = payload['peer']
            if role not in ENDPOINTS:
                raise FixtureError('fixture_request_invalid')
            self.register('pia', payload['public_key'], [role])
            return {'status': 'OK', 'peer_ip': ADDRESSES['pia'],
                    'server_key': self.state['keys'][role]['public_key'], 'server_port': 51820,
                    'dns_servers': ['10.65.0.1'], 'peer_pubkey': payload['public_key'], 'server_ip': ENDPOINTS[role]}

    def public_status(self):
        return {'run_id': self.config['run_id'], 'names': self.network.names, 'links': self.network.links,
                'peers': {role: {'endpoint': endpoint, 'public_key': self.state['keys'][role]['public_key'],
                                  'port': 51820} for role, endpoint in ENDPOINTS.items()}}


class RegistrationServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, fixture, *, address=None):
        self.fixture = fixture
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address or (fixture.config['peer_vm_address'], fixture.config['port']), RegistrationHandler)

    def process_request(self, request, client_address):
        request.settimeout(3)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, _request, _client_address):
        pass  # Never print a request, bearer token or exception traceback.


class RegistrationHandler(BaseHTTPRequestHandler):
    server_version = 'ExitLaneD6'

    def log_message(self, *_args):
        pass

    def reply(self, code, value):
        raw = json.dumps(value, separators=(',', ':')).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        fixture = self.server.fixture
        if (self.client_address[0] != fixture.config['candidate_vm_address']
                or self.path != '/upstream' or self.headers.get_all('Authorization') is None
                or len(self.headers.get_all('Authorization')) != 1
                or not hmac.compare_digest(self.headers['Authorization'].encode('latin-1'),
                                           ('Bearer ' + fixture.config['token']).encode())):
            self.reply(403, {'error': 'fixture_unauthorized'})
            return
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if (len(lengths) != 1 or not re.fullmatch('[0-9]{1,4}', lengths[0])
                    or self.headers.get('Transfer-Encoding') is not None
                    or self.headers.get('Content-Type') != 'application/json'):
                raise FixtureError('fixture_request_invalid')
            length = int(lengths[0])
            if not 1 <= length <= MAX_BODY:
                raise FixtureError('fixture_request_invalid')
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise FixtureError('fixture_request_invalid')
            result = fixture.request(decode(raw))
            self.reply(200, {'result': result})
        except FixtureError:
            self.reply(400, {'error': 'fixture_request_failed'})
        except (OSError, ValueError, TypeError, KeyError):
            self.reply(503, {'error': 'fixture_unavailable'})


def client_configuration(value, config):
    if not isinstance(value, dict) or set(value) != {'run_id', 'configuration', 'endpoint'}:
        raise FixtureError('fixture_client_invalid')
    if run_id(value['run_id']) != config['run_id'] or value['endpoint'] != config['candidate_vm_address'] + ':51820':
        raise FixtureError('fixture_client_invalid')
    text = value['configuration']
    if not isinstance(text, str) or not 1 <= len(text) <= 8192 or '\x00' in text:
        raise FixtureError('fixture_client_invalid')
    sections = {'Interface': {}, 'Peer': {}}
    current = None
    seen = set()
    permitted = {'Interface': {'PrivateKey', 'Address', 'DNS', 'MTU'},
                 'Peer': {'PublicKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'}}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            current = line[1:-1] if line.endswith(']') else None
            if current not in sections or current in seen:
                raise FixtureError('fixture_client_invalid')
            seen.add(current)
            continue
        if current is None or '=' not in line:
            raise FixtureError('fixture_client_invalid')
        key, field = (item.strip() for item in line.split('=', 1))
        if key not in permitted[current] or key in sections[current]:
            raise FixtureError('fixture_client_invalid')
        sections[current][key] = field
    try:
        private = public_key(sections['Interface']['PrivateKey'])
        server = public_key(sections['Peer']['PublicKey'])
        address = ipaddress.ip_interface(sections['Interface']['Address'])
        if address.version != 4 or address.ip != ipaddress.ip_address('10.77.0.2'):
            raise ValueError
        for network in sections['Peer']['AllowedIPs'].split(','):
            ipaddress.ip_network(network.strip(), strict=False)
    except (KeyError, ValueError, TypeError):
        raise FixtureError('fixture_client_invalid') from None
    return f'[Interface]\nPrivateKey = {private}\n[Peer]\nPublicKey = {server}\nEndpoint = {value["endpoint"]}\nAllowedIPs = 1.1.1.1/32,10.77.0.1/32,10.64.0.1/32,10.65.0.1/32,10.66.0.1/32,fd99::1/128\nPersistentKeepalive = 1\n'


def configure_client(value, config, store, network):
    payload = client_configuration(value, config)
    network.validate_owned()
    # Creation is once-only; recorded ifindex pins all subsequent replacements.
    try:
        ownership = store.read('client.json')
    except FixtureError:
        if os.path.lexists(store.path / 'client.json'):
            raise
        existing = json.loads(network.ns('client', 'ip', '-j', 'link', 'show'))
        if any(link['ifname'] == 'wg-client' for link in existing):
            raise FixtureError('fixture_resource_conflict')
        network.ns('client', 'ip', 'link', 'add', 'wg-client', 'type', 'wireguard')
        facts = json.loads(network.ns('client', 'ip', '-j', 'link', 'show', 'dev', 'wg-client'))[0]
        store.write('client.json', {'ifindex': facts['ifindex']})
    else:
        facts = json.loads(network.ns('client', 'ip', '-j', 'link', 'show', 'dev', 'wg-client'))[0]
        if ownership != {'ifindex': facts['ifindex']}:
            raise FixtureError('fixture_resource_conflict')
    network.ns('client', 'wg', 'setconf', 'wg-client', '/dev/stdin', data=payload.encode())
    network.ns('client', 'ip', 'link', 'set', 'wg-client', 'up')
    # Linux refuses routes through a DOWN WireGuard interface. Reconcile only
    # fixed fixture routes after proving this same interface's recorded ifindex.
    network.ns('client', 'ip', 'address', 'replace', '10.77.0.2/32', 'dev', 'wg-client')
    network.ns('client', 'ip', '-6', 'address', 'replace', 'fd99:77::2/128', 'dev', 'wg-client')
    for route in ('1.1.1.1/32', '10.77.0.1/32', '10.64.0.1/32', '10.65.0.1/32', '10.66.0.1/32'):
        network.ns('client', 'ip', 'route', 'replace', route, 'dev', 'wg-client')
    network.ns('client', 'ip', '-6', 'route', 'replace', 'fd99::1/128', 'dev', 'wg-client')


def dns_answer(query):
    if not 17 <= len(query) <= 512 or query[4:12] != b'\x00\x01\x00\x00\x00\x00\x00\x00':
        return None
    offset = 12
    while offset < len(query) and query[offset]:
        length = query[offset]
        if length > 63 or offset + length + 1 >= len(query):
            return None
        offset += length + 1
    if offset + 5 != len(query) or query[offset + 1:] != b'\x00\x01\x00\x01':
        return None
    return (query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:]
            + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x01\x01\x01\x01')


def namespace_services(role):
    if Path('/proc/self/ns/net').stat().st_ino == Path('/proc/1/ns/net').stat().st_ino:
        raise FixtureError('fixture_namespace_required')
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            body, transport = self.request
            answer = dns_answer(body) if self.server.server_address[1] == 53 else body if len(body) <= 1024 else None
            if answer:
                transport.sendto(answer, self.client_address)
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                if self.server.server_address[1] == 53:
                    prefix = self.request.recv(2)
                    if len(prefix) != 2:
                        return
                    length = struct.unpack('!H', prefix)[0]
                    if not 1 <= length <= 512:
                        return
                    body = b''
                    while len(body) < length:
                        part = self.request.recv(length - len(body))
                        if not part:
                            return
                        body += part
                    answer = dns_answer(body)
                    if answer:
                        self.request.sendall(struct.pack('!H', len(answer)) + answer)
                else:
                    body = self.request.recv(1025)
                    if 0 < len(body) <= 1024:
                        self.request.sendall(body)
            except OSError:
                pass
    # Bind only after verifying that this child is outside the host namespace.
    servers = []
    if role not in {'peer', 'target'}:
        raise FixtureError('fixture_request_invalid')
    dns_addresses = ('10.64.0.1', '10.65.0.1', '10.66.0.1')
    # UDP sendto on a wildcard socket can choose an uplink/interface source
    # instead of the queried local address, breaking conntrack and DNS clients.
    udp_bindings = [(address, 53) for address in dns_addresses]
    if role == 'target':
        udp_bindings += [('1.1.1.1', port) for port in (53, 5666, 7777)]
    for binding in udp_bindings:
        servers.append(socketserver.UDPServer(binding, UDP))
    for port in ((53,) if role == 'peer' else (53, 5666, 7778)):
        servers.append(socketserver.TCPServer(('0.0.0.0', port), TCP))  # nosec B104
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print('ready', flush=True)
    threading.Event().wait()


def initialize(config, store, network):
    fresh = not os.path.lexists(store.path)
    if not fresh:
        if store.read('config.json') != config:
            raise FixtureError('fixture_resource_conflict')
        network.validate_owned()
    else:
        network.preflight()
        store.directory(create=True)
        store.write('config.json', config)
    network.daemon_lock = store.lock(daemon=True)
    network.daemon_lock.__enter__()
    if fresh:
        keys = {}
        for role in ('a', 'b'):
            private = public_key(command(['wg', 'genkey']).decode().strip())
            public = public_key(command(['wg', 'pubkey'], data=(private + '\n').encode()).decode().strip())
            keys[role] = {'private_key': private, 'public_key': public}
        store.write('state.json', {'keys': keys, 'registrations': {provider: [] for provider in ADDRESSES}})
        network.setup()
    fixture = UpstreamFixture(config, store, network)
    with store.lock():
        fixture.state = store.read('state.json')
        network.apply_keys(fixture.state)
    return fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('serve', 'client', 'status', 'proton', 'services', 'ownership', 'fault', 'catalog'))
    parser.add_argument('role', nargs='?', choices=('peer', 'target'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        print('fixture_root_required', file=sys.stderr)
        return 77
    os.umask(0o077)
    children = []
    try:
        if args.command == 'services':
            if args.role is None:
                raise FixtureError('fixture_request_invalid')
            namespace_services(args.role)
            return 0
        value = decode(sys.stdin.buffer.read(16385), 16384)
        if args.command == 'serve':
            config = configuration(value)
        else:
            store = Store(value.get('run_id'))
            config = configuration(store.read('config.json'))
        store = Store(config['run_id'])
        network = Network(config, store)
        if args.command == 'serve':
            fixture = initialize(config, store, network)
            for role in ('a', 'b', 'target'):
                network.validate_owned()
                # Fixed child argv in verified invocation-owned namespace.
                child_arguments = ['ip', 'netns', 'exec', network.names[role],
                                   sys.executable, str(Path(__file__).resolve()),
                                   'services', 'target' if role == 'target' else 'peer']
                child = subprocess.Popen(child_arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)  # nosec B603
                children.append(child)
                ready, _, _ = select.select([children[-1].stdout], [], [], 3)
                if not ready or children[-1].stdout.readline(16) != b'ready\n':
                    raise FixtureError('fixture_service_failed')
            def interrupted(_signum, _frame):
                raise KeyboardInterrupt
            signal.signal(signal.SIGTERM, interrupted)
            print(json.dumps(fixture.public_status()), flush=True)
            with RegistrationServer(fixture) as server:
                server.serve_forever(poll_interval=0.2)
        elif args.command == 'client':
            with store.lock():
                configure_client(value, config, store, network)
            print(json.dumps({'configured': True}))
        elif args.command == 'ownership':
            if set(value) != {'run_id', 'role'}:
                raise FixtureError('fixture_request_invalid')
            print(json.dumps(network.ownership_projection(value['role'])))
        elif args.command == 'fault':
            print(json.dumps(FaultController(network).apply(value)))
        else:
            network.validate_owned()
            fixture = UpstreamFixture(config, store, network)
            if args.command == 'catalog':
                if set(value) == {'run_id'}:
                    result = fixture.request({'action': 'selected_catalog'})
                elif set(value) == {'run_id', 'mullvad', 'pia'}:
                    result = fixture.request({'action': 'select_catalog', 'mullvad': value['mullvad'], 'pia': value['pia']})
                else:
                    raise FixtureError('fixture_request_invalid')
                print(json.dumps(result))
            elif args.command == 'proton':
                if set(value) != {'run_id', 'public_key', 'peer'} or value['peer'] not in ENDPOINTS:
                    raise FixtureError('fixture_request_invalid')
                with fixture.lock, store.lock():
                    fixture.state = store.read('state.json')
                    fixture.register('proton', value['public_key'], [value['peer']])
                print(json.dumps({'registered': True}))
            else:
                if set(value) != {'run_id'}:
                    raise FixtureError('fixture_request_invalid')
                print(json.dumps(fixture.public_status()))
        return 0
    except KeyboardInterrupt:
        return 130
    except FixtureError as error:
        print(str(error) if str(error) in ERROR_CODES else 'fixture_operation_failed', file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError):
        print('fixture_operation_failed', file=sys.stderr)
        return 1
    finally:
        for child in children:
            child.terminate()
        for child in children:
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=3)


if __name__ == '__main__':
    raise SystemExit(main())
