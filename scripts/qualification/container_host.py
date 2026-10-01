#!/usr/bin/env python3
"""D6 two-host qualification coordinator, never an appliance entrypoint.

Requires two explicitly disposable hosts and an existing private SSH identity.
Secrets travel only on SSH stdin. Every mutation checks the exact guest hostname;
daemon/host faults additionally refuse foreign containers. Packet acceptance is
separate: a healthy restarted container alone is never a qualification PASS.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import secrets
import stat
import subprocess  # nosec B404
import sys
import time
import uuid
from pathlib import Path

from container_appliance import HTTP, PAIR, ApplianceHarness

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
HOSTNAME = re.compile(r'exitlane-docker-d6-(?:peer-)?[a-z0-9-]{1,40}\Z')


class QualificationError(RuntimeError):
    pass


def _packet_acceptance_observations(observers):
    """Map owned interfaces to the explicit seven-point D6 packet contract.

    A capture process may observe several links in one namespace. The packet
    validator models logical acceptance points, so provider wg-peer interfaces
    and the three target links need stable aliases independent of handle shape.
    Supplemental links remain captured in the raw observer evidence.
    """
    required = {'wan', 'client', 'provider-a', 'provider-b',
                'target-pa', 'target-pb', 'target-uplink'}
    result = {}
    for role, interfaces in observers:
        if not isinstance(interfaces, dict):
            raise QualificationError('qualification_packet_topology_mismatch')
        aliases = {
            'wan': {'eth0': 'wan'},
            'client': {'wg-client': 'client'},
            'provider-a': {'wg-peer': 'provider-a'},
            'provider-b': {'wg-peer': 'provider-b'},
            'target': {'pa': 'target-pa', 'pb': 'target-pb', 'uplink': 'target-uplink'},
        }.get(role, {})
        for interface, facts in interfaces.items():
            point = aliases.get(interface)
            # Preserve the established one-link handle contract for any
            # supported test topology that names that logical point directly.
            if point is None and len(interfaces) == 1 and interface == role:
                point = role
            if point is not None:
                if point in result:
                    raise QualificationError('qualification_packet_topology_mismatch')
                result[point] = facts
    if set(result) != required:
        raise QualificationError('qualification_packet_topology_mismatch')
    return result


def validate_config(value):
    required = {'run_id', 'candidate', 'peer', 'identity', 'known_hosts', 'image',
                'revision', 'allow_host_restart'}
    if not isinstance(value, dict) or set(value) != required:
        raise QualificationError('qualification_config_invalid')
    try:
        if str(uuid.UUID(value['run_id'])) != value['run_id']:
            raise ValueError
        for role in ('candidate', 'peer'):
            host = value[role]
            if set(host) != {'address', 'hostname', 'user'}:
                raise ValueError
            address = ipaddress.IPv4Address(host['address'])
            if (not address.is_private or address.is_loopback or address.is_unspecified
                    or HOSTNAME.fullmatch(host['hostname']) is None
                    or re.fullmatch('[a-z][a-z0-9_-]{0,31}', host['user']) is None):
                raise ValueError
        if value['candidate']['address'] == value['peer']['address']:
            raise ValueError
        if value['candidate']['hostname'] == value['peer']['hostname']:
            raise ValueError
        if not IMAGE.fullmatch(value['image']) or not re.fullmatch('[a-f0-9]{40}', value['revision']):
            raise ValueError
        if type(value['allow_host_restart']) is not bool:
            raise ValueError
        for field in ('identity', 'known_hosts'):
            path = Path(value[field])
            if not path.is_absolute() or '\n' in str(path) or path.is_symlink():
                raise ValueError
            facts = path.stat()
            if not stat.S_ISREG(facts.st_mode) or stat.S_IMODE(facts.st_mode) & 0o077:
                raise ValueError
    except (ValueError, TypeError, KeyError, OSError):
        raise QualificationError('qualification_config_invalid') from None
    return value


class Remote:
    def __init__(self, host, identity, known_hosts):
        self.host = host
        self.arguments = ['ssh', '-i', identity, '-o', 'IdentitiesOnly=yes',
                          '-o', 'BatchMode=yes', '-o', 'ForwardAgent=no',
                          '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5',
                          '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
                          '-o', 'UserKnownHostsFile=' + known_hosts,
                          host['user'] + '@' + host['address'], 'sudo', 'python3', '-']

    def run(self, source, *, data=None, timeout=60, check=True, output_limit=1048576):
        if type(output_limit) is not int or not 1 <= output_limit <= 32 * 1024 * 1024:
            raise QualificationError('qualification_output_limit_invalid')
        # Data is Python-literal encoded inside SSH stdin, never a shell/argv.
        header = ("import os,json,subprocess,sys,time\n"
                  + "if os.uname().nodename != " + repr(self.host['hostname'])
                  + ": raise SystemExit('qualification_host_identity_mismatch')\n"
                  + "payload=json.loads(" + repr(json.dumps(data)) + ")\n")
        try:
            result = subprocess.run(self.arguments, input=header + source, text=True,
                                    capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            if not check:
                return None
            raise QualificationError('qualification_remote_unavailable') from None
        if result.returncode or len(result.stdout) > output_limit or len(result.stderr) > output_limit:
            if not check:
                return None
            # Child output may contain cookies/configuration; never interpolate.
            raise QualificationError('qualification_remote_operation_failed')
        return result.stdout


COMMAND = '''
r=subprocess.run(payload['argv'],input=payload.get('input'),text=True,capture_output=True,
                 timeout=payload.get('timeout',40),check=False)
if len(r.stdout)>1048576 or len(r.stderr)>1048576:raise SystemExit('qualification_output_limit')
print(json.dumps({'code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}))
'''


class HostHarness:
    def __init__(self, config):
        self.config = validate_config(config)
        self.candidate = Remote(config['candidate'], config['identity'], config['known_hosts'])
        self.peer = Remote(config['peer'], config['identity'], config['known_hosts'])
        self.prefix = 'exitlane-d6-' + uuid.UUID(config['run_id']).hex[:12]
        self.network = self.prefix + '-network'
        self.volume = self.prefix + '-state'
        self.container = self.prefix + '-appliance'
        self.cookie = ''
        self.receipts = []

    def command(self, host, argv, *, data=None, timeout=40, check=True):
        value = json.loads(host.run(COMMAND, data={'argv': argv, 'input': data, 'timeout': timeout},
                                    timeout=timeout + 15))
        if check and value['code']:
            raise QualificationError('qualification_command_failed')
        return value

    def docker(self, *arguments, data=None, timeout=40, check=True):
        return self.command(self.candidate, ['docker', *arguments], data=data, timeout=timeout, check=check)

    def wait(self, probe, stage, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if probe():
                self.receipts.append({'stage': stage, 'time_ns': time.time_ns()})
                return
            time.sleep(.25)
        raise QualificationError('qualification_bounded_gate_failed:' + stage)

    def preflight(self):
        from check_docker_appliance_host import validate_host
        version = json.loads(self.docker('version', '--format', '{{json .Server.Version}}')['stdout'])
        info = json.loads(self.docker('info', '--format', '{{json .}}')['stdout'])
        compose = json.loads(self.docker('compose', 'version', '--format', 'json')['stdout'])['version']
        validate_host(version, info, compose)
        image = json.loads(self.docker('image', 'inspect', self.config['image'])['stdout'])[0]
        labels = image['Config']['Labels']
        if (image['Architecture'] != 'amd64' or image['Os'] != 'linux'
                or labels.get('org.opencontainers.image.revision') != self.config['revision']
                or labels.get('org.exitlane.support') != 'experimental'):
            raise QualificationError('qualification_image_identity_mismatch')
        self.assert_disposable()
        self.receipts.append({'stage': 'preflight', 'engine': version, 'compose': compose,
                              'image': image['Id'], 'revision': self.config['revision']})

    def assert_disposable(self):
        names = self.docker('ps', '-a', '--format', '{{.Names}}')['stdout'].splitlines()
        if any(not name.startswith(self.prefix + '-') for name in names):
            raise QualificationError('qualification_foreign_container_present')
        for name in names:
            self.assert_owned('container', name)

    def assert_owned(self, kind, name):
        value = json.loads(self.docker(kind, 'inspect', name)['stdout'])[0]
        labels = value.get('Labels') if kind in {'network', 'volume'} else value['Config']['Labels']
        if not labels or labels.get('org.exitlane.qualification.run') != self.config['run_id']:
            raise QualificationError('qualification_resource_ownership_mismatch')
        return value

    def create(self, image=None):
        # Private bounded container tmpfs, never a host temporary file.
        private_tmpfs = '/tmp:rw,noexec,nosuid,mode=0700,size=64m'  # nosec B108
        arguments = ['create', '--name', self.container, '--label',
                     'org.exitlane.qualification.run=' + self.config['run_id'],
                     '--network', self.network, '--init', '--restart', 'unless-stopped',
                     '--read-only', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                     '--device', '/dev/net/tun', '--security-opt', 'no-new-privileges:true',
                     '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv6.conf.all.forwarding=0',
                     '--sysctl', 'net.ipv6.conf.default.forwarding=0',
                     '--sysctl', 'net.ipv4.ping_group_range=0 0',
                     '--tmpfs', '/run:rw,noexec,nosuid,mode=0700,size=32m',
                     '--tmpfs', private_tmpfs,
                     '--mount', 'type=volume,src=' + self.volume + ',dst=/data',
                     '--memory', '2g', '--cpus', '2', '--pids-limit', '128',
                     '--log-opt', 'max-size=10m', '--log-opt', 'max-file=3',
                     '--publish', '127.0.0.1:8787:8787/tcp',
                     '--publish', self.config['candidate']['address'] + ':51820:51820/udp',
                     image or self.config['image']]
        self.docker(*arguments)
        self.docker('start', self.container)
        self.wait(self.healthy, 'container_ready')

    def healthy(self):
        try:
            return self.docker('exec', self.container, 'python', '-m',
                               'exitlane.container_entrypoint', 'health', check=False)['code'] == 0
        except QualificationError:
            return False

    def prepare(self):
        self.preflight()
        label = 'org.exitlane.qualification.run=' + self.config['run_id']
        # Existing names are errors. There is no adoption/reconfiguration path.
        self.docker('network', 'create', '--label', label, self.network)
        self.docker('volume', 'create', '--label', label, self.volume)
        self.create()
        self.receipts.append({'stage': 'canonical_image_ready', 'image': self.config['image']})

    def install_fixture_routes(self):
        """Keep only exact synthetic routes across reboot; Docker owns its firewall."""
        self.assert_disposable()
        identifier = self.config['run_id']
        routes = ['192.0.0.9/32', '192.0.0.10/32', '1.1.1.1/32', '169.254.243.2/32',
                  '10.64.0.1/32', '10.65.0.1/32', '10.66.0.1/32']
        gateway = self.config['peer']['address']
        program = '''import json,subprocess
routes=ROUTES
gateway=GATEWAY
for destination in routes:
 values=json.loads(subprocess.run(['ip','-j','route','show','exact',destination],capture_output=True,text=True,check=True).stdout)
 if values:
  if len(values)!=1 or values[0].get('gateway')!=gateway:raise SystemExit('qualification_route_conflict')
 else:subprocess.run(['ip','route','add',destination,'via',gateway],check=True)
'''.replace('ROUTES', repr(routes)).replace('GATEWAY', repr(gateway))
        directory = '/var/lib/exitlane-qualification/' + identifier
        unit = 'exitlane-d6-network-' + identifier + '.service'
        contents = ('[Unit]\nDescription=ExitLane disposable D6 synthetic routes\n'
                    'Wants=network-online.target\nAfter=network-online.target\nBefore=docker.service\n'
                    '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                    'ExecStart=/usr/bin/python3 ' + directory + '/routes.py\n'
                    '[Install]\nWantedBy=multi-user.target\n')
        self.candidate.run('''from pathlib import Path
root=Path(payload['directory'])
root.mkdir(mode=0o700,exist_ok=False)
script=root/'routes.py';script.write_text(payload['program']);script.chmod(0o600)
unit=Path('/etc/systemd/system')/payload['unit']
if unit.exists() or unit.is_symlink():raise SystemExit('qualification_unit_conflict')
unit.write_text(payload['contents']);unit.chmod(0o644)
drop=Path('/etc/systemd/system/docker.service.d');drop.mkdir(mode=0o755,exist_ok=True)
owned=drop/('exitlane-d6-'+payload['identifier']+'.conf')
if owned.exists() or owned.is_symlink():raise SystemExit('qualification_unit_conflict')
owned.write_text('[Unit]\\nRequires='+payload['unit']+'\\nAfter='+payload['unit']+'\\n')
owned.chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now',payload['unit']],check=True,timeout=30)
''', data={'directory': directory, 'identifier': identifier, 'program': program,
           'unit': unit, 'contents': contents})
        self.receipts.append({'stage': 'synthetic_routes_persisted', 'destinations': routes,
                              'host_firewall_modified': False})

    def api(self, path, *, method='GET', body=None, timeout=8):
        if type(timeout) is not int or not 1 <= timeout <= 180:
            raise QualificationError('qualification_api_timeout_invalid')
        data = {'address': '127.0.0.1', 'path': path, 'method': method, 'body': body,
                'headers': {'Cookie': self.cookie} if self.cookie else {}}
        # The shared HTTP helper reads stdin; here its stdin is an in-memory
        # StringIO inside the fixed SSH interpreter, never an argument/env/file.
        source = "import io\nsys.stdin=io.StringIO(json.dumps(payload))\n" + HTTP.replace('timeout=8)', 'timeout=' + str(timeout) + ')')
        return json.loads(self.candidate.run(source, data=data, timeout=timeout + 10))

    def onboarding(self):
        value = self.api('/api/setup/admin', method='POST', body={
            'username': 'synthetic_admin', 'password': 'synthetic-only-' + secrets.token_hex(18)})
        if value['status'] != 200:
            raise QualificationError('qualification_onboarding_failed')
        self.cookie = ApplianceHarness.cookie(value)
        address = self.config['candidate']['address']
        result = self.api('/api/ingress/wireguard', method='POST', body={
            'endpoint': address, 'interface': 'wg-office', 'subnet': '10.77.0.0/24',
            'client': 'synthetic_router', 'dns': '10.64.0.1', 'port': 51820})
        if result['status'] != 200:
            raise QualificationError('qualification_ingress_creation_failed')
        profile = self.api('/api/ingress/wireguard/config')
        if profile['status'] != 200 or not profile['body']['available']:
            raise QualificationError('qualification_ingress_profile_unavailable')
        return profile['body']['configuration']

    def pair(self):
        value = self.docker('exec', self.container, 'python', '-c', PAIR)
        return json.loads(value['stdout'])

    def synthetic_image(self, token):
        """Derivative changes upstream responses only; never a production image."""
        if re.fullmatch('[a-f0-9]{64}', token) is None:
            raise QualificationError('qualification_fixture_token_invalid')
        self.assert_owned('container', self.container)
        original_pair = self.pair()
        self.docker('stop', '--time', '15', self.container)
        setup = self.prefix + '-fixture-config'
        code = '''import json,os,sys
payload=json.load(sys.stdin)
descriptor=os.open('/data/.d6-upstream.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(descriptor,'w') as out:json.dump(payload,out);out.flush();os.fsync(out.fileno())
'''
        self.docker('run', '--rm', '--name', setup, '--label',
                    'org.exitlane.qualification.run=' + self.config['run_id'], '--network', 'none',
                    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                    '--mount', 'type=volume,src=' + self.volume + ',dst=/data', '-i',
                    self.config['image'], 'python', '-c', code,
                    data=json.dumps({'address': self.config['peer']['address'], 'port': 8991, 'token': token}))
        base, derived = self.prefix + '-base:fixture', self.prefix + '-synthetic:fixture'
        self.docker('image', 'tag', self.config['image'], base)
        paths = ('scripts/qualification/container_host_upstream.py',
                 'docker/testing/sitecustomize_d6.py', 'docker/testing/Dockerfile.host-qualification')
        files = {path: (Path(__file__).resolve().parents[2] / path).read_text() for path in paths}
        self.candidate.run('''from pathlib import Path
root=Path('/var/lib/exitlane-qualification/source')
for name,content in payload.items():
 p=root/name
 if p.exists() or p.is_symlink():raise SystemExit('qualification_source_collision')
 p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(content);p.chmod(0o600)
''', data=files)
        self.command(self.candidate, ['docker', 'build', '--network=none', '--pull=false',
                     '--build-arg', 'EXITLANE_BASE=' + base, '-f',
                     '/var/lib/exitlane-qualification/source/docker/testing/Dockerfile.host-qualification',
                     '-t', derived, '/var/lib/exitlane-qualification/source'], timeout=150)
        identity = json.loads(self.docker('image', 'inspect', derived)['stdout'])[0]['Id']
        if identity == self.config['image'] or IMAGE.fullmatch(identity) is None:
            raise QualificationError('qualification_derivative_identity_invalid')
        self.docker('rm', self.container)
        self.create(image=identity)
        if self.pair() != original_pair:
            raise QualificationError('qualification_durable_pair_changed')
        self.receipts.append({'stage': 'synthetic_upstream_derivative', 'canonical': self.config['image'],
                              'derivative': identity, 'production_lifecycle_replaced': False})
        return identity

    def external_process(self, kind, role, *, interfaces=(), namespace=None, source_address=None, family=4):
        """Start an independent sender/observer; no credentials in its process arguments."""
        if type(family) is not int or family not in {4, 6}:
            raise QualificationError('qualification_family_invalid')
        role_pattern = '[a-z][a-z0-9_-]{0,39}' if kind == 'sender' else '[a-z][a-z0-9-]{0,30}'
        if kind not in {'capture', 'sender'} or re.fullmatch(role_pattern, role) is None:
            raise QualificationError('qualification_process_invalid')
        if kind == 'sender' and namespace is None:
            raise QualificationError('qualification_namespace_required')
        host = self.peer
        identifier = uuid.uuid4().hex
        root = '/run/exitlane-d6-' + identifier
        unit = 'exitlane-d6-' + kind + '-' + identifier + '.service'
        script_name = ('container_host_packets.py' if kind == 'capture' else
                       'container_host_sender.py' if family == 4 else 'container_host_ipv6.py')
        script_path = '/var/lib/exitlane-qualification/' + script_name
        command = ['/usr/bin/python3', script_path]
        if namespace is not None:
            permitted = {'ed6-' + self.config['run_id'].replace('-', '')[:10] + '-' + item
                         for item in ('a', 'b', 'client', 'target')}
            if namespace not in permitted:
                raise QualificationError('qualification_namespace_invalid')
            role_name = next(item for item in ('a', 'b', 'client', 'target')
                             if namespace.endswith('-' + item))
            ownership = self.command(self.peer, ['/usr/bin/python3',
                '/var/lib/exitlane-qualification/container_host_peer.py', 'ownership'],
                data=json.dumps({'run_id': self.config['run_id'], 'role': role_name}))
            projection = json.loads(ownership['stdout'])
            if (projection['run_id'] != self.config['run_id']
                    or projection['role'] != role_name or projection['namespace'] != namespace):
                raise QualificationError('qualification_namespace_ownership_mismatch')
            command = ['/usr/sbin/ip', 'netns', 'exec', namespace, *command]
        addresses = [self.config['candidate']['address'], self.config['peer']['address'],
                     '192.0.0.9', '192.0.0.10', '1.1.1.1', '10.77.0.1', '10.77.0.2',
                     '10.64.0.1', '10.64.0.2', '10.65.0.1', '10.65.0.2',
                     '10.66.0.1', '10.66.0.2', 'fd99::1', 'fd99:77::2', '169.254.243.2']
        configuration = ({'interfaces': list(interfaces), 'addresses': addresses, 'run_dir': root}
                         if kind == 'capture' else {'source': source_address, 'interface': 'wg-client',
                            'run_dir': root, 'deadline_seconds': 1800, 'dns': '1.1.1.1',
                            'namespace_inode': projection['namespace_inode'],
                            'ifindex': projection['interface_ifindexes']['wg-client']})
        if kind == 'sender' and family == 6:
            configuration = {'mode': 'send', 'interface': 'wg-client', 'run_dir': root,
                             'deadline_seconds': 1800, 'namespace_inode': projection['namespace_inode'],
                             'ifindex': projection['interface_ifindexes']['wg-client']}
        file_path = '/var/lib/exitlane-qualification/' + identifier + '.json'
        log_path = '/var/lib/exitlane-qualification/' + identifier + '.log'
        # Every command component is a fixed executable, validated namespace or
        # owned path; unit parsing has no shell and no user-supplied interpolation.
        unit_text = ('[Unit]\nDescription=ExitLane D6 external ' + kind + '\n'
                     '[Service]\nExecStart=' + ' '.join(command) + '\n'
                     'StandardInput=file:' + file_path + '\n'
                     'StandardOutput=append:' + log_path + '\nStandardError=append:' + log_path + '\n'
                     'KillMode=control-group\nTimeoutStopSec=10\n')
        host.run('''from pathlib import Path
root=Path('/var/lib/exitlane-qualification')
script=root/payload['script_name']
if script.is_symlink():raise SystemExit('qualification_source_unsafe')
if script.exists() and script.read_text()!=payload['source']:raise SystemExit('qualification_source_mismatch')
if not script.exists():script.write_text(payload['source']);script.chmod(0o600)
for p,text in ((Path(payload['config_path']),json.dumps(payload['configuration'])),(Path(payload['log_path']),'')):
 if p.exists() or p.is_symlink():raise SystemExit('qualification_process_collision')
 p.write_text(text);p.chmod(0o600)
unit=Path('/etc/systemd/system')/payload['unit']
if unit.exists() or unit.is_symlink():raise SystemExit('qualification_unit_collision')
unit.write_text(payload['unit_text']);unit.chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','start',payload['unit']],check=True,timeout=30)
''', data={'source': Path(__file__).with_name(script_name).read_text(), 'script_name': script_name,
           'unit': unit, 'unit_text': unit_text, 'config_path': file_path,
           'log_path': log_path, 'configuration': configuration})
        handle = {'kind': kind, 'role': role, 'root': root, 'unit': unit,
                  'interfaces': list(interfaces), 'namespace': namespace, 'family': family}
        self.wait(lambda: host.run("from pathlib import Path\nprint(Path(payload).is_dir())\n",
                                   data=root).strip() == 'True', role + '_process_directory', timeout=20)
        return handle

    def control(self, handle, phase, *, stop=False, calibration_phase=None):
        if (re.fullmatch('[a-z][a-z0-9_-]{0,39}', phase) is None or type(stop) is not bool
                or calibration_phase is not None and re.fullmatch('[a-z][a-z0-9_-]{0,39}', calibration_phase) is None):
            raise QualificationError('qualification_phase_invalid')
        value = {'phase': phase, 'stop': stop}
        if handle['kind'] == 'capture':
            value['calibration_phase'] = calibration_phase or ('calibration6' if handle.get('family', 4) == 6 else 'calibration')
        host = self.candidate if handle.get('host') == 'candidate' else self.peer
        host.run('''from pathlib import Path
root=Path(payload['root'])
if root.is_symlink() or root.stat().st_uid!=0 or root.stat().st_mode&0o077:raise SystemExit('qualification_control_unsafe')
temporary=root/'.control.new'
descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
with os.fdopen(descriptor,'w') as out:json.dump(payload['value'],out);out.flush();os.fsync(out.fileno())
os.replace(temporary,root/'control.json')
''', data={'root': handle['root'], 'value': value})

    def evidence(self, handle):
        if (handle.get('kind') not in {'capture', 'sender'}
                or re.fullmatch('/run/exitlane-d6-[a-f0-9]{32}', handle.get('root', '')) is None):
            raise QualificationError('qualification_receipt_handle_invalid')
        filename = 'receipts.json' if handle['kind'] == 'capture' else 'sender.json'
        host = self.candidate if handle.get('host') == 'candidate' else self.peer
        return json.loads(host.run('''from pathlib import Path
import stat
root=Path(payload['root']);directory=root.lstat()
if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=0 or directory.st_mode&0o077:raise SystemExit('qualification_receipt_unsafe')
fd=os.open(root/payload['filename'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 facts=os.fstat(fd)
 if not stat.S_ISREG(facts.st_mode) or facts.st_uid!=0 or facts.st_mode&0o077 or facts.st_size>32*1024*1024:raise SystemExit('qualification_receipt_unsafe')
 with os.fdopen(fd,'r') as stream:
  fd=None;content=stream.read(32*1024*1024+1)
 if len(content)>32*1024*1024:raise SystemExit('qualification_receipt_unsafe')
 print(content)
finally:
 if fd is not None:os.close(fd)
''', data={'root': handle['root'], 'filename': filename}, output_limit=32 * 1024 * 1024))

    def candidate_capture(self, *, namespace=False):
        """Supplemental on-host epochs: namespace loss is labelled, never a zero.

        The independently continuous external witnesses remain mandatory across
        reboot. Epoch observations add the actual container/uplink/bridge layer.
        """
        facts = self.assert_owned('container', self.container)
        net = self.assert_owned('network', self.network)
        pid = facts['State']['Pid']
        if type(pid) is not int or pid <= 0:
            raise QualificationError('qualification_candidate_namespace_invalid')
        bridge = net['Options'].get('com.docker.network.bridge.name', 'br-' + net['Id'][:12])
        if re.fullmatch('[a-zA-Z0-9_.-]{1,15}', bridge) is None:
            raise QualificationError('qualification_bridge_invalid')
        if namespace:
            links = json.loads(self.docker('exec', self.container, 'ip', '-j', 'link', 'show')['stdout'])
            interfaces = ['eth0', 'wg-office'] + [v['ifname'] for v in links if v['ifname'] in {
                'wg-mullvad', 'wg-pia', 'wg-proton'}]
            if 'wg-office' not in {v['ifname'] for v in links}:
                raise QualificationError('qualification_ingress_missing')
        else:
            interfaces = ['eth0', bridge]
        identifier = uuid.uuid4().hex
        root = '/run/exitlane-d6-' + identifier
        unit = 'exitlane-d6-capture-' + identifier + '.service'
        source = Path(__file__).with_name('container_host_packets.py').read_text()
        script = '/var/lib/exitlane-qualification/packets-' + hashlib.sha256(source.encode()).hexdigest()[:16] + '.py'
        cfg = {'interfaces': interfaces, 'run_dir': root, 'addresses': [
            self.config['candidate']['address'], self.config['peer']['address'],
            '1.1.1.1', '192.0.0.9', '192.0.0.10', '10.77.0.1', '10.77.0.2',
            '10.64.0.1', '10.64.0.2', '10.65.0.1', '10.65.0.2', '10.66.0.1', '10.66.0.2',
            'fd99::1', 'fd99:77::2']}
        path = '/var/lib/exitlane-qualification/' + identifier + '.json'
        log = '/var/lib/exitlane-qualification/' + identifier + '.log'
        arguments = ['/usr/bin/python3', script]
        if namespace:
            arguments = ['/usr/bin/nsenter', '--net=/proc/' + str(pid) + '/ns/net', *arguments]
        text = ('[Unit]\nDescription=ExitLane D6 candidate observation epoch\n'
                '[Service]\nExecStart=' + ' '.join(arguments) + '\nStandardInput=file:' + path +
                '\nStandardOutput=append:' + log + '\nStandardError=append:' + log +
                '\nKillMode=control-group\nTimeoutStopSec=10\n')
        self.candidate.run("""from pathlib import Path
p=Path(payload['script'])
if p.is_symlink() or (p.exists() and p.read_text()!=payload['source']):raise SystemExit('qualification_source_mismatch')
if not p.exists():p.write_text(payload['source']);p.chmod(0o600)
for name,value in ((payload['path'],json.dumps(payload['cfg'])),(payload['log'],'')):
 p=Path(name)
 if p.exists() or p.is_symlink():raise SystemExit('qualification_process_collision')
 p.write_text(value);p.chmod(0o600)
u=Path('/etc/systemd/system')/payload['unit']
if u.exists() or u.is_symlink():raise SystemExit('qualification_unit_collision')
u.write_text(payload['text']);u.chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','start',payload['unit']],check=True,timeout=30)
""", data={'script': script, 'source': source, 'path': path, 'log': log,
           'cfg': cfg, 'unit': unit, 'text': text})
        handle = {'kind': 'capture', 'role': 'candidate-namespace' if namespace else 'candidate-host',
                  'host': 'candidate', 'root': root, 'unit': unit, 'interfaces': interfaces,
                  'container_pid': pid, 'namespace': namespace}
        if self.assert_owned('container', self.container)['State']['Pid'] != pid:
            raise QualificationError('qualification_candidate_epoch_race')
        return handle

    def normal_calibration(self):
        """Deliberately unsafe synthetic control, without relaxing appliance policy.

        A separate disposable-host injector enters the candidate namespace and
        emits non-client-source markers. ExitLane itself retains NET_ADMIN only.
        The same protocol identities must be visible on normal uplink/WAN/target.
        """
        facts = self.assert_owned('container', self.container)
        address = facts['NetworkSettings']['Networks'][self.network]['IPAddress']
        pid = facts['State']['Pid']
        if type(pid) is not int or pid <= 0 or not ipaddress.IPv4Address(address).is_private:
            raise QualificationError('qualification_candidate_namespace_invalid')
        source = Path(__file__).with_name('container_host_sender.py').read_text()
        path = '/var/lib/exitlane-qualification/container_host_sender.py'
        self.candidate.run('''from pathlib import Path
p=Path(payload['path'])
if p.is_symlink():raise SystemExit('qualification_source_unsafe')
if p.exists() and p.read_text()!=payload['source']:raise SystemExit('qualification_source_mismatch')
if not p.exists():p.write_text(payload['source']);p.chmod(0o600)
''', data={'path': path, 'source': source})
        program = '''import importlib.util,json,socket,sys,time
v=json.load(sys.stdin)
s=importlib.util.spec_from_file_location('sender','/var/lib/exitlane-qualification/container_host_sender.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) as client:
 client.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'eth0\\0')
 for number in range(1,4):
  for stream in m.STREAMS:
   client.sendto(m.packet(v['source'],'calibration',number,*stream),('1.1.1.1',0))
  time.sleep(.1)
print(json.dumps({'calibration_emitted':15}))
'''
        result = self.command(self.candidate, ['nsenter', '--net=/proc/' + str(pid) + '/ns/net',
                              'python3', '-c', program], data=json.dumps({'source': address}))
        return json.loads(result['stdout'])

    def packet_phase(self, phase, captures, *, operation=None, fault=None, blocked=False, require_recovery=True, family=4):
        """Continuous external pressure spans an actual operation/fault and recovery.

        Zero-WAN acceptance never substitutes for recovered provider traffic.
        Mixed transition phases permit provider delivery; a disconnected steady
        phase additionally requires zero decoded protected traffic at either peer.
        """
        from container_host_packets import validate_receipts
        from container_host_sender import STREAMS

        if not isinstance(phase, str) or re.fullmatch('[a-z][a-z0-9_-]{0,39}', phase) is None:
            raise QualificationError('qualification_phase_invalid')
        if (type(family) is not int or family not in {4, 6}
                or family == 6 and (blocked is not True or require_recovery is not False)):
            raise QualificationError('qualification_family_state_invalid')
        if any(self.evidence(handle)['phase'] == phase for handle in captures):
            raise QualificationError('qualification_phase_reused')
        for handle in captures:
            self.control(handle, phase, calibration_phase='calibration6' if family == 6 else 'calibration')
            self.wait(lambda handle=handle: self.evidence(handle)['phase'] == phase and all(
                facts['ready'] and facts['polls'] >= 2 for facts in self.evidence(handle)['captures'].values()),
                handle['role'] + '_phase_ack', timeout=10)
        namespace = 'ed6-' + self.config['run_id'].replace('-', '')[:10] + '-client'
        sender = self.external_process('sender', phase, namespace=namespace, source_address='10.77.0.2', family=family)
        self.control(sender, phase)
        self.last_sender = sender
        self.last_packet_evidence = {'phase': phase, 'sender_handle': sender}
        try:
            self.wait(lambda: len(self.evidence(sender)['attempts']) >= 25, phase + '_pressure_active', timeout=10)
            if operation is not None:
                operation()
            if fault is not None:
                self.fault(fault)
            # Complete another proven pressure interval after the operation.
            before = len(self.evidence(sender)['attempts'])
            self.wait(lambda: len(self.evidence(sender)['attempts']) >= before + 25,
                      phase + '_post_operation_pressure', timeout=10)
            if not blocked and require_recovery:
                stamp = int(self.peer.run('print(time.time_ns())\n').strip())
                peers = [value for value in captures if value['role'] in {'provider-a', 'provider-b'}]
                self.wait(lambda: set(STREAMS) <= {
                    (sample['kind'], sample['protocol']) for peer in peers
                    for facts in self.evidence(peer)['captures'].values()
                    for sample in facts['samples'] if sample['observed_ns'] >= stamp},
                    phase + '_fresh_provider_delivery', timeout=30)
        finally:
            self.control(sender, phase, stop=True)
            self.wait(lambda: self.command(self.peer, ['systemctl', 'show', sender['unit'],
                '--property=SubState', '--value'])['stdout'].strip() in {'dead', 'failed'},
                phase + '_sender_finished', timeout=10)
        result = self.evidence(sender)
        status = self.command(self.peer, ['systemctl', 'show', sender['unit'], '--property=ExecMainStatus', '--value'])
        if status['stdout'].strip() != '0':
            raise QualificationError('qualification_sender_exit_failed')
        observations = {}
        observer_facts = []
        for handle in captures:
            self.wait(lambda handle=handle: all(facts['end_ns'] >= result['end_ns'] for facts in self.evidence(handle)['captures'].values()),
                      handle['role'] + '_drain_complete', timeout=5)
            value = self.evidence(handle)
            observer_facts.append((handle['role'], value['captures']))
            process = self.command(self.peer, ['systemctl', 'show', handle['unit'], '--property=SubState', '--value'])
            if process['stdout'].strip() != 'running':
                raise QualificationError('qualification_observer_exit_failed')
        observations = _packet_acceptance_observations(observer_facts)
        forbidden = ['wan', 'target-uplink']
        if blocked:
            forbidden.extend(['provider-a', 'provider-b', 'target-pa', 'target-pb'])
        self.last_packet_evidence = {'phase': phase, 'sender': result, 'captures': observations}
        required = ('wan', 'client', 'provider-a', 'provider-b',
                    'target-pa', 'target-pb', 'target-uplink')
        if family == 6:
            from container_host_ipv6 import validate_ipv6
            receipt = validate_ipv6(observations, result, phase=phase,
                                    required_points=required, sender_points=('client',),
                                    encapsulation_points=('wan',))
            receipt['expected_state'] = 'ipv6_blocked'
        else:
            receipt = validate_receipts(observations, result, phase=phase,
                                        forbidden_points=tuple(forbidden), sender_points=('client',),
                                        required_points=required)
            receipt['expected_state'] = ('blocked' if blocked else 'provider_or_block_with_fresh_recovery'
                                         if require_recovery else 'provider_or_block_transition')
        self.receipts.append(receipt)
        return {'receipt': receipt, 'sender': result, 'captures': observations}

    def archive_candidate_capture(self, handle):
        if handle.get('host') != 'candidate' or handle.get('kind') != 'capture':
            raise QualificationError('qualification_candidate_epoch_invalid')
        if re.fullmatch('/run/exitlane-d6-[a-f0-9]{32}', handle.get('root', '')) is None:
            raise QualificationError('qualification_candidate_epoch_invalid')
        value = self.candidate.run("""from pathlib import Path
import shutil,hashlib,stat
root=Path(payload['root']);facts=root.lstat()
if not stat.S_ISDIR(facts.st_mode) or facts.st_uid!=0 or facts.st_mode&0o077:raise SystemExit('qualification_epoch_unsafe')
parent=Path('/var/lib/exitlane-qualification/epochs')
if parent.is_symlink():raise SystemExit('qualification_epoch_unsafe')
parent.mkdir(mode=0o700,exist_ok=True)
if parent.stat().st_uid!=0 or parent.stat().st_mode&0o077:raise SystemExit('qualification_epoch_unsafe')
destination=parent/root.name;destination.mkdir(mode=0o700,exist_ok=False)
receipts={}
for p in root.iterdir():
 if p.name not in {'control.json','receipts.json'} and not p.name.endswith('.pcap'):continue
 f=p.lstat()
 if not stat.S_ISREG(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077 or f.st_size>32*1024*1024:raise SystemExit('qualification_epoch_unsafe')
 out=destination/p.name;shutil.copyfile(p,out);out.chmod(0o600)
 receipts[p.name]={'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size}
print(json.dumps({'archive':str(destination),'files':receipts}))
""", data=handle)
        return json.loads(value)

    def measure_clock(self, token):
        """Bound a candidate-to-reference clock offset using the existing LAN RPC.

        SSH latency is outside the interval. This is supplemental observer
        metadata; the continuous seven-point witness uses one reference clock.
        """
        if re.fullmatch('[a-f0-9]{64}', token) is None:
            raise QualificationError('qualification_fixture_token_invalid')
        source = """import http.client
connection=http.client.HTTPConnection(payload['address'],8991,timeout=3)
body=json.dumps({'action':'clock','run_id':payload['run_id']}).encode()
start=time.time_ns()
connection.request('POST','/upstream',body,{'Authorization':'Bearer '+payload['token'],'Content-Type':'application/json'})
r=connection.getresponse();raw=r.read(4097);end=time.time_ns()
if r.status!=200 or len(raw)>4096:raise SystemExit('qualification_clock_unavailable')
outer=json.loads(raw)
if set(outer)!={'result'}:raise SystemExit('qualification_clock_invalid')
v=outer['result']
if set(v)!={'reference_ns','boot_id'}:raise SystemExit('qualification_clock_invalid')
print(json.dumps({'local_before_ns':start,'reference_ns':v['reference_ns'],'local_after_ns':end,'reference_boot_id':v['boot_id']}))
connection.close()
"""
        result = json.loads(self.candidate.run(source, data={'address': self.config['peer']['address'],
                            'run_id': self.config['run_id'], 'token': token}))
        return {'measurement': {key: result[key] for key in (
            'local_before_ns', 'reference_ns', 'local_after_ns')},
            'reference_boot_id': result['reference_boot_id']}

    def peer_fault(self, role, action):
        if role not in {'a', 'b'} or action not in {'handshake_off', 'handshake_on',
                'dataplane_off', 'dataplane_on', 'dns_off', 'dns_on'}:
            raise QualificationError('qualification_peer_fault_invalid')
        result = self.command(self.peer, ['/usr/bin/python3',
            '/var/lib/exitlane-qualification/container_host_peer.py', 'fault'],
            data=json.dumps({'run_id': self.config['run_id'], 'role': role, 'action': action}))
        return json.loads(result['stdout'])

    def network_snapshot(self):
        """Non-secret rule/generation snapshots accompany packet receipts."""
        self.assert_owned('container', self.container)
        result = {}
        for name, argv in {'rules': ['ip', '-j', 'rule', 'show'],
                           'routes': ['ip', '-j', 'route', 'show', 'table', 'all'],
                           'firewall': ['nft', '-j', 'list', 'ruleset'],
                           'interfaces': ['ip', '-j', 'link', 'show']}.items():
            result[name] = json.loads(self.docker('exec', self.container, *argv)['stdout'])
        result['process'] = self.process_identity()
        result['state_pair'] = self.pair()
        return result

    def process_identity(self):
        facts = self.assert_owned('container', self.container)
        source = """from pathlib import Path
values=[]
for p in Path('/proc').iterdir():
 if p.name.isdigit():
  try:
   cmd=(p/'cmdline').read_bytes().split(b'\\0')
   if cmd[1:4]==[b'-m',b'exitlane.container_entrypoint',b'worker']:
    values.append([int(p.name),(p/'stat').read_text().split(') ')[1].split()[19]])
  except OSError:continue
if len(values)!=1:raise SystemExit('qualification_worker_identity_unproven')
print(json.dumps(values[0]))
"""
        value = self.docker('exec', self.container, 'python', '-c', 'import json\n' + source)
        return {'host_pid': facts['State']['Pid'], 'started': facts['State']['StartedAt'],
                'restart_count': facts['RestartCount'], 'worker': json.loads(value['stdout'])}

    def configure_daemon_mode(self, enabled):
        """Preparation is separate from the measured fault: old daemon owns shutdown."""
        if type(enabled) is not bool or not self.config['allow_host_restart']:
            raise QualificationError('qualification_host_fault_not_authorized')
        self.assert_disposable()
        original = self.assert_owned('container', self.container)
        if original['State'].get('Running') is not True or not self.healthy():
            raise QualificationError('qualification_daemon_preparation_not_ready')
        identity = (original['Id'], original['Image'], original['Mounts'])
        original_pair = self.pair()
        current = json.loads(self.docker('info', '--format', '{{json .LiveRestoreEnabled}}')['stdout'])
        if type(current) is not bool:
            raise QualificationError('qualification_daemon_mode_unproven')
        if current is enabled:
            self.assert_daemon_mode(enabled)
            if self.pair() != original_pair:
                raise QualificationError('qualification_daemon_preparation_state_changed')
            return
        # https://github.com/moby/moby/blob/docker-v29.8.2/daemon/daemon.go
        # Lines1438–1444 retain old live-restore tasks; lines434–442 stop them
        # when the new daemon restores with live-restore disabled.
        # Docker29.8.2 daemon.go: old live-restore shutdown leaves tasks alive,
        # but startup with live-restore=false explicitly shuts those tasks down.
        # Stop/start this exact owned container outside measured packet pressure;
        # never assume unless-stopped auto-starts across that mode transition.
        self.docker('stop', '--time', '15', original['Id'])
        stopped = self.assert_owned('container', self.container)
        if (stopped['State'].get('Running') is not False
                or stopped['State'].get('Status') != 'exited'
                or (stopped['Id'], stopped['Image'], stopped['Mounts']) != identity):
            raise QualificationError('qualification_daemon_preparation_stop_unproven')
        self.candidate.run("""from pathlib import Path
p=Path('/etc/docker/daemon.json')
if p.is_symlink():raise SystemExit('qualification_daemon_config_invalid')
v=json.loads(p.read_text()) if p.exists() else {}
if not isinstance(v,dict):raise SystemExit('qualification_daemon_config_invalid')
v['live-restore']=payload
p.write_text(json.dumps(v));p.chmod(0o600)
subprocess.run(['systemctl','restart','docker'],check=True,timeout=90)
""", data=enabled, timeout=110)
        self.assert_daemon_mode(enabled)
        retained = self.assert_owned('container', self.container)
        if ((retained['Id'], retained['Image'], retained['Mounts']) != identity
                or retained['State'].get('Running') is not False
                or retained['State'].get('Status') != 'exited'):
            raise QualificationError('qualification_daemon_preparation_identity_changed')
        self.docker('start', original['Id'])
        self.wait(self.healthy, 'daemon_mode_preparation_recovered', timeout=180)
        recovered = self.assert_owned('container', self.container)
        if ((recovered['Id'], recovered['Image'], recovered['Mounts']) != identity
                or recovered['State'].get('Running') is not True):
            raise QualificationError('qualification_daemon_preparation_identity_changed')
        if self.pair() != original_pair:
            raise QualificationError('qualification_daemon_preparation_state_changed')
        self.assert_daemon_mode(enabled)
        self.receipts.append({'stage': 'daemon_mode_preparation', 'outside_pressure': True,
                              'live_restore': enabled, 'state_pair_preserved': True})

    def assert_daemon_mode(self, enabled):
        value = json.loads(self.docker('info', '--format', '{{json .LiveRestoreEnabled}}')['stdout'])
        if value is not enabled:
            raise QualificationError('qualification_daemon_mode_unproven')

    def fault(self, action):
        allowed = {'container_restart', 'parent_crash', 'worker_crash',
                   'daemon_restart', 'daemon_live_restore', 'host_reboot'}
        if action not in allowed:
            raise QualificationError('qualification_fault_invalid')
        if not self.config['allow_host_restart']:
            raise QualificationError('qualification_host_fault_not_authorized')
        self.assert_disposable()
        self.assert_owned('container', self.container)
        original_pair = self.pair()
        original_process = self.process_identity()
        boot = self.candidate.run("print(open('/proc/sys/kernel/random/boot_id').read().strip())\n").strip()
        if action == 'container_restart':
            self.docker('restart', '--time', '15', self.container)
        elif action in {'parent_crash', 'worker_crash'}:
            # Find exactly one direct worker child of the actual supervisor.
            source = '''import os,signal
from pathlib import Path
workers=[]
for p in Path('/proc').iterdir():
 if p.name.isdigit():
  try:cmd=(p/'cmdline').read_bytes().split(b'\\0')
  except OSError:continue
  if cmd[1:4]==[b'-m',b'exitlane.container_entrypoint',ROLE]:workers.append(int(p.name))
if len(workers)!=1:raise SystemExit('qualification_worker_identity_unproven')
print('qualification_signal_sent',flush=True)
os.kill(workers[0],signal.SIGKILL)
'''
            source = source.replace('ROLE', repr(b'serve' if action == 'parent_crash' else b'worker'))
            injection = self.docker('exec', self.container, 'python', '-c', source, check=False)
            if injection['code'] not in {0, 137} or injection['stdout'].strip() != 'qualification_signal_sent':
                raise QualificationError('qualification_signal_injection_unproven')
            self.receipts.append({'stage': action + '_signal', 'exit': injection['code'],
                                  'signal_sent': True})
        elif action in {'daemon_restart', 'daemon_live_restore'}:
            self.assert_daemon_mode(action == 'daemon_live_restore')
            self.candidate.run("subprocess.run(['systemctl','restart','docker'],check=True,timeout=90)\n", timeout=110)
        else:
            self.candidate.run("subprocess.run(['systemctl','reboot'],check=True)\n", timeout=15, check=False)
            self.wait(lambda: self.candidate.run(
                "print(open('/proc/sys/kernel/random/boot_id').read().strip())\n", check=False) not in {None, boot + '\n'},
                'new_host_boot', timeout=180)
        def recovered():
            if not self.healthy():
                return False
            try:
                current = self.process_identity()
            except QualificationError:
                return False
            if action == 'daemon_live_restore':
                if current != original_process:
                    raise QualificationError('qualification_live_restore_process_changed')
                return True
            return current != original_process
        self.wait(recovered, action + '_recovered', timeout=180)
        if self.pair() != original_pair:
            raise QualificationError('qualification_durable_pair_changed')
        self.receipts.append({'stage': action, 'state_pair_preserved': True,
                              'packet_qualification': 'requires_external_receipts',
                              'process_before': original_process, 'process_after': self.process_identity()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--action', choices=('prepare', 'container_restart', 'parent_crash',
                        'worker_crash', 'daemon_restart', 'daemon_live_restore', 'host_reboot'), required=True)
    args = parser.parse_args()
    facts = args.config.lstat()
    if not stat.S_ISREG(facts.st_mode) or stat.S_IMODE(facts.st_mode) & 0o077 or facts.st_size > 8192:
        raise SystemExit('qualification_config_permissions_invalid')
    harness = HostHarness(json.loads(args.config.read_text()))
    try:
        if args.action == 'prepare':
            harness.prepare()
        else:
            harness.preflight()
            harness.fault(args.action)
        print(json.dumps({'result': 'OBSERVED', 'packet_qualification': 'OUTSTANDING',
                          'receipts': harness.receipts}, sort_keys=True))
    except QualificationError as error:
        raise SystemExit(str(error)) from None


if __name__ == '__main__':
    main()
