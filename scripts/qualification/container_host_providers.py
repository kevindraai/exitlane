"""D6 direct-provider proof through the real application API.

Only upstream API responses are synthetic, as established by HostHarness. This
helper replaces no provider, lifecycle, routing or proof factory. Generated
Proton private keys and synthetic PIA credentials live only in memory and SSH
stdin, never argv/environment, errors, summaries or receipt metadata. The peer
registration command receives the public key only. No real account is needed.

Use ProviderQualification(harness, continuous_captures, receipts=Receipts(...)).
Authenticate/import once, then activate/connect/disconnect with continuous packet
pressure. A healthy API or an accepted mutation alone is never a packet PASS.
Errors preserve the appliance and fixture; there is no implicit retry/cleanup.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets

DIRECT = {'mullvad': ('wg-mullvad', '10.64.0.2'), 'pia': ('wg-pia', '10.65.0.2'),
          'proton': ('wg-proton', '10.66.0.2')}
ENDPOINTS = {'a': '192.0.0.9', 'b': '192.0.0.10'}
PEER_SCRIPT = '/var/lib/exitlane-qualification/container_host_peer.py'
ERRORS = frozenset({'provider_switch_failed', 'provider_not_ready', 'provider_not_active',
                    'provider_connection_conflict', 'provider_connect_failed', 'provider_disconnect_failed',
                    'credential_replacement_unsupported', 'proton_profile_duplicate', 'proton_profile_limit',
                    'invalid_proton_profile', 'invalid_credential_payload', 'invalid_credentials',
                    'vpn_action_in_progress', 'connection_failed', 'provider_egress_readiness_failed',
                    'container_ingress_required', 'runtime_capability_unavailable'})


class ProviderEvidenceError(RuntimeError):
    """Only known static identifiers; never expose provider/profile output."""


def key(value):
    if not isinstance(value, str) or re.fullmatch('[A-Za-z0-9+/]{43}=', value) is None:
        raise ProviderEvidenceError('provider_fixture_key_invalid')
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise ProviderEvidenceError('provider_fixture_key_invalid') from None
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ProviderEvidenceError('provider_fixture_key_invalid')
    return value


class ProviderQualification:
    def __init__(self, harness, captures, *, receipts):
        self.h = harness
        self.captures = captures
        self.receipts = receipts

    def _api(self, path, *, method='GET', body=None):
        try:
            result = self.h.api(path, method=method, body=body, timeout=90)
        except Exception:  # noqa: BLE001 -- remote exceptions may contain private profile material
            raise ProviderEvidenceError('provider_api_failed') from None
        if not isinstance(result, dict) or not isinstance(result.get('body'), dict):
            raise ProviderEvidenceError('provider_response_invalid')
        content = result['body']
        if result.get('status') != 200:
            error = content.get('detail') or content.get('error_code') or content.get('error')
            raise ProviderEvidenceError(error if isinstance(error, str) and error in ERRORS else 'provider_api_failed')
        return content

    def _command(self, host, arguments, *, data=None):
        try:
            value = self.h.command(host, arguments, data=data)
            if not isinstance(value, dict) or value.get('code') != 0 or not isinstance(value.get('stdout'), str):
                raise ValueError
            return value['stdout']
        except Exception:  # noqa: BLE001 -- omit command output and private stdin
            raise ProviderEvidenceError('provider_fixture_command_failed') from None

    def _authorized(self):
        self.h.assert_disposable()
        self.h.assert_owned('container', self.h.container)
        if self._api('/api/auth/session').get('authenticated') is not True:
            raise ProviderEvidenceError('provider_authentication_required')

    def _public_peer(self, role):
        if role not in ENDPOINTS:
            raise ProviderEvidenceError('provider_fixture_peer_invalid')
        try:
            manifest = json.loads(self._command(self.h.peer, ['/usr/bin/python3', PEER_SCRIPT, 'status'],
                                               data=json.dumps({'run_id': self.h.config['run_id']})))
            if (not isinstance(manifest, dict) or set(manifest) != {'run_id', 'names', 'links', 'peers'}
                    or manifest['run_id'] != self.h.config['run_id'] or set(manifest['peers']) != set(ENDPOINTS)):
                raise ValueError
            peer = manifest['peers'][role]
            if (not isinstance(peer, dict) or set(peer) != {'endpoint', 'public_key', 'port'}
                    or peer['endpoint'] != ENDPOINTS[role] or type(peer['port']) is not int
                    or not 1 <= peer['port'] <= 65535):
                raise ValueError
            key(peer['public_key'])
            return peer
        except (ValueError, TypeError, KeyError):
            raise ProviderEvidenceError('provider_fixture_manifest_invalid') from None

    def authenticate_pia(self):
        self._authorized()
        password = 'synthetic-D6-only-' + secrets.token_hex(18)
        try:
            result = self._api('/api/vpn/providers/pia/authenticate', method='POST',
                               body={'username': 'd6synthetic', 'password': password})
            if result.get('ok') is not True:
                raise ProviderEvidenceError('provider_authentication_failed')
            summary = {'provider': 'pia', 'authenticated': True, 'commercial_account_used': False}
            self.receipts.write('pia-authentication.json', summary)
            return summary
        finally:
            password = None

    def import_proton(self, *, peer='a'):
        self._authorized()
        endpoint = self._public_peer(peer)
        private = profile = None
        try:
            private = key(self._command(self.h.peer, ['wg', 'genkey']).strip())
            public = key(self._command(self.h.peer, ['wg', 'pubkey'], data=private + '\n').strip())
            registered = json.loads(self._command(self.h.peer, ['/usr/bin/python3', PEER_SCRIPT, 'proton'],
                data=json.dumps({'run_id': self.h.config['run_id'], 'public_key': public, 'peer': peer})))
            if registered != {'registered': True}:
                raise ProviderEvidenceError('provider_fixture_registration_failed')
            profile = (f'[Interface]\nPrivateKey = {private}\nAddress = 10.66.0.2/32\n'
                       'DNS = 10.66.0.1\nMTU = 1380\n[Peer]\n'
                       f'PublicKey = {endpoint["public_key"]}\nEndpoint = {endpoint["endpoint"]}:{endpoint["port"]}\n'
                       'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n')
            result = self._api('/api/vpn/providers/proton/profiles', method='POST',
                body={'config': profile, 'display_name': 'Disposable D6 ' + peer.upper(), 'country_code': 'NL'})
            imported = result.get('profile')
            if (result.get('ok') is not True or not isinstance(imported, dict)
                    or not isinstance(imported.get('id'), str) or re.fullmatch('[a-f0-9]{24}', imported['id']) is None
                    or imported.get('endpoint') != endpoint['endpoint'] or imported.get('port') != endpoint['port']):
                raise ProviderEvidenceError('provider_profile_import_unproven')
            summary = {'provider': 'proton', 'profile_id': imported['id'], 'peer': peer,
                       'endpoint': endpoint['endpoint'], 'port': endpoint['port'],
                       'source': '10.66.0.2/32', 'public_key_sha256': hashlib.sha256(public.encode()).hexdigest()}
            self.receipts.write('proton-import-' + peer + '.json', summary)
            return summary
        finally:
            private = profile = None

    def _selected(self, provider, connected):
        overview = self._api('/api/vpn/providers')
        if overview.get('active_provider_id') != provider or not isinstance(overview.get('providers'), list):
            return False
        items = overview['providers']
        if (len(items) != len(DIRECT) or any(not isinstance(item, dict) for item in items)
                or {item.get('id') for item in items} != set(DIRECT)
                or any(not isinstance(item.get('status'), dict) for item in items)):
            raise ProviderEvidenceError('provider_registry_boundary_invalid')
        connected_ids = [item['id'] for item in items if item.get('status', {}).get('connected') is True]
        if connected_ids != ([provider] if connected else []):
            return False
        response = self._api('/api/vpn/providers/' + provider + '/status')
        metadata, status = response.get('provider'), response.get('status')
        if (not isinstance(metadata, dict) or not isinstance(status, dict) or metadata.get('id') != provider
                or metadata.get('active') is not True or status.get('is_active') is not True
                or status.get('connected') is not connected):
            return False
        if connected:
            interface, address = DIRECT[provider]
            if status.get('tunnel_interface') != interface or status.get('latency_endpoint') not in ENDPOINTS.values():
                return False
            role = next(role for role, endpoint in ENDPOINTS.items() if endpoint == status['latency_endpoint'])
            peer = self._public_peer(role)
            try:
                links = json.loads(self.h.docker('exec', self.h.container, 'ip', '-j', 'address',
                                                'show', 'dev', interface)['stdout'])
                ipv4 = {(item['local'], item['prefixlen']) for link in links for item in link['addr_info']
                        if item['family'] == 'inet'}
                endpoints = self.h.docker('exec', self.h.container, 'wg', 'show', interface, 'endpoints')['stdout'].splitlines()
                expected = peer['public_key'] + '\t' + peer['endpoint'] + ':' + str(peer['port'])
                if ipv4 != {(address, 32)} or endpoints != [expected]:
                    return False
            except (ValueError, TypeError, KeyError):
                raise ProviderEvidenceError('provider_topology_unproven') from None
        return True

    def _wait_selected(self, provider, connected):
        def observe():
            try:
                return self._selected(provider, connected)
            except ProviderEvidenceError as error:
                if str(error) == 'provider_api_failed':
                    return False
                raise
        try:
            self.h.wait(observe, 'd6-' + provider + '-public-state', timeout=30)
        except Exception:  # noqa: BLE001 -- fixed error, never include remote output
            raise ProviderEvidenceError('provider_state_unproven') from None

    def _mutation(self, action, provider, *, target=None, connected=None):
        if provider not in DIRECT or action not in {'activate', 'connect', 'disconnect'}:
            raise ProviderEvidenceError('provider_action_invalid')
        if target is not None and (action != 'connect' or not isinstance(target, str)
                                   or re.fullmatch('[A-Za-z0-9_.:-]{1,80}', target) is None):
            raise ProviderEvidenceError('provider_target_invalid')
        self._authorized()
        expected_connected = action != 'disconnect' if connected is None else connected
        if type(expected_connected) is not bool:
            raise ProviderEvidenceError('provider_action_invalid')
        phase = 'p-' + action + '-' + provider + '-' + secrets.token_hex(4)
        self.h.last_packet_evidence = None
        metadata = {'phase': phase, 'provider': provider, 'action': action, 'result': 'RUNNING'}
        self.receipts.write(phase + '-metadata.json', metadata)
        def operation():
            body = {'target': target} if action == 'connect' else None
            result = self._api('/api/vpn/providers/' + provider + '/' + action, method='POST', body=body)
            if result.get('ok') is not True or action in {'connect', 'disconnect'} and result.get('success') is not True:
                code = result.get('error_code') or result.get('error')
                raise ProviderEvidenceError(code if isinstance(code, str) and code in ERRORS else 'provider_action_failed')
            if action == 'activate' and result.get('active_provider_id') != provider:
                raise ProviderEvidenceError('provider_activation_unproven')
            self._wait_selected(provider, expected_connected)
        try:
            # Pressure starts before the mutation. Valid provider delivery before
            # disconnect is permitted, while plaintext fallback is always denied.
            transition = action == 'disconnect'
            result = self.h.packet_phase(phase, self.captures, operation=operation,
                                         blocked=not expected_connected and not transition,
                                         require_recovery=expected_connected)
            if (not isinstance(result, dict) or result.get('receipt', {}).get('accepted') is not True
                    or result['receipt'].get('phase') != phase):
                raise ProviderEvidenceError('provider_packet_proof_unproven')
            receipt = self.receipts.write(phase + '-packets.json', result)
            metadata['packets'] = receipt
            if transition:
                # Separate capture/sender epoch: no pre-disconnect packets may
                # contaminate the strict disconnected steady-state measurement.
                blocked_phase = 'p-blocked-' + provider + '-' + secrets.token_hex(4)
                metadata['blocked_phase'] = blocked_phase
                self.receipts.write(phase + '-metadata.json', metadata)
                blocked_result = self.h.packet_phase(blocked_phase, self.captures,
                    operation=lambda: self._wait_selected(provider, False), blocked=True, require_recovery=False)
                if (not isinstance(blocked_result, dict)
                        or blocked_result.get('receipt', {}).get('accepted') is not True
                        or blocked_result['receipt'].get('phase') != blocked_phase):
                    raise ProviderEvidenceError('provider_blocked_proof_unproven')
                metadata['blocked_packets'] = self.receipts.write(blocked_phase + '-packets.json', blocked_result)
            metadata.update(result='PACKET_COMPONENT_PASS', packets=receipt)
            self.receipts.write(phase + '-metadata.json', metadata)
            return metadata
        except BaseException:  # noqa: BLE001 -- preserve interrupted evidence without private exception text
            evidence = getattr(self.h, 'last_packet_evidence', None)
            if evidence is not None:
                metadata['failed_packets'] = self.receipts.write(phase + '-failed-packets.json', evidence)
            metadata['result'] = 'FAILED'
            self.receipts.write(phase + '-metadata.json', metadata)
            raise ProviderEvidenceError('provider_packet_stage_failed') from None

    def activate(self, provider):
        return self._mutation('activate', provider)

    def switch(self, provider):
        return self.activate(provider)

    def select(self, provider):
        """Select an authenticated target while all direct providers are disconnected."""
        return self._mutation('activate', provider, connected=False)

    def connect(self, provider, *, target=None):
        return self._mutation('connect', provider, target=target)

    def disconnect(self, provider):
        return self._mutation('disconnect', provider)
