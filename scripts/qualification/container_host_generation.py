"""D6 pending-generation crash/restore through the unchanged runtime and root CLI.

Run last among authenticated API components: restore deliberately revokes the
old session. No direct state writes, injected factory, guessed worker PID, or
healthy-restart helper substitutes for the actual pending-state packet proof.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor

from container_host_failures import FailureEvidenceError, FailureQualification

INVENTORY_PROGRAM = '''import json
from pathlib import Path
from exitlane.container_state import ContainerState
from exitlane.container_paths import ContainerLayout
from exitlane.providers.wireguard_keys import _public_key_for_private
v=ContainerState(ContainerLayout(Path('/data'))).validate()
items=[]
for i in v.intents:
 d={'provider':i.provider_id,'status':i.status,'generation':i.generation}
 if i.config:
  d.update(interface=i.config.interface,endpoint=i.config.endpoint_address,
   public_key=_public_key_for_private(i.config.private_key),peer_public_key=i.config.peer_public_key)
 items.append(d)
print(json.dumps({'selected_provider':v.selected_provider,'intents':items}))
'''
KILL_PROGRAM = '''import json,os,signal,sys
from pathlib import Path
v=json.load(sys.stdin)
if set(v)!={'pid','start'} or type(v['pid']) is not int or v['pid']<=0 or not isinstance(v['start'],str) or not v['start'].isdigit():raise SystemExit('qualification_worker_identity_unproven')
p=Path('/proc')/str(v['pid'])
cmd=(p/'cmdline').read_bytes().split(b'\\0')
parts=(p/'stat').read_text().split(') ')[1].split()
parent=Path('/proc')/parts[1]
pcmd=(parent/'cmdline').read_bytes().split(b'\\0')
if cmd[1:4]!=[b'-m',b'exitlane.container_entrypoint',b'worker'] or parts[19]!=v['start'] or pcmd[1:4]!=[b'-m',b'exitlane.container_entrypoint',b'serve']:raise SystemExit('qualification_worker_identity_unproven')
print('qualification_signal_sent',flush=True)
os.kill(v['pid'],signal.SIGKILL)
'''


class GenerationQualification:
    def __init__(self, harness, captures, *, receipts):
        self.h, self.receipts = harness, receipts
        self.failures = FailureQualification(harness, captures, receipts=receipts)
        self.last_control_status = None

    @staticmethod
    def _api_projection(result):
        if not isinstance(result, dict):
            return {'http_status': None, 'body_present': False, 'ok': None, 'success': None, 'error_code': None}
        body, status = result.get('body'), result.get('status')
        body = body if isinstance(body, dict) else {}
        code = body.get('detail') or body.get('error_code') or body.get('error')
        return {'http_status': status if type(status) is int and (status == 0 or 100 <= status <= 599) else None,
                'body_present': isinstance(result.get('body'), dict),
                'ok': body.get('ok') if type(body.get('ok')) is bool else None,
                'success': body.get('success') if type(body.get('success')) is bool else None,
                'error_code': code if isinstance(code, str) and code in {
                    'provider_switch_failed', 'vpn_action_in_progress', 'provider_not_ready',
                    'connection_failed', 'vpn_connect_timeout'} else None}

    def _inventory(self):
        response = self.h.docker('exec', self.h.container, 'python', '-c', INVENTORY_PROGRAM, check=False)
        if not isinstance(response, dict) or response.get('code') != 0:
            return None
        try:
            value = json.loads(response['stdout'])
            if (not isinstance(value, dict) or set(value) != {'selected_provider', 'intents'}
                    or not isinstance(value['intents'], list)
                    or any(not isinstance(item, dict) or item.get('provider') not in {'mullvad', 'pia', 'proton'}
                           or item.get('status') not in {'active', 'pending', 'recovery_required'} for item in value['intents'])):
                return None
            return value
        except (ValueError, KeyError, TypeError):
            return None

    def _cli(self, command, *, passphrase=None, name=None):
        arguments = ['exec', '-i', self.h.container, 'python', '-m', 'exitlane.container_cli', command]
        if name is not None:
            if not isinstance(name, str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,95}\\.elbackup', name) is None:
                raise FailureEvidenceError('generation_backup_name_invalid')
            arguments += ['--name', name, '--confirm', 'RESTORE EXITLANE']
        if passphrase is not None:
            arguments += ['--passphrase-stdin']
        result = self.h.docker(*arguments, data=passphrase + '\n' if passphrase is not None else None,
                               check=False, timeout=180)
        if not isinstance(result, dict) or result.get('code') != 0:
            raise FailureEvidenceError('generation_control_unavailable')
        try:
            return json.loads(result['stdout'])
        except (ValueError, KeyError, TypeError):
            raise FailureEvidenceError('generation_control_contract_invalid') from None

    def _pending_safe(self, expected, original_worker):
        try:
            status = self._cli('status')
        except FailureEvidenceError as error:
            if error.args != ('generation_control_unavailable',):
                raise
            self.last_control_status = {'probe': 'control_temporarily_unavailable'}
            return False
        if isinstance(status, dict):
            self.last_control_status = {
                'state': status.get('state') if status.get('state') in {'ready', 'recovery_required'} else None,
                **{field: status.get(field) if type(status.get(field)) is bool else None
                   for field in ('worker_running', 'available', 'recovery_required')},
            }
        if (not isinstance(status, dict) or status.get('state') not in {'ready', 'recovery_required'}
                or any(type(status.get(field)) is not bool for field in ('worker_running', 'available', 'recovery_required'))):
            raise FailureEvidenceError('generation_control_contract_invalid')
        inventory = self._inventory()
        # Healthy management is permitted. Pending generation must remain exact,
        # with no automatic promotion/replacement, and the killed worker cannot
        # still be the observed live worker. Packet proof independently denies
        # protected delivery at both provider peers and the normal WAN.
        if inventory != expected or any(item['provider'] == 'pia' and item['status'] == 'active' for item in inventory['intents']):
            raise FailureEvidenceError('generation_baseline_invalid')
        if status['worker_running'] and self.h.process_identity()['worker'] == original_worker:
            return False
        link = self.h.docker('exec', self.h.container, 'ip', '-j', 'link', 'show', 'dev', 'wg-pia', check=False)
        if link.get('code') == 0:
            try:
                links = json.loads(link['stdout'])
            except (ValueError, KeyError, TypeError):
                return False
            if len(links) != 1 or links[0].get('ifname') != 'wg-pia' or not self.failures._handshake('pia', established=False):
                return False
            interface_state = 'present_without_handshake'
        elif link.get('code') == 1:
            interface_state = 'absent'
        else:
            return False
        return {'control': self.last_control_status, 'inventory': inventory, 'pia_interface': interface_state}

    def run(self, *, catalog_preparation, passphrase):
        # Caller retains the in-memory recovery credential if control disappears;
        # the driver neither generates an unrecoverable secret nor persists it.
        if (not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 1024
                or any(character in passphrase for character in ('\n', '\r', '\0'))):
            raise FailureEvidenceError('generation_passphrase_invalid')
        f = self.failures
        f.providers._authorized()
        binding = f._prepared_catalogs(catalog_preparation, 'mullvad', 'pia', 'a', 'b')
        if not f.providers._selected('mullvad', True):
            raise FailureEvidenceError('generation_active_source_required')
        source = f._bound_source('mullvad', 'a')
        baseline = self._inventory()
        if baseline is None or baseline['selected_provider'] != 'mullvad':
            raise FailureEvidenceError('generation_baseline_invalid')
        active = [item for item in baseline['intents'] if item['provider'] == 'mullvad' and item['status'] == 'active']
        if len(active) != 1 or any(item['status'] != 'active' for item in baseline['intents']):
            raise FailureEvidenceError('generation_baseline_invalid')
        try:
            def run(metadata):
                # Backup legitimately replaces/quiesces the worker. Capture its
                # identity afterwards, not the process from catalog preparation.
                backup = self._cli('backup', passphrase=passphrase)
                if not isinstance(backup, dict) or set(backup) != {'name'}:
                    raise FailureEvidenceError('generation_backup_unproven')
                name = backup['name']
                if not isinstance(name, str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,95}\\.elbackup', name) is None:
                    raise FailureEvidenceError('generation_backup_name_invalid')
                metadata['backup_name'] = name
                metadata['baseline_inventory'] = baseline
                original = self.h.process_identity()
                metadata['original_process'] = original
                def crash():
                    metadata['target_fault'] = f._fault('b', 'handshake_off')
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        # Terminal network/HTTP failure is expected after SIGKILL;
                        # a successful switch is always disqualifying.
                        action = pool.submit(self.h.api, '/api/vpn/providers/pia/activate', method='POST', body=None, timeout=180)
                        def pending():
                            inventory = self._inventory()
                            if inventory is None or not f._handshake('pia', established=False):
                                return False
                            intents = [item for item in inventory['intents'] if item['provider'] == 'pia' and item['status'] == 'pending']
                            if len(intents) != 1 or intents[0].get('endpoint') != '192.0.0.10':
                                return False
                            metadata['pending_inventory'] = inventory
                            return True
                        self.h.wait(pending, 'd6-pia-pending-zero-handshake', timeout=30)
                        if self.h.process_identity()['worker'] != original['worker']:
                            raise FailureEvidenceError('generation_worker_identity_changed')
                        worker = original['worker']
                        killed = self.h.docker('exec', '-i', self.h.container, 'python', '-c', KILL_PROGRAM,
                            data=json.dumps({'pid': worker[0], 'start': worker[1]}), check=False)
                        if killed.get('code') not in {0, 137} or killed.get('stdout', '').strip() != 'qualification_signal_sent':
                            raise FailureEvidenceError('generation_signal_unproven')
                        metadata['signal'] = {'sent': True, 'exit': killed['code']}
                        try:
                            result = action.result()
                        except Exception:  # noqa: BLE001 -- network exception text can contain cookies
                            metadata['api_interrupted'] = True
                        else:
                            metadata['api_response'] = self._api_projection(result)
                            if isinstance(result, dict) and result.get('status') == 0 and result.get('body') is None:
                                # Existing HTTP helper's explicit socket/HTTP
                                # interruption wrapper, not an API success.
                                metadata['api_interrupted'] = {'transport_interrupted': True, 'status': 0}
                            elif (not isinstance(result, dict) or result.get('status') not in {409, 503}
                                    or not isinstance(result.get('body'), dict)
                                    or result['body'].get('detail') not in {'provider_switch_failed', 'vpn_action_in_progress'}):
                                raise FailureEvidenceError('generation_expected_interruption_unproven')
                            else:
                                metadata['api_interrupted'] = {'status': result['status'], 'error': result['body']['detail']}
                    metadata['next_gate'] = 'pending_startup_safe'
                    try:
                        self.h.wait(lambda: self._pending_safe(metadata['pending_inventory'], original['worker']),
                                    'd6-pending-startup-safe', timeout=60)
                    finally:
                        metadata['last_control_status'] = self.last_control_status
                    metadata['pending_state'] = self._pending_safe(metadata['pending_inventory'], original['worker'])
                metadata['transition'] = f._phase('pending-crash', crash)
                def blocked():
                    self.h.wait(lambda: self._pending_safe(metadata['pending_inventory'], original['worker']),
                                'd6-pending-remains-safe', timeout=10)
                    metadata['pending_network'] = self.h.network_snapshot()
                metadata['blocked'] = f._phase('pending-blocked', blocked, blocked=True)
                def restore():
                    result = self._cli('restore', name=name, passphrase=passphrase)
                    if result != {'restored': True}:
                        raise FailureEvidenceError('generation_restore_unproven')
                    self.h.wait(self.h.healthy, 'd6-generation-restored-health', timeout=120)
                    after = self._inventory()
                    if after is None or after['selected_provider'] != 'mullvad' or any(item['status'] != 'active' for item in after['intents']):
                        raise FailureEvidenceError('generation_restored_intents_unproven')
                    restored = [item for item in after['intents'] if item['provider'] == 'mullvad' and item['status'] == 'active']
                    if restored != active:
                        raise FailureEvidenceError('generation_original_keys_unproven')
                    session = self.h.api('/api/auth/session', method='GET', body=None, timeout=30)
                    if session.get('status') != 200 or session.get('body', {}).get('authenticated') is not False:
                        raise FailureEvidenceError('generation_old_session_not_revoked')
                    metadata['restored_inventory'] = after
                    metadata['old_session_revoked'] = True
                    metadata['restore'] = result
                metadata['restored'] = f._phase('generation-restore', restore, recovery=True)
            return f._run('pending-generation', {'source': source, 'catalog_binding': binding,
                          'pending_provider': 'pia', 'authenticated_components_after_restore': 'REAUTHENTICATION_REQUIRED'}, run)
        finally:
            passphrase = None
