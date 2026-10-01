"""Bounded D6 failure components through real provider APIs and owned peer faults.

No provider/lifecycle factories are replaced. Caller first authenticates/imports
with ProviderQualification and supplies catalog selection IDs/profile IDs. Each
method is one attempt, with fresh capture phases and private durable receipts.
Faults stay in place on failure; restoring them is an explicit measured action.
DNS fault covers both UDP and TCP 53; it does not claim independent injections.
A component PASS is never complete D6 qualification or production support.
"""
from __future__ import annotations

import json
import re
import secrets
from concurrent.futures import ThreadPoolExecutor

from container_host_providers import (
    DIRECT,
    ENDPOINTS,
    PEER_SCRIPT,
    ProviderQualification,
)

FAULTS = {'handshake_off', 'dataplane_off', 'dns_off'}
CONNECT_ERRORS = {'vpn_connect_timeout', 'provider_dns_unavailable', 'provider_connect_failed',
                  'provider_egress_readiness_failed', 'container_provider_commit_failed'}


class FailureEvidenceError(RuntimeError):
    """Fixed identifiers only; no provider output or exception strings."""


class FailureQualification:
    def __init__(self, harness, captures, *, receipts):
        self.h, self.captures, self.receipts = harness, captures, receipts
        self.providers = ProviderQualification(harness, captures, receipts=receipts)
        self.last_api_response = None

    def _validate(self, provider, peer, *, target=None):
        if provider not in DIRECT or peer not in {'a', 'b'}:
            raise FailureEvidenceError('failure_target_invalid')
        if target is not None and (not isinstance(target, str) or re.fullmatch('[A-Za-z0-9_.:-]{1,80}', target) is None):
            raise FailureEvidenceError('failure_target_invalid')
        self.providers._authorized()

    def _bound_source(self, provider, peer):
        response = self.providers._api('/api/vpn/providers/' + provider + '/status')
        status, metadata = response.get('status'), response.get('provider')
        if (not isinstance(status, dict) or not isinstance(metadata, dict)
                or metadata.get('id') != provider or metadata.get('active') is not True
                or status.get('connected') is not True or status.get('is_active') is not True
                or status.get('latency_endpoint') != ENDPOINTS[peer]):
            raise FailureEvidenceError('failure_source_peer_unproven')
        return {'provider': provider, 'peer': peer, 'endpoint': status['latency_endpoint']}

    def _bound_target(self, provider, target, peer):
        if not isinstance(target, str):
            raise FailureEvidenceError('failure_explicit_target_required')
        if provider == 'proton':
            records = self.providers._api('/api/vpn/providers/proton/profiles').get('profiles')
            identifiers, endpoint = ('id',), 'endpoint'
        else:
            records = self.providers._api('/api/vpn/providers/' + provider + '/locations/NL/servers').get('servers')
            identifiers, endpoint = ('id', 'hostname'), 'station'
        if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
            raise FailureEvidenceError('failure_target_catalog_unproven')
        matches = [record for record in records if any(record.get(name) == target for name in identifiers)]
        if len(matches) != 1 or matches[0].get(endpoint) != ENDPOINTS[peer]:
            raise FailureEvidenceError('failure_target_peer_unproven')
        return {'provider': provider, 'target': target, 'peer': peer, 'endpoint': ENDPOINTS[peer]}

    def _fault(self, peer, action):
        if peer not in {'a', 'b'} or action not in FAULTS | {item.replace('_off', '_on') for item in FAULTS}:
            raise FailureEvidenceError('failure_fault_invalid')
        result = self.h.peer_fault(peer, action)
        dimension = action.replace('_on', '_off')
        if (not isinstance(result, dict) or result.get('run_id') != self.h.config['run_id']
                or result.get('role') != peer or not isinstance(result.get('faults'), dict)
                or result['faults'].get(dimension) is not action.endswith('_off')):
            raise FailureEvidenceError('failure_fault_unproven')
        return result

    def _action(self, provider, action, *, target=None, errors=None):
        # Switch allows up to the core's bounded 150-second transaction including
        # rollback. Transport deadline is bounded above it; no repeated POST.
        self.last_api_response = None
        result = self.h.api('/api/vpn/providers/' + provider + '/' + action,
                            method='POST', body={'target': target} if action == 'connect' else None, timeout=180)
        if not isinstance(result, dict) or not isinstance(result.get('body'), dict):
            raise FailureEvidenceError('failure_api_contract_invalid')
        body, status = result['body'], result.get('status')
        known_errors = CONNECT_ERRORS | {'provider_switch_failed', 'provider_not_ready',
                                        'container_ingress_required', 'provider_connection_conflict',
                                        'provider_not_active', 'provider_authentication_required',
                                        'vpn_action_in_progress', 'connection_failed'}
        code = body.get('detail') if status != 200 else body.get('error_code') or body.get('error')
        self.last_api_response = {
            'http_status': status if type(status) is int and 100 <= status <= 599 else None,
            'ok': body.get('ok') if type(body.get('ok')) is bool else None,
            'success': body.get('success') if type(body.get('success')) is bool else None,
            'error_code': code if isinstance(code, str) and code in known_errors else None,
        }
        if errors is None:
            if status != 200 or body.get('ok') is not True or body.get('success') is not True:
                raise FailureEvidenceError('failure_recovery_action_unproven')
            return {'http_status': status, 'success': True}
        if (status not in {200, 503} or code not in errors
                or status == 200 and (body.get('ok') is not False or body.get('success') is not False)):
            raise FailureEvidenceError('failure_expected_api_error_unproven')
        return {'http_status': status, 'expected_error': code}

    def _phase(self, label, operation, *, blocked=False, recovery=False):
        phase = 'f-' + label[:18] + '-' + secrets.token_hex(4)
        try:
            result = self.h.packet_phase(phase, self.captures, operation=operation,
                                         blocked=blocked, require_recovery=recovery)
        except BaseException as error:
            observations = {'phase': phase, 'diagnostic': self._diagnostic(error, phase), 'captures': {}}
            previous = getattr(self.h, 'last_packet_evidence', None)
            if previous is not None:
                observations['previous_packet_evidence'] = previous
            sender = getattr(self.h, 'last_sender', None)
            if sender is None and isinstance(getattr(self.h, 'last_packet_evidence', None), dict):
                sender = self.h.last_packet_evidence.get('sender_handle')
            handles = ([('sender', sender)] if sender is not None else []) + [
                ('capture-' + str(index), handle) for index, handle in enumerate(self.captures)]
            for name, handle in handles:
                try:
                    value = self.h.evidence(handle)
                    if name == 'sender':
                        observations['sender'] = value
                    else:
                        observations['captures'][name] = value
                except Exception:  # noqa: BLE001 -- a failed observer must not obscure the original stage
                    observations.setdefault('unavailable_observers', []).append(name)
            self.h.last_packet_evidence = observations
            self.receipts.write(phase + '-failed-observers.json', observations)
            raise
        if (not isinstance(result, dict) or result.get('receipt', {}).get('accepted') is not True
                or result['receipt'].get('phase') != phase):
            raise FailureEvidenceError('failure_packet_proof_unproven')
        artifact = self.receipts.write(phase + '-packets.json', result)
        return {'phase': phase, 'packets': artifact, 'blocked': blocked, 'fresh_recovery_required': recovery}

    @staticmethod
    def _diagnostic(error, phase=None):
        """Only static allowlisted codes/stages/functions, no arbitrary exception text."""
        code = error.args[0] if error.args and isinstance(error.args[0], str) else None
        allowed = {'qualification_phase_reused', 'qualification_family_state_invalid',
                   'qualification_sender_exit_failed', 'qualification_observer_exit_failed',
                   'failure_api_contract_invalid', 'failure_expected_api_error_unproven',
                   'failure_recovery_action_unproven', 'failure_packet_proof_unproven',
                   'failure_fault_unproven', 'failure_fault_invalid',
                   'generation_backup_name_invalid', 'generation_control_unavailable',
                   'generation_control_contract_invalid', 'generation_passphrase_invalid',
                   'generation_active_source_required', 'generation_baseline_invalid',
                   'generation_backup_unproven', 'generation_worker_identity_changed',
                   'generation_signal_unproven', 'generation_expected_interruption_unproven',
                   'generation_restore_unproven', 'generation_restored_intents_unproven',
                   'generation_original_keys_unproven', 'generation_old_session_not_revoked'}
        diagnostic = {'code': code if code in allowed else 'failure_stage_error'}
        if phase is not None:
            for stage in ('pressure_active', 'post_operation_pressure', 'fresh_provider_delivery', 'sender_finished'):
                if code == 'qualification_bounded_gate_failed:' + phase + '_' + stage:
                    diagnostic = {'code': 'qualification_bounded_gate_failed', 'stage': stage}
        for stage in ('d6-pia-pending-zero-handshake', 'd6-pending-startup-refused',
                      'd6-pending-remains-refused', 'd6-pending-startup-safe', 'd6-pending-remains-safe',
                      'd6-generation-restored-health'):
            if code == 'qualification_bounded_gate_failed:' + stage:
                diagnostic = {'code': 'qualification_bounded_gate_failed', 'stage': stage}
        functions = []
        trace = error.__traceback__
        while trace is not None:
            name = trace.tb_frame.f_code.co_name
            if name in {'packet_phase', 'wait', 'evidence', 'validate_receipts', '_action', '_fault', '_phase',
                        'crash', 'pending', 'restore', '_inventory', '_cli', '_refused', '_pending_safe'} and name not in functions:
                functions.append(name)
            trace = trace.tb_next
        diagnostic['functions'] = functions
        return diagnostic

    def _run(self, label, metadata, operation):
        identifier = 'failure-' + label + '-' + secrets.token_hex(4)
        name = identifier + '-metadata.json'
        metadata = {'component': label, 'result': 'RUNNING', 'full_d6_result': 'OUTSTANDING',
                    'production_supported': False, **metadata}
        self.providers._authorized()
        self.h.last_packet_evidence = None
        self.last_api_response = None
        self.receipts.write(name, metadata)
        try:
            operation(metadata)
            metadata['result'] = 'PACKET_COMPONENT_PASS'
            self.receipts.write(name, metadata)
            return metadata
        except BaseException as error:  # noqa: BLE001 -- remote errors may contain secret material
            metadata['result'] = 'FAILED'
            if self.last_api_response is not None:
                metadata['last_api_response'] = self.last_api_response
            evidence = getattr(self.h, 'last_packet_evidence', None)
            metadata['diagnostic'] = evidence.get('diagnostic', self._diagnostic(error)) if isinstance(evidence, dict) else self._diagnostic(error)
            if evidence is not None:
                metadata['failed_packets'] = self.receipts.write(identifier + '-failed-packets.json', evidence)
            self.receipts.write(name, metadata)
            raise FailureEvidenceError('failure_component_failed') from None

    def _handshake(self, provider, *, established):
        interface = DIRECT[provider][0]
        value = self.h.docker('exec', self.h.container, 'wg', 'show', interface, 'latest-handshakes', check=False)
        if not isinstance(value, dict) or value.get('code', 0) != 0:
            return False
        rows = value.get('stdout', '').splitlines()
        if len(rows) != 1:
            return False
        columns = rows[0].split()
        return len(columns) == 2 and columns[1].isdigit() and (int(columns[1]) > 0) is established

    def failed_connect(self, provider, *, target, peer, fault='handshake_off'):
        """Disconnected baseline; absent handshake, unusable dataplane or DNS loss."""
        self._validate(provider, peer, target=target)
        if fault not in FAULTS:
            raise FailureEvidenceError('failure_fault_invalid')
        if not self.providers._selected(provider, False):
            raise FailureEvidenceError('failure_disconnected_baseline_required')
        binding = self._bound_target(provider, target, peer)
        def run(metadata):
            def action():
                metadata['fault'] = self._fault(peer, fault)
                if fault == 'dataplane_off':
                    # Observe the actual WireGuard handshake while the real API
                    # transaction is live, without acquiring an API writer lease.
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        observation = pool.submit(self.h.wait, lambda: self._handshake(provider, established=True),
                                                  'd6-unusable-dataplane-handshake', timeout=30)
                        metadata['api'] = self._action(provider, 'connect', target=target, errors=CONNECT_ERRORS)
                        observation.result()
                    metadata['handshake_observed'] = True
                else:
                    metadata['api'] = self._action(provider, 'connect', target=target, errors=CONNECT_ERRORS)
                self.providers._wait_selected(provider, False)
            metadata['transition'] = self._phase('failed-connect', action)
            metadata['blocked'] = self._phase('connect-blocked', lambda: self.providers._wait_selected(provider, False), blocked=True)
        return self._run('failed-connect', {'provider': provider, 'peer': peer, 'fault_action': fault, 'target_binding': binding}, run)

    def late_handshake(self, provider, *, target, peer):
        self._validate(provider, peer, target=target)
        if not self.providers._selected(provider, False):
            raise FailureEvidenceError('failure_disconnected_baseline_required')
        binding = self._bound_target(provider, target, peer)
        def run(metadata):
            def action():
                metadata['fault'] = self._fault(peer, 'handshake_off')
                def release():
                    self.h.wait(lambda: self._handshake(provider, established=False),
                                'd6-late-handshake-zero-observed', timeout=30)
                    return self._fault(peer, 'handshake_on')
                with ThreadPoolExecutor(max_workers=1) as pool:
                    restored = pool.submit(release)
                    metadata['api'] = self._action(provider, 'connect', target=target)
                    metadata['released_after_zero_handshake'] = restored.result()
                self.providers._wait_selected(provider, True)
            metadata['recovered'] = self._phase('late-handshake', action, recovery=True)
        return self._run('late-handshake', {'provider': provider, 'peer': peer, 'target_binding': binding}, run)

    def provider_loss(self, provider, *, peer, fault='handshake_off'):
        self._validate(provider, peer)
        if fault not in FAULTS:
            raise FailureEvidenceError('failure_fault_invalid')
        if not self.providers._selected(provider, True):
            raise FailureEvidenceError('failure_connected_baseline_required')
        binding = self._bound_source(provider, peer)
        def run(metadata):
            def action():
                metadata['fault'] = self._fault(peer, fault)
                self.providers._wait_selected(provider, False)
            metadata['transition'] = self._phase('provider-loss', action)
            metadata['blocked'] = self._phase('loss-blocked', lambda: self.providers._wait_selected(provider, False), blocked=True)
            if fault == 'dns_off':
                metadata['dns_protocols_injected'] = ['udp', 'tcp']
        return self._run('provider-loss', {'provider': provider, 'peer': peer, 'fault_action': fault, 'source_binding': binding}, run)

    def prepare_catalogs(self, *, mullvad, pia):
        """Pin only synthetic responses; caller then qualifies a fresh worker.

        Return this receipt to failed_switch after the independently measured
        worker restart. No core cache mutation or restart is performed here.
        """
        self.providers._authorized()
        if mullvad not in {'a', 'b'} or pia not in {'a', 'b'}:
            raise FailureEvidenceError('failure_catalog_invalid')
        before = self.h.process_identity()
        result = json.loads(self.providers._command(self.h.peer, ['/usr/bin/python3', PEER_SCRIPT, 'catalog'],
            data=json.dumps({'run_id': self.h.config['run_id'], 'mullvad': mullvad, 'pia': pia})))
        expected = {'run_id': self.h.config['run_id'], 'catalogs': {'mullvad': [mullvad], 'pia': [pia]}}
        if result != expected:
            raise FailureEvidenceError('failure_catalog_unproven')
        preparation = {**result, 'previous_process': before}
        self.receipts.write('failure-catalog-preparation-' + secrets.token_hex(4) + '.json', preparation)
        return preparation

    def _prepared_catalogs(self, preparation, source, target_provider, source_peer, target_peer):
        if source not in {'mullvad', 'pia'} or target_provider not in {'mullvad', 'pia'}:
            raise FailureEvidenceError('failure_cross_provider_selection_unproven')
        expected = {'run_id': self.h.config['run_id'], 'catalogs': {source: [source_peer], target_provider: [target_peer]}}
        if (not isinstance(preparation, dict) or set(preparation) != {'run_id', 'catalogs', 'previous_process'}
                or any(preparation[name] != expected[name] for name in expected)
                or not isinstance(preparation['previous_process'], dict)):
            raise FailureEvidenceError('failure_cross_provider_selection_unproven')
        observed = json.loads(self.providers._command(self.h.peer, ['/usr/bin/python3', PEER_SCRIPT, 'catalog'],
                              data=json.dumps({'run_id': self.h.config['run_id']})))
        current = self.h.process_identity()
        previous = preparation['previous_process']
        if (observed != expected or not isinstance(current, dict)
                or not isinstance(current.get('worker'), list) or len(current['worker']) != 2
                or not isinstance(previous.get('worker'), list) or len(previous['worker']) != 2
                or current['worker'] == previous['worker']):
            raise FailureEvidenceError('failure_fresh_worker_unproven')
        return {'catalogs': observed, 'before': previous, 'after': current}

    def failed_switch(self, source, target_provider, *, source_peer, target_peer, rollback=True, catalog_preparation=None):
        """Cross-provider activation fails; source recovers or remains blocked.

        Mullvad/PIA catalogs must be pinned with prepare_catalogs, followed by an
        independently qualified worker restart. Core activate and rollback use
        connect(None); readback plus a fresh worker excludes cached/random relays.
        """
        self._validate(source, source_peer)
        self._validate(target_provider, target_peer)
        if source == target_provider or source_peer == target_peer or type(rollback) is not bool:
            raise FailureEvidenceError('failure_switch_topology_invalid')
        preparation = self._prepared_catalogs(catalog_preparation, source, target_provider, source_peer, target_peer)
        if not self.providers._selected(source, True):
            raise FailureEvidenceError('failure_connected_baseline_required')
        source_binding = self._bound_source(source, source_peer)
        # Public source catalog proves the fresh core consumes the selected API
        # response. The target's cache is empty in that same new worker.
        servers = self.providers._api('/api/vpn/providers/' + source + '/locations/NL/servers').get('servers')
        if (not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], dict)
                or servers[0].get('station') != {'a': '192.0.0.9', 'b': '192.0.0.10'}[source_peer]):
            raise FailureEvidenceError('failure_core_catalog_unproven')
        def run(metadata):
            def action():
                metadata['target_fault'] = self._fault(target_peer, 'handshake_off')
                if not rollback:
                    def break_source():
                        self.h.wait(lambda: self._handshake(target_provider, established=False),
                                    'd6-target-handoff-started', timeout=30)
                        return self._fault(source_peer, 'handshake_off')
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        broken = pool.submit(break_source)
                        metadata['api'] = self._action(target_provider, 'activate', errors={'provider_switch_failed'})
                        metadata['source_fault'] = broken.result()
                else:
                    metadata['api'] = self._action(target_provider, 'activate', errors={'provider_switch_failed'})
                self.providers._wait_selected(source, rollback)
            metadata['transition'] = self._phase('failed-switch', action, recovery=rollback)
            metadata['steady'] = self._phase('rollback-result', lambda: self.providers._wait_selected(source, rollback),
                                             blocked=not rollback, recovery=rollback)
        return self._run('failed-switch', {'source': source, 'target_provider': target_provider,
                        'source_peer': source_peer, 'target_peer': target_peer, 'rollback_expected': rollback,
                        'catalog_preparation': preparation, 'source_binding': source_binding}, run)

    def failed_target(self, provider, *, target, source_peer, target_peer, rollback=True):
        """Real same-provider connect(B) while A is committed, with rollback proof."""
        self._validate(provider, target_peer, target=target)
        if source_peer not in {'a', 'b'} or source_peer == target_peer or type(rollback) is not bool:
            raise FailureEvidenceError('failure_switch_topology_invalid')
        if not self.providers._selected(provider, True):
            raise FailureEvidenceError('failure_connected_baseline_required')
        source_binding = self._bound_source(provider, source_peer)
        target_binding = self._bound_target(provider, target, target_peer)
        def run(metadata):
            def action():
                metadata['target_fault'] = self._fault(target_peer, 'handshake_off')
                if not rollback:
                    def break_source():
                        self.h.wait(lambda: self._handshake(provider, established=False),
                                    'd6-target-generation-started', timeout=30)
                        return self._fault(source_peer, 'handshake_off')
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        broken = pool.submit(break_source)
                        metadata['api'] = self._action(provider, 'connect', target=target, errors=CONNECT_ERRORS)
                        metadata['source_fault'] = broken.result()
                else:
                    metadata['api'] = self._action(provider, 'connect', target=target, errors=CONNECT_ERRORS)
                self.providers._wait_selected(provider, rollback)
            metadata['transition'] = self._phase('failed-target', action, recovery=rollback)
            metadata['steady'] = self._phase('target-rollback', lambda: self.providers._wait_selected(provider, rollback),
                                             blocked=not rollback, recovery=rollback)
        return self._run('failed-target', {'provider': provider, 'source_peer': source_peer,
                        'target_peer': target_peer, 'rollback_expected': rollback,
                        'source_binding': source_binding, 'target_binding': target_binding}, run)
