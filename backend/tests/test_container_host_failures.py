"""Failure API and packet contracts with fake transport, no core factory patch."""
import importlib.util
import json
import threading
from pathlib import Path

import pytest
from test_container_host_providers import PRIVATE, FakeHarness, MemoryReceipts

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('container_host_failures', ROOT / 'scripts/qualification/container_host_failures.py')
failures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(failures)


class FailureHarness(FakeHarness):
    def __init__(self):
        super().__init__()
        self.faults = {role: {'handshake_off': False, 'dataplane_off': False, 'dns_off': False} for role in ('a', 'b')}
        self.fault_calls = []
        self.api_error = 'vpn_connect_timeout'
        self.wrong_error = False
        self.unexpected_success = False
        self.late = False
        self.candidate_started = threading.Event()
        self.peer_enabled = threading.Event()
        self.break_source = False
        self.source_broken = threading.Event()
        self.handshake_positive = False
        self.reject_steady = False
        self.worker = [17, '1000']
        self.catalogs = {'mullvad': ['a', 'b'], 'pia': ['a', 'b']}
        self.old_catalog_cache = False

    def process_identity(self):
        return {'host_pid': 123, 'started': 'synthetic', 'restart_count': 0, 'worker': list(self.worker)}

    def command(self, host, arguments, *, data):
        if arguments[-1] == 'catalog':
            assert host is self.peer
            payload = json.loads(data)
            if 'mullvad' in payload:
                self.catalogs = {name: [payload[name]] for name in ('mullvad', 'pia')}
            return {'code': 0, 'stdout': json.dumps({'run_id': self.config['run_id'], 'catalogs': self.catalogs})}
        return super().command(host, arguments, data=data)

    def peer_fault(self, role, action):
        self.fault_calls.append((role, action))
        self.faults[role][action.replace('_on', '_off')] = action.endswith('_off')
        if action == 'handshake_on':
            self.peer_enabled.set()
        if role == 'a' and action == 'handshake_off' and self.candidate_started.is_set():
            self.source_broken.set()
        return {'run_id': self.config['run_id'], 'role': role, 'faults': dict(self.faults[role])}

    def api(self, path, *, method, body, timeout):
        if path.endswith('/locations/NL/servers'):
            provider = path.split('/')[4]
            roles = ['a', 'b'] if self.old_catalog_cache else self.catalogs[provider]
            return {'status': 200, 'body': {'servers': [
                {'id': 'nl-ams-wg-' + role if provider == 'mullvad' else role + '.synthetic-' + role,
                 'hostname': 'nl-ams-wg-' + role if provider == 'mullvad' else role + '.synthetic-' + role,
                 'station': {'a': '192.0.0.9', 'b': '192.0.0.10'}[role]} for role in roles]}}
        if path == '/api/vpn/providers/proton/profiles':
            return {'status': 200, 'body': {'profiles': [{'id': 'a' * 24, 'endpoint': '192.0.0.9'},
                                                      {'id': 'b' * 24, 'endpoint': '192.0.0.10'}]}}
        if method != 'POST':
            assert timeout == 90
            return super().api(path, method=method, body=body, timeout=timeout)
        assert timeout == 180
        self.api_calls.append((path, method, body))
        action = path.split('/')[-1]
        assert action in {'connect', 'activate'}
        self.candidate_started.set()
        if self.late:
            assert self.peer_enabled.wait(1)
            self.connected = True
            return {'status': 200, 'body': {'ok': True, 'success': True}}
        if self.break_source:
            assert self.source_broken.wait(1)
            self.connected = False
        # An actual successful API operation is a failure of the expected-failure
        # test, even if a later packet observation could have been acceptable.
        if self.unexpected_success:
            return {'status': 200, 'body': {'ok': True, 'success': True}}
        error = 'untrusted-' + PRIVATE if self.wrong_error else self.api_error
        if action == 'activate':
            return {'status': 503, 'body': {'detail': error}}
        return {'status': 200, 'body': {'ok': False, 'success': False, 'error_code': error}}

    def docker(self, *args, check=True):
        if 'latest-handshakes' in args:
            assert check is False
            assert self.candidate_started.wait(1)
            return {'code': 0, 'stdout': 'public-only\t' + ('123' if self.handshake_positive else '0') + '\n'}
        return super().docker(*args)

    def peer_fault_loss(self, role, action):
        value = self.peer_fault(role, action)
        self.connected = False
        return value

    def packet_phase(self, phase, captures, *, operation, blocked, require_recovery):
        self.pressure.append((phase, captures, blocked, require_recovery))
        self.last_packet_evidence = {'phase': phase, 'sender': {'attempts': [1]}, 'captures': {}}
        operation()
        return {'receipt': {'phase': phase, 'accepted': not (blocked and self.reject_steady)},
                **self.last_packet_evidence}


def qualification(*, connected=False):
    h, receipts = FailureHarness(), MemoryReceipts()
    h.connected = connected
    return failures.FailureQualification(h, ['continuous-external-captures'], receipts=receipts), h, receipts


@pytest.mark.parametrize('fault', ['handshake_off', 'dns_off', 'dataplane_off'])
def test_failed_connect_expected_api_failure_and_separate_blocked_packet_proof(fault):
    value, h, receipts = qualification()
    h.handshake_positive = fault == 'dataplane_off'
    result = value.failed_connect('mullvad', target='nl-ams-wg-b', peer='b', fault=fault)
    assert result['result'] == 'PACKET_COMPONENT_PASS'
    assert result['full_d6_result'] == 'OUTSTANDING' and result['production_supported'] is False
    assert h.fault_calls == [('b', fault)]
    assert h.api_calls.count(('/api/vpn/providers/mullvad/connect', 'POST', {'target': 'nl-ams-wg-b'})) == 1
    assert [entry[2:] for entry in h.pressure] == [(False, False), (True, False)]
    assert result['transition']['phase'] != result['blocked']['phase']
    assert result['api']['expected_error'] == 'vpn_connect_timeout'
    assert PRIVATE not in json.dumps(receipts.values)
    if fault == 'dataplane_off':
        assert result['handshake_observed'] is True


@pytest.mark.parametrize('kind', ['wrong_error', 'unexpected_success', 'reject_steady'])
def test_api_expectation_and_packet_acceptance_are_independent_and_never_retried(kind):
    value, h, receipts = qualification()
    setattr(h, kind, True)
    with pytest.raises(failures.FailureEvidenceError, match='failure_component_failed') as error:
        value.failed_connect('mullvad', target='nl-ams-wg-b', peer='b')
    assert PRIVATE not in str(error.value) and PRIVATE not in json.dumps(receipts.values)
    assert len([path for path, method, _body in h.api_calls if method == 'POST']) == 1
    metadata = next(value for name, value in receipts.values.items() if name.endswith('-metadata.json'))
    assert metadata['result'] == 'FAILED' and metadata['failed_packets']
    assert h.fault_calls == [('b', 'handshake_off')]  # no silent cleanup/retry


def test_late_handshake_release_waits_for_real_candidate_zero_before_one_connect_recovers():
    value, h, _receipts = qualification()
    h.late = True
    result = value.late_handshake('mullvad', target='nl-ams-wg-b', peer='b')
    assert result['result'] == 'PACKET_COMPONENT_PASS'
    assert h.fault_calls == [('b', 'handshake_off'), ('b', 'handshake_on')]
    assert h.pressure[-1][2:] == (False, True)
    assert len([path for path, method, _body in h.api_calls if method == 'POST']) == 1


@pytest.mark.parametrize('rollback', [True, False])
def test_failed_target_rolls_back_or_stays_blocked_without_invalidating_source_before_handoff(rollback):
    value, h, _receipts = qualification(connected=True)
    h.break_source = not rollback
    result = value.failed_target('mullvad', target='nl-ams-wg-b', source_peer='a', target_peer='b', rollback=rollback)
    assert ('/api/vpn/providers/mullvad/connect', 'POST', {'target': 'nl-ams-wg-b'}) in h.api_calls
    assert result['result'] == 'PACKET_COMPONENT_PASS'
    assert h.pressure[-1][2:] == (not rollback, rollback)
    assert h.active == 'mullvad'
    assert h.fault_calls == [('b', 'handshake_off')] + ([] if rollback else [('a', 'handshake_off')])
    assert h.connected is rollback


@pytest.mark.parametrize('fault', ['handshake_off', 'dataplane_off', 'dns_off'])
def test_loss_and_dns_udp_tcp_are_owned_faults_no_api_mutation_or_recovery_claim(fault):
    value, h, _receipts = qualification(connected=True)
    original = h.peer_fault
    def loss(role, action):
        result = original(role, action)
        h.connected = False
        return result
    h.peer_fault = loss
    result = value.provider_loss('mullvad', peer='a', fault=fault)
    assert result['blocked']['blocked'] is True
    assert not any(method == 'POST' for _path, method, _body in h.api_calls)
    if fault == 'dns_off':
        assert result['dns_protocols_injected'] == ['udp', 'tcp']


def test_no_fault_until_auth_baseline_and_topology_are_verified():
    value, h, _receipts = qualification(connected=True)
    h.authenticated = False
    with pytest.raises(Exception, match='provider_authentication_required'):
        value.provider_loss('mullvad', peer='a')
    assert h.fault_calls == []
    h.authenticated = True
    with pytest.raises(failures.FailureEvidenceError, match='switch_topology_invalid'):
        value.failed_switch('mullvad', 'pia', source_peer='a', target_peer='a')
    assert h.fault_calls == []


def test_random_cross_provider_default_selection_is_gated_before_fault_or_mutation():
    value, h, _receipts = qualification(connected=True)
    with pytest.raises(failures.FailureEvidenceError, match='cross_provider_selection_unproven'):
        value.failed_switch('mullvad', 'pia', source_peer='a', target_peer='b')
    assert not h.fault_calls and not h.pressure
    assert not any(method == 'POST' for _path, method, _body in h.api_calls)


@pytest.mark.parametrize('rollback', [True, False])
def test_cross_provider_failure_requires_pinned_catalog_actual_fresh_worker_and_core_readback(rollback):
    value, h, _receipts = qualification(connected=True)
    preparation = value.prepare_catalogs(mullvad='a', pia='b')
    with pytest.raises(failures.FailureEvidenceError, match='fresh_worker_unproven'):
        value.failed_switch('mullvad', 'pia', source_peer='a', target_peer='b', catalog_preparation=preparation)
    assert h.fault_calls == []
    h.worker = [18, '1100']
    h.api_error = 'provider_switch_failed'
    h.break_source = not rollback
    result = value.failed_switch('mullvad', 'pia', source_peer='a', target_peer='b',
                                rollback=rollback, catalog_preparation=preparation)
    assert result['result'] == 'PACKET_COMPONENT_PASS'
    assert result['catalog_preparation']['before']['worker'] != result['catalog_preparation']['after']['worker']
    assert h.pressure[-1][2:] == (not rollback, rollback)
    assert ('/api/vpn/providers/pia/activate', 'POST', None) in h.api_calls


def test_changed_fixture_catalog_or_old_core_cache_denies_before_fault():
    value, h, _receipts = qualification(connected=True)
    preparation = value.prepare_catalogs(mullvad='a', pia='b')
    h.worker = [18, '1100']
    h.old_catalog_cache = True
    with pytest.raises(failures.FailureEvidenceError, match='core_catalog_unproven'):
        value.failed_switch('mullvad', 'pia', source_peer='a', target_peer='b', catalog_preparation=preparation)
    h.catalogs['pia'] = ['a', 'b']
    with pytest.raises(failures.FailureEvidenceError, match='fresh_worker_unproven'):
        value.failed_switch('mullvad', 'pia', source_peer='a', target_peer='b', catalog_preparation=preparation)
    assert not h.fault_calls


def test_unusable_dataplane_cannot_pass_without_observed_real_handshake():
    value, h, receipts = qualification()
    h.handshake_positive = False
    with pytest.raises(failures.FailureEvidenceError, match='failure_component_failed'):
        value.failed_connect('mullvad', target='nl-ams-wg-b', peer='b', fault='dataplane_off')
    assert not any(item.get('result') == 'PACKET_COMPONENT_PASS' for item in receipts.values.values())


def test_component_failed_packet_evidence_persists_without_exception_secrets():
    value, h, receipts = qualification()
    def packet_failure(*_args, **_kwargs):
        h.last_packet_evidence = {'phase': 'evidence-kept', 'sender': {'attempts': [1]}}
        raise RuntimeError(PRIVATE)
    h.packet_phase = packet_failure
    with pytest.raises(failures.FailureEvidenceError) as error:
        value.failed_connect('mullvad', target='nl-ams-wg-b', peer='b')
    assert PRIVATE not in str(error.value) and PRIVATE not in json.dumps(receipts.values)
    assert any(data.get('previous_packet_evidence', {}).get('phase') == 'evidence-kept' for data in receipts.values.values())
    assert not h.fault_calls  # phase refused before running operation


def test_packet_exception_collects_readonly_sender_and_all_observers_without_retry_or_secret_text():
    value, h, receipts = qualification()
    handles = [{'role': 'wan'}, {'role': 'provider-a'}, {'role': 'provider-b'}]
    value.captures = handles
    observed = []
    def evidence(handle):
        observed.append(handle)
        return {'public_packets': [1, 2], 'role': handle['role']}
    h.evidence = evidence
    def fail(phase, captures, *, operation, blocked, require_recovery):
        operation()
        h.last_sender = {'role': 'sender'}
        raise RuntimeError('qualification_bounded_gate_failed:' + phase + '_sender_finished')
    h.packet_phase = fail
    with pytest.raises(failures.FailureEvidenceError):
        value.failed_connect('mullvad', target='nl-ams-wg-b', peer='b')
    assert observed == [{'role': 'sender'}, *handles]
    metadata = next(data for name, data in receipts.values.items() if name.endswith('-metadata.json'))
    assert metadata['diagnostic']['code'] == 'qualification_bounded_gate_failed'
    assert metadata['diagnostic']['stage'] == 'sender_finished'
    raw = next(data for name, data in receipts.values.items() if name.endswith('-failed-observers.json'))
    assert len(raw['captures']) == 3 and raw['sender']['public_packets'] == [1, 2]
    assert len([path for path, method, _body in h.api_calls if method == 'POST']) == 1
    assert h.fault_calls == [('b', 'handshake_off')]


def test_diagnostic_never_copies_unknown_exception_text_or_trace_paths():
    value, h, receipts = qualification()
    def fail(*args, **kwargs):
        raise RuntimeError('qualification_bounded_gate_failed:' + PRIVATE)
    h.packet_phase = fail
    with pytest.raises(failures.FailureEvidenceError):
        value.failed_connect('mullvad', target='nl-ams-wg-b', peer='b')
    metadata = next(data for name, data in receipts.values.items() if name.endswith('-metadata.json'))
    assert metadata['diagnostic']['code'] == 'failure_stage_error'
    assert PRIVATE not in json.dumps(receipts.values)


def test_handshake_probe_waits_through_missing_interface_without_raising_or_enabling_peer():
    value, h, _receipts = qualification()
    results = [{'code': 1, 'stdout': '', 'stderr': PRIVATE}, {'code': 0, 'stdout': 'public\t0\n'}]
    def wg_query(*arguments, check=True):
        assert check is False and arguments[-1] == 'latest-handshakes'
        return results.pop(0)
    h.docker = wg_query
    assert value._handshake('mullvad', established=False) is False
    assert not h.fault_calls
    assert value._handshake('mullvad', established=False) is True


def test_wrong_recovery_action_retains_only_known_api_status_fields_without_secrets():
    value, h, receipts = qualification()
    # HTTP200 connect timeout is an expected failure in a failed-connect test,
    # but is the wrong result in a late-handshake recovery test.
    def timeout(*_args, **_kwargs):
        return {'status': 200, 'body': {'ok': False, 'success': False, 'error_code': 'vpn_connect_timeout',
                                      'error': PRIVATE, 'config': PRIVATE}}
    h.api = timeout
    with pytest.raises(failures.FailureEvidenceError, match='recovery_action_unproven'):
        value._action('mullvad', 'connect', target='nl-ams-wg-b')
    assert value.last_api_response == {'http_status': 200, 'ok': False, 'success': False, 'error_code': 'vpn_connect_timeout'}
    h.api = lambda *_args, **_kwargs: {'status': 200, 'body': {'ok': False, 'success': False, 'error_code': PRIVATE}}
    with pytest.raises(failures.FailureEvidenceError):
        value._action('mullvad', 'connect')
    assert value.last_api_response['error_code'] is None
    assert PRIVATE not in json.dumps(value.last_api_response)
    assert receipts.values == {}


@pytest.mark.parametrize('operation', ['failed_connect', 'late_handshake'])
def test_explicit_target_must_resolve_to_fault_peer_before_any_mutation(operation):
    value, h, _receipts = qualification()
    with pytest.raises(failures.FailureEvidenceError, match='target_peer_unproven'):
        getattr(value, operation)('mullvad', target='nl-ams-wg-a', peer='b')
    assert not h.fault_calls and not h.pressure
    assert not any(method == 'POST' for _path, method, _body in h.api_calls)


@pytest.mark.parametrize('target', [None, 'NL', 'recommended', 'unknown-relay'])
def test_country_default_or_unknown_selection_is_not_an_exact_peer_binding(target):
    value, h, _receipts = qualification()
    with pytest.raises(failures.FailureEvidenceError):
        value.failed_connect('mullvad', target=target, peer='b')
    assert not h.fault_calls and not h.pressure


@pytest.mark.parametrize('operation', ['provider_loss', 'failed_target'])
def test_connected_source_must_match_caller_peer_before_any_fault(operation):
    value, h, _receipts = qualification(connected=True)
    with pytest.raises(failures.FailureEvidenceError, match='source_peer_unproven'):
        if operation == 'provider_loss':
            value.provider_loss('mullvad', peer='b')
        else:
            value.failed_target('mullvad', target='nl-ams-wg-a', source_peer='b', target_peer='a')
    assert not h.fault_calls and not h.pressure
    assert not any(method == 'POST' for _path, method, _body in h.api_calls)


def test_target_peer_binding_is_exact_for_pia_catalog_and_proton_public_profile():
    value, h, _receipts = qualification()
    assert value._bound_target('pia', 'b.synthetic-b', 'b')['endpoint'] == '192.0.0.10'
    assert value._bound_target('proton', 'b' * 24, 'b')['endpoint'] == '192.0.0.10'
    with pytest.raises(failures.FailureEvidenceError, match='target_peer_unproven'):
        value._bound_target('proton', 'a' * 24, 'b')
    h.catalogs['pia'] = ['a']
    with pytest.raises(failures.FailureEvidenceError, match='target_peer_unproven'):
        value._bound_target('pia', 'b.synthetic-b', 'b')
    assert not h.fault_calls
