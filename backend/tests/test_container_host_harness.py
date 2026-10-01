"""Disposable-host faults must never target unidentified/shared hosts."""
import importlib.util
import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / 'scripts/qualification'))
SPEC = importlib.util.spec_from_file_location('host_harness', ROOT / 'scripts/qualification/container_host.py')
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


@pytest.fixture
def configuration(tmp_path):
    identity, known = tmp_path / 'identity', tmp_path / 'known'
    identity.write_text('synthetic-identity-path-only'); identity.chmod(0o600)
    known.write_text('synthetic-host-key-path-only'); known.chmod(0o600)
    return {'run_id': str(uuid.uuid4()),
            'candidate': {'address': '192.168.99.10', 'hostname': 'exitlane-docker-d6-synthetic', 'user': 'codex'},
            'peer': {'address': '192.168.99.11', 'hostname': 'exitlane-docker-d6-peer-synthetic', 'user': 'codex'},
            'identity': str(identity), 'known_hosts': str(known), 'image': 'sha256:' + 'a' * 64,
            'revision': 'b' * 40, 'allow_host_restart': True}


@pytest.mark.parametrize('field,value', [('image', 'moving:latest'), ('revision', 'main'),
                                       ('run_id', '../existing'), ('allow_host_restart', 'yes')])
def test_configuration_rejects_unbounded_identity(configuration, field, value):
    configuration[field] = value
    with pytest.raises(harness.QualificationError, match='qualification_config_invalid'):
        harness.validate_config(configuration)


@pytest.mark.parametrize('field,value', [('address', '1.1.1.1'), ('address', '127.0.0.1'),
                                      ('hostname', 'production'), ('user', 'codex; id')])
def test_host_boundaries_are_explicit(configuration, field, value):
    configuration['candidate'][field] = value
    with pytest.raises(harness.QualificationError):
        harness.validate_config(configuration)


def test_secret_transfer_uses_stdin_and_checks_hostname(configuration, monkeypatch):
    calls = []
    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0, '{}', '')
    monkeypatch.setattr(harness.subprocess, 'run', run)
    remote = harness.Remote(configuration['candidate'], configuration['identity'], configuration['known_hosts'])
    remote.run('print(payload)\n', data={'secret': 'synthetic-private-material'})
    args, kwargs = calls[0]
    assert 'synthetic-private-material' not in ' '.join(args)
    assert 'synthetic-private-material' in kwargs['input']
    assert "os.uname().nodename != 'exitlane-docker-d6-synthetic'" in kwargs['input']
    assert args[-3:] == ['sudo', 'python3', '-']
    assert 'ForwardAgent=no' in args and 'StrictHostKeyChecking=yes' in args


def test_remote_errors_never_include_captured_material(configuration, monkeypatch):
    monkeypatch.setattr(harness.subprocess, 'run', lambda args, **kw:
                        subprocess.CompletedProcess(args, 1, 'synthetic-cookie', 'synthetic-private-key'))
    remote = harness.Remote(configuration['candidate'], configuration['identity'], configuration['known_hosts'])
    with pytest.raises(harness.QualificationError) as error:
        remote.run('print("bounded")\n')
    assert str(error.value) == 'qualification_remote_operation_failed'


def test_no_restart_before_authorization_or_ownership(configuration):
    configuration['allow_host_restart'] = False
    instance = harness.HostHarness(configuration)
    instance.docker = lambda *a, **kw: pytest.fail('mutation before authorization')
    with pytest.raises(harness.QualificationError, match='qualification_host_fault_not_authorized'):
        instance.fault('host_reboot')


def test_foreign_containers_block_whole_host_faults(configuration):
    instance = harness.HostHarness(configuration)
    instance.docker = lambda *a, **kw: {'stdout': 'unrelated-appliance\n'}
    with pytest.raises(harness.QualificationError, match='qualification_foreign_container_present'):
        instance.fault('daemon_restart')


def test_resource_label_mismatch_is_never_adopted(configuration):
    instance = harness.HostHarness(configuration)
    instance.docker = lambda *a, **kw: {'stdout': json.dumps([{'Config': {'Labels': {
        'org.exitlane.qualification.run': str(uuid.uuid4())}}}])}
    with pytest.raises(harness.QualificationError, match='qualification_resource_ownership_mismatch'):
        instance.assert_owned('container', instance.container)


def test_actual_candidate_does_not_gain_forbidden_privileges(configuration):
    instance = harness.HostHarness(configuration)
    calls = []
    instance.docker = lambda *a, **kw: calls.append(a) or {'stdout': ''}
    instance.wait = lambda *a, **kw: None
    instance.create()
    args = calls[0]
    assert args[args.index('--cap-add') + 1] == 'NET_ADMIN'
    assert args[args.index('--cap-drop') + 1] == 'ALL'
    assert args[args.index('--network') + 1] == instance.network
    assert args.count('--mount') == 1 and args[args.index('--mount') + 1].endswith('dst=/data')
    assert '--privileged' not in args and 'SYS_ADMIN' not in args and 'NET_RAW' not in args
    assert '127.0.0.1:8787:8787/tcp' in args
    assert configuration['candidate']['address'] + ':51820:51820/udp' in args


def test_measured_daemon_fault_does_not_change_mode(configuration):
    instance = harness.HostHarness(configuration)
    instance.assert_disposable = lambda: None
    instance.assert_owned = lambda *a: {}
    instance.pair = lambda: {'synthetic': 'pair'}
    instance.process_identity = lambda: {'worker': [9, '100'], 'host_pid': 1}
    instance.assert_daemon_mode = lambda enabled: (_ for _ in ()).throw(
        harness.QualificationError('qualification_daemon_mode_unproven'))
    calls = []
    instance.candidate.run = lambda source, **kw: calls.append(source) or 'synthetic-boot'
    with pytest.raises(harness.QualificationError, match='qualification_daemon_mode_unproven'):
        instance.fault('daemon_live_restore')
    assert all('restart' not in source and 'daemon.json' not in source for source in calls)


def test_sender_needs_owned_namespace_before_any_unit(configuration):
    instance = harness.HostHarness(configuration)
    instance.command = lambda *a, **kw: {'stdout': json.dumps({
        'run_id': configuration['run_id'], 'role': 'client', 'namespace': 'foreign'})}
    instance.peer.run = lambda *a, **kw: pytest.fail('unit created before namespace ownership')
    name = 'ed6-' + configuration['run_id'].replace('-', '')[:10] + '-client'
    with pytest.raises(harness.QualificationError, match='qualification_namespace_ownership_mismatch'):
        instance.external_process('sender', 'synthetic', namespace=name, source_address='10.77.0.2')


@pytest.mark.parametrize('code,marker,accepted', [(0, 'qualification_signal_sent', True),
    (137, 'qualification_signal_sent', True), (137, '', False), (1, 'qualification_signal_sent', False)])
def test_parent_signal_requires_intent_marker_and_actual_recovery(configuration, code, marker, accepted):
    instance = harness.HostHarness(configuration)
    instance.assert_disposable = lambda: None
    instance.assert_owned = lambda *a: {}
    instance.pair = lambda: {'synthetic': 'pair'}
    calls = iter([{'worker': [1, '100']}, {'worker': [2, '200']}, {'worker': [2, '200']}])
    instance.process_identity = lambda: next(calls)
    instance.candidate.run = lambda *a, **kw: 'synthetic-boot'
    instance.docker = lambda *a, **kw: {'code': code, 'stdout': marker, 'stderr': ''}
    instance.healthy = lambda: True
    instance.wait = lambda probe, *a, **kw: probe() or pytest.fail('no actual process recovery')
    if accepted:
        instance.fault('parent_crash')
        assert instance.receipts[0]['signal_sent']
        assert instance.receipts[-1]['process_before'] != instance.receipts[-1]['process_after']
    else:
        with pytest.raises(harness.QualificationError, match='qualification_signal_injection_unproven'):
            instance.fault('parent_crash')
        assert instance.receipts == []


def test_reusing_packet_phase_fails_before_pressure_or_fault(configuration):
    instance = harness.HostHarness(configuration)
    instance.evidence = lambda handle: {'phase': 'already-used'}
    instance.control = lambda *a, **kw: pytest.fail('control changed before phase identity gate')
    instance.fault = lambda *a, **kw: pytest.fail('fault before phase identity gate')
    with pytest.raises(harness.QualificationError, match='qualification_phase_reused'):
        instance.packet_phase('already-used', [{'role': 'client'}], fault='parent_crash')


@pytest.mark.parametrize('family', [0, 5, True, '6'])
def test_sender_rejects_unknown_family_before_remote_access(configuration, family):
    instance = harness.HostHarness(configuration)
    instance.peer.run = lambda *a, **kw: pytest.fail('remote access before validation')
    with pytest.raises(harness.QualificationError, match='qualification_family_invalid'):
        instance.external_process('sender', 'synthetic', namespace='owned', family=family)


def test_ipv6_capture_control_selects_separate_calibration(configuration):
    instance = harness.HostHarness(configuration)
    calls = []
    instance.peer.run = lambda source, **kw: calls.append(kw['data'])
    instance.control({'kind': 'capture', 'root': '/run/synthetic', 'family': 6}, 'proof6')
    assert calls[0]['value']['calibration_phase'] == 'calibration6'


def test_invalid_calibration_phase_rejected_before_remote(configuration):
    instance = harness.HostHarness(configuration)
    instance.peer.run = lambda *a, **kw: pytest.fail('remote access before validation')
    with pytest.raises(harness.QualificationError, match='qualification_phase_invalid'):
        instance.control({'kind': 'capture'}, 'proof', calibration_phase='untrusted; command')


@pytest.mark.parametrize('family,blocked,recovery', [(6, False, False), (6, True, True), (5, True, False)])
def test_ipv6_never_claims_provider_recovery(configuration, family, blocked, recovery):
    instance = harness.HostHarness(configuration)
    instance.evidence = lambda *a: pytest.fail('remote evidence before validation')
    with pytest.raises(harness.QualificationError, match='qualification_family_state_invalid'):
        instance.packet_phase('proof', [], family=family, blocked=blocked, require_recovery=recovery)


@pytest.mark.parametrize('artifact', ['regular', 'fifo', 'directory', 'symlink', 'oversize'])
def test_remote_receipt_reader_rejects_unsafe_artifacts_immediately(configuration, tmp_path, artifact):
    import os
    from types import SimpleNamespace
    root = tmp_path / 'owned-run'
    root.mkdir(mode=0o700)
    path = root / 'receipts.json'
    if artifact == 'regular':
        path.write_text('{"synthetic": true}'); path.chmod(0o600)
    elif artifact == 'fifo':
        os.mkfifo(path, 0o600)
    elif artifact == 'directory':
        path.mkdir(mode=0o700)
    elif artifact == 'symlink':
        private = tmp_path / 'unrelated'
        private.write_text('synthetic-private'); path.symlink_to(private)
    else:
        with path.open('wb') as stream: stream.truncate(32*1024*1024+1)
        path.chmod(0o600)
    # Model the remote root identity while exercising real descriptor semantics.
    def facts(value):
        return SimpleNamespace(st_uid=0, st_mode=value.st_mode, st_size=value.st_size)
    class RemotePath:
        def __init__(self, value): self.path = Path(value)
        def lstat(self): return facts(self.path.lstat())
        def __truediv__(self, name): return self.path / name
    def bounded_open(value, flags):
        assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
        return os.open(value, flags)
    proxy = SimpleNamespace(open=bounded_open, fstat=lambda fd: facts(os.fstat(fd)),
                            fdopen=os.fdopen, close=os.close, O_RDONLY=os.O_RDONLY,
                            O_NOFOLLOW=os.O_NOFOLLOW, O_NONBLOCK=os.O_NONBLOCK)
    instance = harness.HostHarness(configuration)
    def execute(source, **kwargs):
        assert kwargs['data']['filename'] == 'receipts.json'
        output = []
        # Inject only filesystem location/UID, as a remote host test substitute.
        source = source.replace('from pathlib import Path', '')
        exec(compile(source, '<remote-receipt>', 'exec'), {'Path': RemotePath, 'os': proxy,  # noqa: S102 -- test the trusted emitted reader
             'payload': {'root': str(root), 'filename': 'receipts.json'},
             'print': lambda value: output.append(value)})
        return output[0]
    instance.peer.run = execute
    handle = {'kind': 'capture', 'root': '/run/exitlane-d6-' + 'a'*32}
    if artifact == 'regular':
        assert instance.evidence(handle) == {'synthetic': True}
    elif artifact == 'symlink':
        with pytest.raises(OSError): instance.evidence(handle)
    else:
        with pytest.raises(SystemExit, match='qualification_receipt_unsafe'): instance.evidence(handle)
