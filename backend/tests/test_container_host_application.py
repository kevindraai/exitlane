"""Round-trip proof must not be inferred from a raw TCP SYN receipt."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / 'scripts/qualification'))
import container_host_application as application


@pytest.mark.parametrize('provider', ['nordvpn', 'unknown'])
def test_unsupported_provider_never_contacts_host(provider):
    with pytest.raises(application.ApplicationEvidenceError, match='application_provider_invalid'):
        application.qualify(None, [], provider=provider, receipts=None)


def test_disconnected_baseline_never_runs_pressure(monkeypatch):
    class Proof:
        def __init__(self, *a, **kw): pass
        def _authorized(self): pass
        def _selected(self, *a): return False
    monkeypatch.setattr(application, 'ProviderQualification', Proof)
    h = SimpleNamespace(packet_phase=lambda *a, **kw: pytest.fail('pressure before connected baseline'))
    with pytest.raises(application.ApplicationEvidenceError, match='application_connected_baseline_required'):
        application.qualify(h, [], provider='mullvad', receipts=None)


def test_roundtrip_program_uses_four_protocols_and_bounded_sockets():
    assert "('udp',7777)" in application.PROGRAM
    assert "('tcp',7778)" in application.PROGRAM
    assert "('dns_udp',53)" in application.PROGRAM
    assert "('dns_tcp',53)" in application.PROGRAM
    assert 'settimeout(3)' in application.PROGRAM
    assert 'type(e).__name__' in application.PROGRAM
    assert 'str(e)' not in application.PROGRAM


def test_dns_tcp_early_eof_is_failure_instead_of_endless_receive(monkeypatch, capsys):
    import json
    import socket

    class TruncatedSocket:
        def __init__(self):
            self.reads = 0
        def settimeout(self, seconds):
            assert seconds == 3
        def connect(self, destination): pass
        def send(self, payload): return len(payload)
        def recv(self, count):
            self.reads += 1
            if self.reads > 2:
                pytest.fail('receiver repeated an EOF read')
            return b'\x00\x10' if self.reads == 1 else b''
        def close(self): pass

    monkeypatch.setattr(socket, 'socket', lambda *args: TruncatedSocket())
    exec(application.PROGRAM, {})  # noqa: S102 -- exercise the fixed socket probe itself
    assert json.loads(capsys.readouterr().out)['dns_tcp'] == 'EOFError'


@pytest.mark.parametrize('observed,accepted', [
    ({'udp': True, 'tcp': True, 'dns_udp': True, 'dns_tcp': True}, True),
    ({'udp': 'TimeoutError', 'tcp': True, 'dns_udp': True, 'dns_tcp': True}, False),
    ({'udp': True, 'tcp': True, 'dns_udp': True, 'dns_tcp': True}, False),
    ({'udp': True, 'tcp': True, 'dns_udp': True, 'dns_tcp': True}, 'wrong-phase'),
    ({'udp': True, 'tcp': True, 'dns_udp': True, 'dns_tcp': True}, 'wrong-state'),
])
def test_live_protocol_failure_or_rejected_packet_proof_cannot_pass(monkeypatch, observed, accepted):
    import json
    identifier = '11111111-1111-4111-8111-111111111111'
    namespace = 'ed6-1111111111-client'
    calls = []
    class Proof:
        def __init__(self, *a, **kw): pass
        def _authorized(self): pass
        def _selected(self, *a): return True
        def _command(self, host, arguments, **kw):
            if 'ownership' in arguments:
                return json.dumps({'run_id': identifier, 'namespace': namespace, 'namespace_inode': [1, 2]})
            assert arguments[:4] == ['ip', 'netns', 'exec', namespace]
            assert "[facts.st_dev,facts.st_ino] != [1, 2]" in kw['data']
            return json.dumps(observed)
    monkeypatch.setattr(application, 'ProviderQualification', Proof)
    def pressure(phase, captures, *, operation):
        operation()
        return {'receipt': {'accepted': accepted is not False,
                            'phase': 'foreign' if accepted == 'wrong-phase' else phase,
                            'expected_state': 'blocked' if accepted == 'wrong-state' else 'provider_or_block_with_fresh_recovery'}}
    h = SimpleNamespace(config={'run_id': identifier}, peer=object(), packet_phase=pressure)
    r = SimpleNamespace(write=lambda name, value: calls.append((name, dict(value))) or name)
    if accepted is True and all(value is True for value in observed.values()):
        assert application.qualify(h, [], provider='mullvad', receipts=r)['result'] == 'PACKET_COMPONENT_PASS'
    else:
        with pytest.raises(application.ApplicationEvidenceError, match='application_component_failed'):
            application.qualify(h, [], provider='mullvad', receipts=r)
        assert calls[-1][1]['result'] == 'FAILED'
        assert all(value.get('result') != 'PACKET_COMPONENT_PASS' for _, value in calls)
