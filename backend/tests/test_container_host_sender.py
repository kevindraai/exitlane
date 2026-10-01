"""Generated pressure must be real, decodable and valid across Docker NAT."""
import importlib.util
import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2] / 'scripts/qualification'


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sender = load('container_host_sender')
packets = load('container_host_packets')


@pytest.mark.parametrize('stream', sender.STREAMS)
def test_every_pressure_stream_has_actual_sequence_and_valid_checksums(stream):
    packet = sender.packet('10.77.0.2', 'provider-loss', 17, *stream)
    evidence = packets.parse_packet(packet, linktype=101)
    assert evidence.identity == (*stream, 'provider-loss', 17)
    assert evidence.source == '10.77.0.2'
    assert sender.checksum(packet[:20]) == 0
    transport = packet[20:]
    if stream[1] == 'icmp':
        assert sender.checksum(transport) == 0
    else:
        pseudo = packet[12:20] + struct.pack('!BBH', 0, packet[9], len(transport))
        assert sender.checksum(pseudo + transport) == 0


def test_dns_marker_survives_realistic_nat_address_port_changes():
    raw = bytearray(sender.packet('10.77.0.2', 'switch-failed', 23, 'dns', 'udp'))
    raw[12:16] = socket.inet_aton('192.168.99.10')
    raw[16:20] = socket.inet_aton('10.65.0.1')
    raw[20:22] = struct.pack('!H', 49123)
    assert packets.parse_packet(bytes(raw), linktype=101).identity == ('dns', 'udp', 'switch-failed', 23)


@pytest.mark.parametrize('phase,sequence', [('bad/name', 1), ('ok', 0), ('ok', True), ('ok', 2**31)])
def test_invalid_sender_identity_cannot_create_false_phase(phase, sequence):
    with pytest.raises(ValueError, match='sender_identity_invalid'):
        sender.packet('10.77.0.2', phase, sequence, 'protected', 'udp')


def test_tcp_attempt_is_syn_with_payload_when_connect_cannot_complete():
    raw = sender.packet('10.77.0.2', 'no-provider', 1, 'protected', 'tcp')
    assert raw[33] == 2
    assert raw[40:] == b'exitlane-d6-protected-no-provider:1'
    assert packets.parse_packet(raw, linktype=101).identity == ('protected', 'tcp', 'no-provider', 1)


def test_fifo_is_rejected_before_a_blocking_read(tmp_path):
    import os
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError):
        sender.private_json(fifo)


@pytest.mark.parametrize('interface', ['eth0', 'wg-client'])
def test_sender_never_uses_host_namespace(interface, monkeypatch):
    from types import SimpleNamespace
    original = Path.stat
    def facts(path, *args, **kwargs):
        if str(path) in {"/proc/self/ns/net", "/proc/1/ns/net"}:
            return SimpleNamespace(st_ino=42)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "stat", facts)
    config = {'source': '10.77.0.2', 'interface': interface,
              'run_dir': '/run/exitlane-d6-' + 'a' * 32,
              'deadline_seconds': 1, 'dns': '1.1.1.1', 'namespace_inode': [4, 42], 'ifindex': 2}
    with pytest.raises(ValueError, match='sender_configuration_invalid|sender_namespace_required'):
        sender.run(config)
