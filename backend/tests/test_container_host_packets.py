"""D6 packet negatives prevent missing evidence from becoming a no-leak claim."""

import importlib.util
import socket
import struct
import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "container_host_packets",
    Path(__file__).parents[2] / "scripts/qualification/container_host_packets.py",
)
packets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = packets
SPEC.loader.exec_module(packets)


def ipv4(payload, *, protocol=17, source="10.77.0.2", destination="1.1.1.1", fragment=0):
    header = bytearray(20)
    header[0], header[8], header[9] = 0x45, 64, protocol
    struct.pack_into("!HH", header, 2, 20 + len(payload), 1)
    struct.pack_into("!H", header, 6, fragment)
    header[12:16], header[16:20] = socket.inet_aton(source), socket.inet_aton(destination)
    return bytes(header) + payload


def ipv6(payload, *, protocol=17):
    return (
        struct.pack("!IHBB", 6 << 28, len(payload), protocol, 64)
        + socket.inet_pton(socket.AF_INET6, "fd55::2")
        + socket.inet_pton(socket.AF_INET6, "fd66::1")
        + payload
    )


def udp(payload, *, source=4444, destination=7777):
    return struct.pack("!HHHH", source, destination, 8 + len(payload), 0) + payload


def tcp(payload, *, source=4444, destination=7778):
    return struct.pack("!HHIIBBHHH", source, destination, 0, 0, 5 << 4, 0x18, 1024, 0, 0) + payload


def dns(name="eld6-provider-loss-12.example.test"):
    question = b"".join(bytes((len(label),)) + label.encode() for label in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 12, 0x100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)


def frame(packet, linktype):
    protocol = 0x86DD if packet[0] >> 4 == 6 else 0x0800
    if linktype == 1:
        return b"\x45" + b"\0" * 11 + struct.pack("!H", protocol) + packet
    if linktype == 113:
        return struct.pack("!HHH8sH", 0, 1, 6, b"\0" * 8, protocol) + packet
    if linktype == 276:
        return struct.pack("!HHIHBB8s", protocol, 0, 2, 1, 0, 6, b"\0" * 8) + packet
    return packet


@pytest.mark.parametrize("linktype", [1, 113, 276, 101, 12])
@pytest.mark.parametrize("version", [4, 6])
@pytest.mark.parametrize("transport", ["udp", "tcp", "icmp"])
def test_complete_marker_across_capture_formats(linktype, version, transport):
    marker = b"exitlane-d6-protected-provider-loss:12"
    if transport == "icmp":
        payload, protocol = (
            struct.pack("!BBHHH", 8 if version == 4 else 128, 0, 0, 1, 12) + marker,
            1 if version == 4 else 58,
        )
    else:
        payload, protocol = (udp(marker), 17) if transport == "udp" else (tcp(marker), 6)
    packet = ipv4(payload, protocol=protocol) if version == 4 else ipv6(payload, protocol=protocol)
    result = packets.parse_packet(frame(packet, linktype), linktype=linktype)
    assert result.kind == "protected"
    assert result.phase == "provider-loss" and result.sequence == 12


def test_nat_changes_addresses_and_ports_but_never_marker_identity():
    marker = b"exitlane-d6-protected-blocked:123"
    before = packets.parse_packet(ipv4(udp(marker, source=9876)), linktype=101)
    after = packets.parse_packet(ipv4(udp(marker, source=54321), source="192.0.0.2"), linktype=101)
    assert before.source != after.source and before.source_port != after.source_port
    assert before.identity == after.identity == ("protected", "udp", "blocked", 123)


def test_wireguard_ciphertext_is_never_scanned_for_markers():
    result = packets.parse_packet(
        ipv4(udp(b"exitlane-d6-protected-blocked:1", destination=51820)), linktype=101
    )
    assert result.kind == "wireguard" and result.identity is None


@pytest.mark.parametrize("fragment", [1, 0x2000, 0x8000])
def test_ipv4_fragments_and_reserved_flags_are_evidence_invalid(fragment):
    result = packets.parse_packet(
        ipv4(udp(b"exitlane-d6-protected-a:1"), fragment=fragment), linktype=101
    )
    assert result.kind == "invalid" and result.error == "ipv4_fragment_unsupported"


@pytest.mark.parametrize("extension", [0, 43, 44, 50, 51, 60, 135, 253, 254])
def test_ipv6_extensions_are_explicit_invalid_not_silent_zero(extension):
    assert (
        packets.parse_packet(
            ipv6(udp(b"exitlane-d6-protected-a:1"), protocol=extension), linktype=101
        ).kind
        == "invalid"
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"exitlane-d6-protected-:1",
        b"exitlane-d6-protected-Bad:1",
        b"exitlane-d6-protected-a:01",
        b"exitlane-d6-protected-a:0",
        b"exitlane-d6-protected-a:2147483648",
        b"exitlane-d6-protected-a:1 trailing",
        b"exitlane-d6-protected-a:1\n",
        b"exitlane-d6-protected-a/../b:1",
        b"exitlane-d6-protected-a:",
        b"exitlane-d6-protected-",
    ],
)
def test_hostile_or_partial_markers_invalidate_evidence(payload):
    result = packets.parse_packet(ipv4(udp(payload)), linktype=101)
    assert result.kind == "invalid"
    assert payload.decode() not in result.error


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_synthetic_dns_question_correlation(protocol):
    message = dns()
    payload = (
        udp(message, destination=53)
        if protocol == "udp"
        else tcp(struct.pack("!H", len(message)) + message, destination=53)
    )
    result = packets.parse_packet(
        ipv4(payload, protocol=17 if protocol == "udp" else 6), linktype=101
    )
    assert result.identity == ("dns", protocol, "provider-loss", 12)


def test_unrelated_dns_is_not_counted():
    assert (
        packets.parse_packet(
            ipv4(udp(dns("ordinary.example.test"), destination=53)), linktype=101
        ).kind
        == "other"
    )


@pytest.mark.parametrize(
    "name",
    [
        "eld6-a-0.example.test",
        "eld6-a-01.example.test",
        "eld6-A-1.example.test",
        "eld6-a-1.example.com",
        "eld6-a-2147483648.example.test",
    ],
)
def test_synthetic_dns_bad_grammar_invalidates_receipt(name):
    assert (
        packets.parse_packet(ipv4(udp(dns(name), destination=53)), linktype=101).kind == "invalid"
    )


def test_tcp_dns_split_or_coalesced_records_invalidate_evidence():
    message = dns()
    for payload in (
        b"\0",
        struct.pack("!H", len(message)) + message[:-1],
        struct.pack("!H", len(message)) + message * 2,
    ):
        assert (
            packets.parse_packet(ipv4(tcp(payload, destination=53), protocol=6), linktype=101).kind
            == "invalid"
        )


@pytest.mark.parametrize("length", [0, 1, 13, 19, 27, 29])
def test_truncated_frames_are_invalid(length):
    raw = ipv4(udp(b"exitlane-d6-protected-a:1"))[:length]
    assert packets.parse_packet(raw, linktype=101).kind == "invalid"


def test_tcp_options_and_vlan_tags_preserve_decode():
    marker = b"exitlane-d6-protected-a:1"
    body = tcp(marker)
    body = body[:12] + bytes((6 << 4,)) + body[13:20] + b"\0" * 4 + body[20:]
    raw = ipv4(body, protocol=6)
    tagged = b"\0" * 12 + struct.pack("!HHHHH", 0x88A8, 10, 0x8100, 20, 0x0800) + raw
    assert packets.parse_packet(tagged).identity == ("protected", "tcp", "a", 1)


def sample(protocol="udp", sequence=1, *, phase="blocked", kind="protected"):
    return {"kind": kind, "protocol": protocol, "phase": phase, "sequence": sequence}


def receipts():
    start, end = 10_000_000_000, 10_600_000_000
    sender = {"phase": "blocked", "start_ns": start, "end_ns": end, "errors": [], "attempts": []}
    streams = [
        ("protected", "udp"),
        ("protected", "tcp"),
        ("protected", "icmp"),
        ("dns", "udp"),
        ("dns", "tcp"),
    ]
    for kind, protocol in streams:
        sender["attempts"].extend(
            {**sample(protocol, sequence, kind=kind), "sent_ns": start + sequence * 100_000_000}
            for sequence in range(1, 6)
        )
    capture = {
        "ready": True,
        "start_ns": start - 100_000_000,
        "end_ns": end + 100_000_000,
        "last_poll_ns": end,
        "polls": 10,
        "ifindex": 7,
        "drops": 0,
        "errors": [],
        "gaps": [],
        "invalid_packets": 0,
        "max_poll_gap_ns": 100_000_000,
        "samples": [],
        "calibration": [
            {
                **sample(protocol, phase="calibration", kind=kind),
                "observed_ns": start - 50_000_000,
                "ifindex": 7,
            }
            for kind, protocol in streams
        ],
    }
    captures = {
        point: deepcopy(capture) for point in ("client", "eth0", "bridge", "uplink", "provider")
    }
    captures["client"]["samples"] = [
        {
            **{key: value for key, value in attempt.items() if key != "sent_ns"},
            "observed_ns": attempt["sent_ns"] + 1,
            "ifindex": 7,
        }
        for attempt in sender["attempts"]
    ]
    return captures, sender


def validate(captures, sender, **kwargs):
    return packets.validate_receipts(
        captures,
        sender,
        phase="blocked",
        forbidden_points=("eth0", "bridge", "uplink"),
        required_points=("client", "eth0", "bridge", "uplink", "provider"),
        **kwargs,
    )


def test_complete_calibrated_zero_plaintext_receipt_passes():
    captures, sender = receipts()
    assert validate(captures, sender)["sent"] == 25


@pytest.mark.parametrize("point", ["eth0", "bridge", "uplink"])
def test_any_nat_independent_protected_sequence_is_a_leak(point):
    captures, sender = receipts()
    captures[point]["samples"] = [{**sample(), "observed_ns": sender["start_ns"] + 1, "ifindex": 7}]
    with pytest.raises(packets.EvidenceInvalid, match="protected_plaintext_observed"):
        validate(captures, sender)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ready", False),
        ("drops", 1),
        ("drops", True),
        ("errors", ["worker_dead"]),
        ("gaps", [[1, 2]]),
        ("polls", 0),
        ("ifindex", 0),
        ("invalid_packets", 1),
        ("max_poll_gap_ns", 1_000_000_001),
        ("calibration", []),
        ("last_poll_ns", 1),
        ("start_ns", 10_000_000_001),
        ("end_ns", 10_000_000_001),
    ],
)
def test_capture_gaps_drops_no_readiness_or_calibration_fail_closed(field, value):
    captures, sender = receipts()
    captures["uplink"][field] = value
    with pytest.raises(packets.EvidenceInvalid):
        validate(captures, sender)


def test_missing_required_capture_never_proves_zero():
    captures, sender = receipts()
    del captures["uplink"]
    with pytest.raises(packets.EvidenceInvalid, match="capture_topology_mismatch"):
        validate(captures, sender)


def test_incomplete_protocol_calibration_fails():
    captures, sender = receipts()
    captures["uplink"]["calibration"] = [deepcopy(captures["uplink"]["calibration"][0])]
    with pytest.raises(packets.EvidenceInvalid, match="calibration_incomplete"):
        validate(captures, sender)


@pytest.mark.parametrize("fault", ["absent", "gap", "duplicate", "time", "error"])
def test_sender_faults_cannot_be_interpreted_as_no_leak(fault):
    captures, sender = receipts()
    if fault == "absent":
        sender["attempts"] = []
    elif fault == "gap":
        sender["attempts"].pop(2)
    elif fault == "duplicate":
        sender["attempts"].append(deepcopy(sender["attempts"][0]))
    elif fault == "time":
        sender["end_ns"] += 3_000_000_000
    else:
        sender["errors"] = ["sender_crashed"]
    with pytest.raises(packets.EvidenceInvalid):
        validate(captures, sender)


def test_provider_delivery_requires_every_sent_identity():
    captures, sender = receipts()
    with pytest.raises(packets.EvidenceInvalid, match="delivery_not_proven"):
        validate(captures, sender, delivery_points=("provider",))
    captures["provider"]["samples"] = deepcopy(captures["client"]["samples"])
    assert validate(captures, sender, delivery_points=("provider",))["accepted"] is True


def test_unknown_sequence_or_phase_is_invalid():
    captures, sender = receipts()
    for bad in [sample(sequence=100), sample(phase="another")]:
        captures["client"]["samples"] = [bad]
        with pytest.raises(packets.EvidenceInvalid):
            validate(captures, sender)


def test_packet_dict_public_projection_contains_no_payload():
    packet = packets.parse_packet(ipv4(udp(b"exitlane-d6-protected-a:1")), linktype=101)
    assert "payload" not in asdict(packet)


def test_no_actual_client_transmission_cannot_prove_no_leak():
    captures, sender = receipts()
    captures["client"]["samples"] = []
    with pytest.raises(packets.EvidenceInvalid, match="sender_transmission_not_proven"):
        validate(captures, sender)


@pytest.mark.parametrize("field,value", [("ifindex", 8), ("observed_ns", 1)])
@pytest.mark.parametrize("category", ["calibration", "samples"])
def test_stale_generation_and_packet_window_never_satisfy_receipt(field, value, category):
    captures, sender = receipts()
    captures["client"][category][0][field] = value
    with pytest.raises(packets.EvidenceInvalid):
        validate(captures, sender)


def test_known_wireguard_destination_opaque_even_with_marker_source_port():
    raw = ipv4(udp(b"exitlane-d6-protected-a:1", source=7777, destination=51820))
    assert packets.parse_packet(raw, linktype=101).kind == "wireguard"


def observer(tmp_path):
    return packets.HostCapture(("eth0",), {"10.77.0.2", "1.1.1.1"}, tmp_path / "owned")


@pytest.mark.parametrize("flags", [0x02, 0x04, 0x14, 0x10])
@pytest.mark.parametrize("port", [53, 7778])
def test_actual_collector_pcap_preserves_empty_output_tcp(tmp_path, monkeypatch, flags, port):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "scripts/qualification"))
    from container_host_output import scan_pcap

    capture = observer(tmp_path)
    segment = bytearray(tcp(b"", destination=port))
    segment[13] = flags
    # NAT/source rewriting cannot hide the explicitly selected destination.
    raw = frame(ipv4(bytes(segment), protocol=6, source="192.0.2.5"), 276)
    assert packets.parse_packet(raw, linktype=276).kind == "other"
    stamp = (capture.start_ns // 1000 + 2) * 1000
    capture.consume("eth0", raw, stamp)
    for output in capture.files.values():
        output.close()
    proof = scan_pcap((capture.root / "eth0.pcap").read_bytes(), stamp - 1000, stamp + 1000)
    assert len(proof["tuples"]) == 1
    assert proof["tuples"][0]["protocol"] == "tcp"
    assert proof["tuples"][0]["destination_port"] == port
    assert capture.facts["eth0"]["samples"] == capture.facts["eth0"]["calibration"] == []


@pytest.mark.parametrize("icmp_type", [3, 11, 12])
@pytest.mark.parametrize("quoted_protocol", [6, 17])
def test_actual_collector_pcap_preserves_icmp_output_quotes(
    tmp_path, monkeypatch, icmp_type, quoted_protocol
):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "scripts/qualification"))
    from container_host_output import scan_pcap

    capture = observer(tmp_path)
    transport = tcp(b"") if quoted_protocol == 6 else udp(b"")
    quote = ipv4(transport, protocol=quoted_protocol, source="192.0.2.5")[:28]
    raw = frame(
        ipv4(
            bytes((icmp_type, 0)) + b"\0" * 6 + quote,
            protocol=1,
            source="192.0.2.1",
            destination="10.77.0.2",
        ),
        276,
    )
    assert packets.parse_packet(raw, linktype=276).kind == "other"
    stamp = (capture.start_ns // 1000 + 2) * 1000
    capture.consume("eth0", raw, stamp)
    for output in capture.files.values():
        output.close()
    proof = scan_pcap((capture.root / "eth0.pcap").read_bytes(), stamp - 1000, stamp + 1000)
    assert len(proof["tuples"]) == 1 and proof["tuples"][0]["quoted"] is True
    assert proof["tuples"][0]["destination"] == "1.1.1.1"
    assert capture.facts["eth0"]["samples"] == capture.facts["eth0"]["calibration"] == []


@pytest.mark.parametrize(
    "raw",
    [
        frame(ipv4(tcp(b"", destination=22), protocol=6), 276),
        frame(
            ipv4(
                tcp(b"", destination=7778), protocol=6, source="192.0.2.5", destination="192.0.2.6"
            ),
            276,
        ),
        frame(ipv4(tcp(b"arbitrary-unmarked-content"), protocol=6), 276),
        frame(
            ipv4(
                tcp(
                    struct.pack("!H", len(dns("ordinary.example.test")))
                    + dns("ordinary.example.test"),
                    destination=53,
                ),
                protocol=6,
            ),
            276,
        ),
    ],
)
def test_output_control_retention_does_not_expand_unrelated_payload_capture(tmp_path, raw):
    capture = observer(tmp_path)
    capture.consume("eth0", raw, capture.start_ns + 1)
    for output in capture.files.values():
        output.close()
    assert (capture.root / "eth0.pcap").stat().st_size == 24


@pytest.mark.parametrize("tags", [1, 2])
def test_output_control_retention_preserves_cooked_vlan_packet(tmp_path, tags):
    capture = observer(tmp_path)
    raw = frame(ipv4(tcp(b""), protocol=6), 276)
    tagged = b"\x81\x00" + raw[2:20]
    for index in range(tags):
        tagged += struct.pack("!HH", 135, 0x0800 if index == tags - 1 else 0x8100)
    tagged += raw[20:]
    capture.consume("eth0", tagged, capture.start_ns + 1)
    for output in capture.files.values():
        output.close()
    assert (capture.root / "eth0.pcap").read_bytes()[40:] == tagged


@pytest.mark.parametrize("body", [b"\x03", b"\x0b\0\0", b"\x0c" + b"\0" * 6])
def test_truncated_unmarked_icmp_control_is_invalid_not_silent_zero(tmp_path, body):
    capture = observer(tmp_path)
    capture.consume("eth0", frame(ipv4(body, protocol=1), 276), capture.start_ns + 1)
    assert capture.facts["eth0"]["invalid_packets"] == 1
    for output in capture.files.values():
        output.close()


@pytest.mark.parametrize(
    "quote", [b"\x45" + b"\0" * 10, ipv4(tcp(b""), protocol=6, fragment=1)[:28]]
)
def test_actual_collected_malformed_icmp_quote_cannot_be_zero(tmp_path, quote):
    capture = observer(tmp_path)
    raw = frame(ipv4(b"\x03\0" + b"\0" * 6 + quote, protocol=1), 276)
    stamp = (capture.start_ns // 1000 + 2) * 1000
    capture.consume("eth0", raw, stamp)
    for output in capture.files.values():
        output.close()
    assert capture.facts["eth0"]["invalid_packets"] == 1
    assert (capture.root / "eth0.pcap").stat().st_size == 24


@pytest.mark.parametrize("port", [22, 8787, 9443])
@pytest.mark.parametrize("protocol", [6, 17])
def test_icmp_retention_never_records_quoted_ssh_or_api_payload(tmp_path, port, protocol):
    capture = observer(tmp_path)
    transport = (
        tcp(b"synthetic-private-sentinel", destination=port)
        if protocol == 6
        else udp(b"synthetic-private-sentinel", destination=port)
    )
    quote = ipv4(transport, protocol=protocol)
    raw = frame(ipv4(b"\x03\0" + b"\0" * 6 + quote, protocol=1), 276)
    capture.consume("eth0", raw, capture.start_ns + 1)
    for output in capture.files.values():
        output.close()
    assert (capture.root / "eth0.pcap").stat().st_size == 24
    assert capture.facts["eth0"]["invalid_packets"] == 0


def test_icmp_dedicated_port_quote_outside_selected_addresses_is_not_recorded(tmp_path):
    capture = observer(tmp_path)
    quote = ipv4(tcp(b""), protocol=6, source="192.0.2.5", destination="192.0.2.6")[:28]
    raw = frame(ipv4(b"\x03\0" + b"\0" * 6 + quote, protocol=1), 276)
    capture.consume("eth0", raw, capture.start_ns + 1)
    for output in capture.files.values():
        output.close()
    assert (capture.root / "eth0.pcap").stat().st_size == 24


def test_observer_filters_unrelated_dns_uncertainty_but_rejects_synthetic(tmp_path):
    capture = observer(tmp_path)
    capture.facts["eth0"]["ifindex"] = 7
    capture.phase = "a"
    unrelated = frame(ipv4(udp(b"ordinary-malformed-dns", destination=53)), 276)
    capture.consume("eth0", unrelated, capture.start_ns + 1)
    assert capture.facts["eth0"]["invalid_packets"] == 0
    synthetic = frame(ipv4(udp(b"eld6-malformed", destination=53)), 276)
    capture.consume("eth0", synthetic, capture.start_ns + 2)
    assert capture.facts["eth0"]["invalid_packets"] == 1
    for output in capture.files.values():
        output.close()


def test_observer_never_masks_relevant_fragment_uncertainty(tmp_path):
    capture = observer(tmp_path)
    raw = frame(ipv4(udp(b"unknown-fragment", destination=4000), fragment=1), 276)
    capture.consume("eth0", raw, capture.start_ns + 1)
    assert capture.facts["eth0"]["invalid_packets"] == 1
    for output in capture.files.values():
        output.close()


@pytest.mark.parametrize(
    "phase,error",
    [("previous", "unexpected_marker_phase"), ("calibration", "late_calibration_packet")],
)
def test_delayed_markers_cannot_be_discarded_as_zero_fallback(tmp_path, phase, error):
    capture = observer(tmp_path)
    capture.phase = "blocked"
    capture.facts["eth0"]["ifindex"] = 7
    raw = frame(ipv4(udp(f"exitlane-d6-protected-{phase}:1".encode())), 276)
    capture.consume("eth0", raw, capture.start_ns + 1)
    assert error in capture.facts["eth0"]["errors"]
    assert (capture.root / "eth0.pcap").stat().st_size > 24
    for output in capture.files.values():
        output.close()


def test_observer_records_actual_marker_time_generation_and_private_files(tmp_path):
    import json

    capture = observer(tmp_path)
    capture.phase = "blocked"
    facts = capture.facts["eth0"]
    facts["ifindex"] = 7
    stamp = capture.start_ns + 1
    raw = frame(ipv4(udp(b"exitlane-d6-protected-blocked:1")), 276)
    capture.consume("eth0", raw, stamp)
    assert facts["samples"][0]["observed_ns"] == stamp
    assert facts["samples"][0]["ifindex"] == 7
    capture.snapshot(stamp + 1)
    result = json.loads(capture.receipt.read_text())
    assert result["captures"]["eth0"]["samples"][0]["sequence"] == 1
    assert capture.root.stat().st_mode & 0o777 == 0o700
    assert capture.receipt.stat().st_mode & 0o777 == 0o600
    assert (capture.root / "eth0.pcap").stat().st_mode & 0o777 == 0o600
    for output in capture.files.values():
        output.close()


def test_observer_failure_invalidates_every_ready_point(tmp_path, monkeypatch):
    import json

    capture = observer(tmp_path)
    capture.facts["eth0"]["ready"] = True
    monkeypatch.setattr(capture, "refresh", lambda *_: (_ for _ in ()).throw(OSError("synthetic")))
    assert capture.run() == 1
    result = json.loads(capture.receipt.read_text())
    assert result["captures"]["eth0"]["ready"] is False
    assert "observer_failed" in result["captures"]["eth0"]["errors"]


def test_observer_control_requires_private_regular_file(tmp_path):
    import json

    capture = observer(tmp_path)
    capture.control.write_text(
        json.dumps({"phase": "blocked", "calibration_phase": "calibration", "stop": False})
    )
    capture.control.chmod(0o644)
    with pytest.raises(packets.EvidenceInvalid, match="control_unsafe"):
        capture.phase_control()
    capture.control.chmod(0o600)
    capture.phase_control()
    assert capture.phase == "blocked"
    for output in capture.files.values():
        output.close()


def test_capture_size_limit_is_hard_error_not_silent_truncation(tmp_path):
    capture = observer(tmp_path)
    capture.phase = "blocked"
    capture.total_bytes = 32 * 1024 * 1024
    raw = frame(ipv4(udp(b"exitlane-d6-protected-blocked:1")), 276)
    with pytest.raises(packets.EvidenceInvalid, match="size_limit"):
        capture.consume("eth0", raw, capture.start_ns + 1)
    for output in capture.files.values():
        output.close()


def test_phase_window_reset_preserves_only_generation_bound_calibration(tmp_path):
    import json

    capture = observer(tmp_path)
    facts = capture.facts["eth0"]
    facts.update(
        gaps=[{"at_ns": 1}],
        max_poll_gap_ns=2_000_000_000,
        invalid_packets=1,
        drops=3,
        polls=10,
        samples=[sample()],
        calibration=[sample(phase="calibration")],
    )
    capture.control.write_text(
        json.dumps({"phase": "blocked", "calibration_phase": "calibration", "stop": False})
    )
    capture.control.chmod(0o600)
    capture.phase_control()
    assert facts["gaps"] == [] and facts["drops"] == 0 and facts["invalid_packets"] == 0
    assert facts["max_poll_gap_ns"] == 0 and facts["polls"] == 0 and facts["samples"] == []
    assert facts["calibration"] == [sample(phase="calibration")]
    for output in capture.files.values():
        output.close()


def test_interface_recreation_records_gap_and_requires_new_calibration(tmp_path, monkeypatch):
    capture = observer(tmp_path)

    class PacketSocket:
        def __init__(self):
            self.closed = False

        def setsockopt(self, *_):
            pass

        def bind(self, *_):
            pass

        def setblocking(self, *_):
            pass

        def getsockopt(self, *_):
            return struct.pack("II", 0, 0)

        def close(self):
            self.closed = True

    old = PacketSocket()
    capture.sockets["eth0"] = (7, old)
    facts = capture.facts["eth0"]
    facts.update(ifindex=7, ready=True, calibration=[sample(phase="calibration")])
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 8)
    monkeypatch.setattr(socket, "socket", lambda *_: PacketSocket())
    monkeypatch.setattr(packets, "attach_kernel_filter", lambda *_: None)
    capture.refresh(capture.start_ns + 1)
    assert old.closed
    assert facts["ifindex"] == 8 and facts["calibration"] == []
    assert facts["gaps"][0]["old_ifindex"] == 7
    assert facts["gaps"][0]["new_ifindex"] == 8
    capture.sockets["eth0"][1].close()
    for output in capture.files.values():
        output.close()


@pytest.mark.parametrize("version,protocol", [(4, 58), (6, 1)])
def test_inconsistent_icmp_address_family_is_evidence_invalid(version, protocol):
    payload = struct.pack("!BBHHH", 128, 0, 0, 1, 1) + b"exitlane-d6-protected-a:1"
    raw = ipv4(payload, protocol=protocol) if version == 4 else ipv6(payload, protocol=protocol)
    result = packets.parse_packet(raw, linktype=101)
    assert result.kind == "invalid" and result.error == "icmp_family_invalid"


def test_observer_counts_only_wireguard_port_metadata_without_cipher_scan(tmp_path):
    capture = observer(tmp_path)
    stamp = capture.start_ns + 1
    raw = frame(ipv4(udp(b"exitlane-d6-protected-a:1", destination=51820)), 276)
    capture.consume("eth0", raw, stamp)
    facts = capture.facts["eth0"]
    assert facts["wireguard_packets"] == 1
    assert facts["wireguard_first_ns"] == stamp and facts["wireguard_last_ns"] == stamp
    assert facts["samples"] == []
    for output in capture.files.values():
        output.close()


@pytest.mark.parametrize(
    "stream",
    [
        ("protected", "udp"),
        ("protected", "tcp"),
        ("protected", "icmp"),
        ("dns", "udp"),
        ("dns", "tcp"),
    ],
)
@pytest.mark.parametrize("remove_calibration", [False, True])
def test_missing_entire_stream_rejected_independently_of_calibration(stream, remove_calibration):
    captures, sender = receipts()
    sender["attempts"] = [
        item for item in sender["attempts"] if (item["kind"], item["protocol"]) != stream
    ]
    for facts in captures.values():
        facts["samples"] = [
            item for item in facts["samples"] if (item["kind"], item["protocol"]) != stream
        ]
        if remove_calibration:
            facts["calibration"] = [
                item for item in facts["calibration"] if (item["kind"], item["protocol"]) != stream
            ]
    with pytest.raises(packets.EvidenceInvalid, match="sender_stream_inventory_mismatch"):
        validate(captures, sender)


def test_extra_calibrated_sender_stream_does_not_expand_ipv4_contract():
    captures, sender = receipts()
    for sequence in range(1, 6):
        attempt = {
            **sample("icmp6", sequence),
            "sent_ns": sender["start_ns"] + sequence * 100_000_000,
        }
        sender["attempts"].append(attempt)
        captures["client"]["samples"].append(
            {**sample("icmp6", sequence), "observed_ns": attempt["sent_ns"] + 1, "ifindex": 7}
        )
    for facts in captures.values():
        facts["calibration"].append(
            {
                **sample("icmp6", phase="calibration"),
                "observed_ns": sender["start_ns"] - 1,
                "ifindex": 7,
            }
        )
    with pytest.raises(packets.EvidenceInvalid, match="sender_stream_inventory_mismatch"):
        validate(captures, sender)


@pytest.mark.parametrize("topology", [None, (), [], "client", ("client", "client"), ("../client",)])
def test_required_topology_cannot_be_empty_inferred_or_hostile(topology):
    captures, sender = receipts()
    with pytest.raises(packets.EvidenceInvalid, match="capture_topology_invalid"):
        packets.validate_receipts(
            captures, sender, phase="blocked", forbidden_points=("eth0",), required_points=topology
        )


def test_required_topology_is_mandatory_api_input():
    captures, sender = receipts()
    with pytest.raises(TypeError, match="required_points"):
        packets.validate_receipts(captures, sender, phase="blocked", forbidden_points=("eth0",))


def test_unexpected_capture_point_is_not_silently_ignored():
    captures, sender = receipts()
    captures["extra"] = deepcopy(captures["eth0"])
    with pytest.raises(packets.EvidenceInvalid, match="capture_topology_mismatch"):
        validate(captures, sender)


def test_reduced_capture_inventory_cannot_satisfy_full_coordinator_topology():
    captures, sender = receipts()
    captures = {point: value for point, value in captures.items() if point in {"client", "uplink"}}
    with pytest.raises(packets.EvidenceInvalid, match="capture_topology_mismatch"):
        validate(captures, sender)


def execute_filter(program, packet):
    """Independent classic-BPF interpreter; out-of-bounds loads reject as Linux."""
    accumulator, index, cursor = 0, 0, 0
    while cursor < len(program):
        op, true, false, value = program[cursor]
        cursor += 1
        if op in {0x20, 0x28, 0x30, 0x48, 0xB1}:
            size = {0x20: 4, 0x28: 2, 0x30: 1, 0x48: 2, 0xB1: 1}[op]
            offset = value + (index if op == 0x48 else 0)
            if offset + size > len(packet):
                return 0
            loaded = int.from_bytes(packet[offset : offset + size], "big")
            if op == 0xB1:
                index = (loaded & 15) * 4
            else:
                accumulator = loaded
        elif op == 0x54:
            accumulator &= value
        elif op == 0x04:
            accumulator = (accumulator + value) & 0xFFFFFFFF
        elif op == 0x87:
            accumulator = index
        elif op == 0x07:
            index = accumulator
        elif op == 0x80:
            accumulator = len(packet)
        elif op == 0x05:
            cursor += value
        elif op in {0x15, 0x35, 0x45, 0x3D}:
            matched = {
                0x15: accumulator == value,
                0x35: accumulator >= value,
                0x45: bool(accumulator & value),
                0x3D: accumulator >= index,
            }[op]
            cursor += true if matched else false
        elif op == 0x06:
            return value
        else:
            raise AssertionError(f"unhandled BPF instruction {op}")
    raise AssertionError("BPF did not terminate")


def kernel_frame(raw, hardware, tags):
    if hardware == 65534:
        return raw
    ethernet = frame(raw, 1)
    for tag in tags:
        ethernet = ethernet[:12] + struct.pack("!HH", tag, 135) + ethernet[12:]
    return ethernet


@pytest.mark.parametrize(
    "hardware,tags", [(1, ()), (1, (0x8100,)), (1, (0x88A8, 0x8100)), (65534, ())]
)
@pytest.mark.parametrize("version", [4, 6])
@pytest.mark.parametrize(
    "protocol,port",
    [(6, 53), (17, 53), (6, 7778), (17, 7777), (17, 51820), (17, 51821), (6, 22), (17, 443)],
)
def test_kernel_filter_retains_pressure_and_wireguard_but_discards_ssh(
    hardware, tags, version, protocol, port
):
    program = packets.kernel_filter({"10.77.0.2", "fd55::2"}, hardware)
    payload = (
        tcp(b"synthetic", destination=port)
        if protocol == 6
        else udp(b"synthetic", destination=port)
    )
    raw = ipv4(payload, protocol=protocol) if version == 4 else ipv6(payload, protocol=protocol)
    assert bool(execute_filter(program, kernel_frame(raw, hardware, tags))) == (
        port != 22 and port != 443
    )


@pytest.mark.parametrize("hardware,tags", [(1, ()), (1, (0x8100,)), (65534, ())])
@pytest.mark.parametrize(
    "raw",
    [
        ipv4(b"x", fragment=0x2000),
        ipv4(b"x", fragment=0x8000),
        ipv4(b"x", protocol=1),
        ipv4(b"x", protocol=253),
        ipv6(b"x", protocol=44),
        ipv6(b"x", protocol=58),
        ipv4(b"x", protocol=6),
        ipv6(b"x", protocol=17),
    ],
)
def test_kernel_filter_keeps_fragment_extension_unknown_and_truncation_evidence(
    hardware, tags, raw
):
    program = packets.kernel_filter({"10.77.0.2", "fd55::2"}, hardware)
    assert execute_filter(program, kernel_frame(raw, hardware, tags))


@pytest.mark.parametrize("hardware", [1, 65534])
def test_kernel_filter_requires_selected_address_even_for_required_ports(hardware):
    program = packets.kernel_filter({"192.0.2.1", "fd99::1"}, hardware)
    for raw in (ipv4(udp(b"x")), ipv6(tcp(b"x")), ipv4(b"x", fragment=0x2000)):
        assert not execute_filter(program, kernel_frame(raw, hardware, ()))


def test_kernel_filter_ipv4_options_and_source_port():
    raw = bytearray(ipv4(tcp(b"x", source=7778, destination=22), protocol=6))
    raw[0] = 0x46
    raw[2:4] = struct.pack("!H", len(raw) + 4)
    raw = raw[:20] + b"\0" * 4 + raw[20:]
    assert execute_filter(packets.kernel_filter({"1.1.1.1"}, 65534), raw)


@pytest.mark.parametrize("hardware", [0, 772, 999])
def test_kernel_filter_unknown_hardware_is_fail_closed(hardware):
    with pytest.raises(packets.EvidenceInvalid, match="hardware_unsupported"):
        packets.kernel_filter({"10.77.0.2"}, hardware)


def test_kernel_filter_max_address_inventory_is_bounded():
    addresses = {f"fd55::{number:x}" for number in range(1, 33)}
    program = packets.kernel_filter(addresses, 1)
    assert len(program) <= 4096
    assert execute_filter(program, frame(ipv6(udp(b"x")), 1))


def test_refresh_attaches_before_activation_and_refuses_attach_failure(tmp_path, monkeypatch):
    capture = observer(tmp_path)
    events = []

    class ObserverSocket:
        def setsockopt(self, *_):
            pass

        def bind(self, address):
            events.append(("bind", address))

        def close(self):
            events.append(("close",))

        def setblocking(self, *_):
            pass

    def create(family, kind, protocol):
        assert protocol == 0  # No packets before kernel filter attachment.
        return ObserverSocket()

    monkeypatch.setattr(socket, "socket", create)
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 7)
    monkeypatch.setattr(packets, "attach_kernel_filter", lambda *_: events.append(("attach",)))
    capture.refresh(capture.start_ns)
    assert events == [("attach",), ("bind", ("eth0", 3))]
    capture.sockets.clear()

    def fail(*_):
        raise packets.EvidenceInvalid("capture_filter_unavailable")

    monkeypatch.setattr(packets, "attach_kernel_filter", fail)
    capture.refresh(capture.start_ns)
    assert events[-1] == ("close",)
    assert capture.facts["eth0"]["ready"] is False
    assert "capture_bind_failed" in capture.facts["eth0"]["errors"]
    for output in capture.files.values():
        output.close()


def test_phase_boundary_drains_old_stats_without_hiding_new_drops(tmp_path):
    import json

    capture = observer(tmp_path)
    counts = iter((9, 2))

    class StatisticsSocket:
        def getsockopt(self, *_):
            return struct.pack("II", 0, next(counts))

    sock = StatisticsSocket()
    capture.sockets["eth0"] = (7, sock)
    capture.control.write_text(
        json.dumps({"phase": "blocked", "calibration_phase": "calibration", "stop": False})
    )
    capture.control.chmod(0o600)
    capture.phase_control()
    assert capture.facts["eth0"]["drops"] == 0
    assert capture.facts["eth0"]["lifetime_drops"] == 9
    capture.phase_control()  # Same phase must not consume/reset kernel counters.
    capture.statistics("eth0", sock)
    assert capture.facts["eth0"]["drops"] == 2
    assert capture.facts["eth0"]["lifetime_drops"] == 11
    for output in capture.files.values():
        output.close()


@pytest.mark.parametrize("hardware", [1, 65534])
def test_real_kernel_accepts_bounded_program_without_packet_capture(monkeypatch, hardware):
    """AF_UNIX-only test: validates Linux BPF, opens no network interface."""
    monkeypatch.setattr(packets, "interface_hardware", lambda *_: hardware)
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        packets.attach_kernel_filter(receiver, "synthetic", {"10.77.0.2", "fd55::2"})
        receiver.settimeout(0.05)
        retained = kernel_frame(ipv4(udp(b"synthetic")), hardware, ())
        discarded = kernel_frame(ipv4(tcp(b"ssh", destination=22), protocol=6), hardware, ())
        sender.send(discarded)
        sender.send(retained)
        assert receiver.recv(65575) == retained
        with pytest.raises(TimeoutError):
            receiver.recv(65575)
    finally:
        receiver.close()
        sender.close()


def test_missing_interface_facts_refuse_filter(monkeypatch):
    def missing(*_):
        raise FileNotFoundError

    monkeypatch.setattr(packets, "interface_hardware", missing)
    with pytest.raises(packets.EvidenceInvalid, match="filter_unavailable"):
        packets.attach_kernel_filter(None, "synthetic", {"10.77.0.2"})


def test_phase_boundary_statistics_failure_remains_fatal(tmp_path):
    import json

    capture = observer(tmp_path)

    class StatisticsSocket:
        def getsockopt(self, *_):
            raise OSError("synthetic")

    capture.sockets["eth0"] = (7, StatisticsSocket())
    capture.control.write_text(
        json.dumps({"phase": "blocked", "calibration_phase": "calibration", "stop": False})
    )
    capture.control.chmod(0o600)
    capture.phase_control()
    assert "capture_statistics_unavailable" in capture.facts["eth0"]["errors"]
    assert capture.facts["eth0"]["drops"] == 0
    for output in capture.files.values():
        output.close()


def test_attach_rejection_is_fixed_and_never_binds(tmp_path, monkeypatch):
    monkeypatch.setattr(packets, "interface_hardware", lambda *_: 1)

    class DeniedSocket:
        def setsockopt(self, *_):
            raise OSError("synthetic private diagnostic")

    with pytest.raises(packets.EvidenceInvalid, match="^capture_filter_unavailable$"):
        packets.attach_kernel_filter(DeniedSocket(), "synthetic", {"10.77.0.2"})


def test_hardware_lookup_uses_current_namespace_readonly_ioctl(monkeypatch):
    import fcntl

    calls = []

    class FactsSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            calls.append("closed")

        def fileno(self):
            return 31

    def create(family, kind):
        assert (family, kind) == (socket.AF_INET, socket.SOCK_DGRAM)
        return FactsSocket()

    def ioctl(descriptor, command, request):
        assert descriptor == 31 and command == 0x8927
        assert len(request) == 256 and request[:16] == b"wg-office".ljust(16, b"\0")
        calls.append("ioctl")
        result = bytearray(request)
        struct.pack_into("=H", result, 16, 65534)
        return bytes(result)

    monkeypatch.setattr(socket, "socket", create)
    monkeypatch.setattr(fcntl, "ioctl", ioctl)
    assert packets.interface_hardware("wg-office") == 65534
    assert calls == ["ioctl", "closed"]


@pytest.mark.parametrize("name", ["", "a" * 16, "eth0/../lo", "eth0\0", "éth0", 4])
def test_hardware_lookup_rejects_unsafe_names_before_socket(name, monkeypatch):
    def forbidden(*_):
        raise AssertionError("socket must not be opened")

    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(packets.EvidenceInvalid, match="interface_invalid"):
        packets.interface_hardware(name)


def test_real_loopback_hardware_is_known_but_not_supported_for_capture():
    assert packets.interface_hardware("lo") == 772  # ARPHRD_LOOPBACK
    with pytest.raises(packets.EvidenceInvalid, match="hardware_unsupported"):
        packets.kernel_filter({"127.0.0.1"}, packets.interface_hardware("lo"))


@pytest.mark.parametrize(
    "error,expected",
    [
        (packets.EvidenceInvalid("observer_interface_mismatch"), "observer_interface_mismatch"),
        (packets.EvidenceInvalid("synthetic secret=PRIVATE"), None),
        (packets.EvidenceInvalid("x" * 65), None),
        (OSError("synthetic secret=PRIVATE"), "observer_os_error_0"),
        (OSError(100, "synthetic secret=PRIVATE"), "observer_os_error_100"),
        (ValueError("synthetic secret=PRIVATE"), "observer_unexpected_error"),
    ],
)
def test_observer_reports_only_static_gate_identifiers(tmp_path, monkeypatch, error, expected):
    capture = observer(tmp_path)
    capture.facts["eth0"]["ready"] = True

    def fail(*_):
        raise error

    monkeypatch.setattr(capture, "refresh", fail)
    assert capture.run() == 1
    content = capture.receipt.read_text()
    result = __import__("json").loads(content)
    errors = result["captures"]["eth0"]["errors"]
    assert "observer_failed" in errors
    assert result["captures"]["eth0"]["ready"] is False
    assert "PRIVATE" not in content
    if expected:
        assert set(errors) == {expected, "observer_failed"}
    else:
        assert errors == ["observer_failed"]


def remote_clock_receipts():
    captures, sender = receipts()
    offset = 3_000_000
    remote = captures["provider"]
    remote["samples"] = deepcopy(captures["client"]["samples"])
    # Reproduce the first packet observed 3ms before the sender's start in the
    # remote clock, rather than adding arbitrary tolerance to all captures.
    remote["samples"][0]["observed_ns"] = sender["start_ns"] + 1
    for key in ("start_ns", "end_ns", "last_poll_ns"):
        remote[key] -= offset
    for item in remote["samples"] + remote["calibration"]:
        item["observed_ns"] -= offset
    measurement = {}
    for label, reference in (
        ("before", sender["start_ns"] - 20_000_000),
        ("after", sender["end_ns"] + 20_000_000),
    ):
        measurement[label] = {
            "local_before_ns": reference - offset - 1_000_000,
            "reference_ns": reference,
            "local_after_ns": reference - offset + 1_000_000,
        }
    return captures, sender, {"provider": measurement}


def test_measured_remote_clock_interval_accepts_real_three_ms_boundary():
    captures, sender, clocks = remote_clock_receipts()
    with pytest.raises(packets.EvidenceInvalid, match="sample_window"):
        validate(captures, sender, delivery_points=("provider",))
    result = validate(captures, sender, delivery_points=("provider",), clock_offsets=clocks)
    assert result["clock_alignment"]["provider"]["lower_ns"] == 2_000_000
    assert result["clock_alignment"]["provider"]["upper_ns"] == 4_000_000
    assert result["clock_alignment"]["client"]["mode"] == "same_reference"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_after",
        "extra",
        "bool",
        "wide",
        "offset",
        "drift",
        "late_before",
        "early_after",
        "source",
        "unknown",
    ],
)
def test_remote_clock_measurements_fail_closed(mutation):
    captures, sender, clocks = remote_clock_receipts()
    measurement = clocks["provider"]
    if mutation == "missing_after":
        measurement.pop("after")
    elif mutation == "extra":
        measurement["lower_ns"] = 0
    elif mutation == "bool":
        measurement["before"]["local_before_ns"] = True
    elif mutation == "wide":
        measurement["before"]["local_after_ns"] += 100_000_001
    elif mutation == "offset":
        for part in measurement.values():
            part["local_before_ns"] -= 2_000_000_000
            part["local_after_ns"] -= 2_000_000_000
    elif mutation == "drift":
        measurement["after"]["local_before_ns"] -= 3_000_000
        measurement["after"]["local_after_ns"] -= 3_000_000
    elif mutation == "late_before":
        measurement["before"]["reference_ns"] = sender["start_ns"] + 1
    elif mutation == "early_after":
        measurement["after"]["reference_ns"] = sender["end_ns"] - 1
    elif mutation == "source":
        clocks["client"] = clocks.pop("provider")
    else:
        clocks["unknown"] = clocks.pop("provider")
    with pytest.raises(packets.EvidenceInvalid, match="clock_"):
        validate(captures, sender, clock_offsets=clocks)


@pytest.mark.parametrize(
    "boundary", ["capture_start", "capture_end", "sample_local", "sample_remote"]
)
def test_remote_clock_does_not_hide_missing_capture_or_outside_samples(boundary):
    captures, sender, clocks = remote_clock_receipts()
    remote = captures["provider"]
    if boundary == "capture_start":
        remote["start_ns"] = sender["start_ns"] - 3_000_000
    elif boundary == "capture_end":
        remote["end_ns"] = sender["end_ns"] - 3_000_000
        remote["last_poll_ns"] = remote["end_ns"]
    elif boundary == "sample_local":
        remote["samples"][0]["observed_ns"] = remote["start_ns"] - 1
    else:
        remote["samples"][0]["observed_ns"] = sender["start_ns"] - 5_000_000
    with pytest.raises(packets.EvidenceInvalid, match="capture_"):
        validate(captures, sender, clock_offsets=clocks)


def test_remote_clock_calibration_remains_strictly_local():
    captures, sender, clocks = remote_clock_receipts()
    captures["provider"]["calibration"][0]["observed_ns"] = captures["provider"]["start_ns"] - 1
    with pytest.raises(packets.EvidenceInvalid, match="calibration_generation"):
        validate(captures, sender, clock_offsets=clocks)
