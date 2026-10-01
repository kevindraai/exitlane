"""Separate IPv6 block proof, with checksum and packet-level calibration."""

import importlib.util
import json
import socket
import struct
import sys
from copy import deepcopy
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2] / "scripts/qualification"
sys.path.insert(0, str(ROOT))
try:
    SPEC = importlib.util.spec_from_file_location(
        "container_host_ipv6", ROOT / "container_host_ipv6.py"
    )
    ipv6 = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(ipv6)
finally:
    sys.path.pop(0)


@pytest.mark.parametrize("kind,protocol", ipv6.STREAMS)
def test_checksum_and_decode_for_all_ipv6_streams(kind, protocol):
    raw = ipv6.packet("blocked6", 12, kind, protocol)
    assert raw[0] >> 4 == 6
    assert struct.unpack_from("!H", raw, 4)[0] == len(raw) - 40
    pseudo = raw[8:40] + struct.pack("!I3xB", len(raw) - 40, raw[6])
    assert ipv6.checksum(pseudo + raw[40:]) == 0
    parsed = ipv6.evidence.parse_packet(raw, linktype=101)
    assert parsed.identity == (kind, protocol, "blocked6", 12)
    assert parsed.source == ipv6.SOURCE and parsed.destination == ipv6.DESTINATION


@pytest.mark.parametrize(
    "phase,seq",
    [
        (None, 1),
        ("invalid phase", 1),
        ("a" * 41, 1),
        ("blocked6", 0),
        ("blocked6", True),
        ("blocked6", 2**31),
    ],
)
def test_invalid_identities_fail_closed(phase, seq):
    with pytest.raises(ValueError, match="identity_invalid"):
        ipv6.packet(phase, seq, "protected", "udp")


def test_ipv4_icmp_cannot_replace_icmp6():
    with pytest.raises(ValueError, match="stream_invalid"):
        ipv6.packet("blocked6", 1, "protected", "icmp")


def receipts():
    start, end = 10_000_000_000, 10_200_000_000
    sender = {
        "family": 6,
        "phase": "blocked6",
        "start_ns": start,
        "end_ns": end,
        "errors": [],
        "attempts": [],
    }
    receipt = {
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
        "calibration": [],
        "wireguard_packets": 1,
    }
    for kind, protocol in ipv6.STREAMS:
        base = {
            "kind": kind,
            "protocol": protocol,
            "sequence": 1,
            "source": ipv6.SOURCE,
            "destination": ipv6.DESTINATION,
        }
        sender["attempts"].append({**base, "phase": "blocked6", "sent_ns": start + 100_000_000})
        receipt["calibration"].append(
            {**base, "phase": "calibration6", "observed_ns": start - 50_000_000, "ifindex": 7}
        )
    captures = {
        name: deepcopy(receipt)
        for name in ("client", "office", "uplink", "provider_a", "provider_b")
    }
    captures["client"]["samples"] = [
        {**item, "observed_ns": item["sent_ns"] + 1, "ifindex": 7} for item in sender["attempts"]
    ]
    return captures, sender


def validate(captures, sender):
    return ipv6.validate_ipv6(
        captures,
        sender,
        phase="blocked6",
        required_points=("client", "office", "uplink", "provider_a", "provider_b"),
        sender_points=("client",),
        encapsulation_points=("uplink",),
    )


def test_complete_ipv6_block_receipt_requires_source_and_all_calibrated_planes():
    captures, sender = receipts()
    result = validate(captures, sender)
    assert result["family"] == 6 and result["ipv6_forwarding"] == "blocked"
    assert result["sent"] == 5


@pytest.mark.parametrize(
    "change",
    [
        "stream",
        "source",
        "family",
        "missing_family",
        "source_family",
        "destination_family",
        "missing_address",
        "ipv4_stream",
        "cipher",
        "plane",
        "calibration",
    ],
)
def test_ipv6_evidence_rejects_incomplete_or_wrong_family_receipts(change):
    captures, sender = receipts()
    if change == "stream":
        sender["attempts"].pop()
    elif change == "source":
        captures["client"]["samples"] = []
    elif change == "family":
        sender["family"] = 4
    elif change == "missing_family":
        sender.pop("family")
    elif change == "source_family":
        captures["client"]["samples"][0]["source"] = "10.77.0.2"
    elif change == "destination_family":
        captures["client"]["samples"][0]["destination"] = "1.1.1.1"
    elif change == "missing_address":
        captures["provider_b"]["calibration"][0].pop("source")
    elif change == "ipv4_stream":
        sender["attempts"].append({**sender["attempts"][0], "protocol": "icmp"})
    elif change == "cipher":
        captures["uplink"]["wireguard_packets"] = 0
    elif change == "plane":
        captures.pop("provider_b")
    else:
        captures["office"]["calibration"].pop()
    with pytest.raises(ipv6.evidence.EvidenceInvalid):
        validate(captures, sender)


@pytest.mark.parametrize("point", ["office", "uplink", "provider_a", "provider_b"])
def test_ipv6_plaintext_on_any_nonclient_plane_is_failure(point):
    captures, sender = receipts()
    captures[point]["samples"] = deepcopy(captures["client"]["samples"])
    with pytest.raises(ipv6.evidence.EvidenceInvalid, match="plaintext_observed"):
        validate(captures, sender)


def test_default_ipv4_validation_rejects_ipv6_receipt():
    captures, sender = receipts()
    with pytest.raises(ipv6.evidence.EvidenceInvalid):
        ipv6.evidence.validate_receipts(
            captures,
            sender,
            phase="blocked6",
            required_points=tuple(captures),
            forbidden_points=("uplink",),
            calibration_phase="calibration6",
        )


def test_fixed_ethernet_mac_framing_and_raw_wireguard_calibration():
    raw = ipv6.packet("calibration6", 1, "dns", "udp")
    framed = ipv6._ethernet(raw, 1, "02:00:00:00:00:01", "02:00:00:00:00:02")
    assert framed[:14] == bytes.fromhex("02000000000202000000000186dd")
    assert ipv6.evidence.parse_packet(framed, linktype=1).identity == (
        "dns",
        "udp",
        "calibration6",
        1,
    )
    assert ipv6._ethernet(raw, 65534, None, None) == raw


@pytest.mark.parametrize(
    "hardware,source,destination",
    [
        (1, "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:02"),
        (1, "00:00:00:00:00:00", "02:00:00:00:00:02"),
        (1, None, None),
        (65534, "02:00:00:00:00:01", None),
        (772, None, None),
    ],
)
def test_unsafe_mac_or_hardware_configuration_is_rejected(hardware, source, destination):
    with pytest.raises(ValueError):
        ipv6._ethernet(b"synthetic", hardware, source, destination)


def test_calibration_sends_exactly_five_packets_on_only_owned_interface(tmp_path, monkeypatch):
    sent = []

    class RawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def bind(self, address):
            assert address == ("wg-office", 0)

        def send(self, raw):
            sent.append(raw)
            return len(raw)

    def create(family, kind, protocol):
        assert (family, kind, protocol) == (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
        return RawSocket()

    monkeypatch.setattr(socket, "socket", create)
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 7)
    monkeypatch.setattr(ipv6.evidence, "interface_hardware", lambda _: 65534)
    monkeypatch.setattr(ipv6, "_root", lambda _: tmp_path)
    config = {
        "mode": "calibrate",
        "interface": "wg-office",
        "ifindex": 7,
        "phase": "calibration6",
        "run_dir": "unused",
        "source_mac": None,
        "destination_mac": None,
    }
    assert ipv6.calibrate(config) == 0
    assert len(sent) == 5
    assert {ipv6.evidence.parse_packet(raw, linktype=101).identity[:2] for raw in sent} == set(
        ipv6.STREAMS
    )
    assert (tmp_path / "calibration.json").stat().st_mode & 0o777 == 0o600
    assert json.loads((tmp_path / "calibration.json").read_text())["errors"] == []


def test_calibration_refuses_stale_generation_before_sending(monkeypatch):
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 8)
    with pytest.raises(ValueError, match="interface_invalid"):
        ipv6.calibrate(
            {
                "mode": "calibrate",
                "interface": "wg-office",
                "ifindex": 7,
                "phase": "calibration6",
                "run_dir": "unused",
                "source_mac": None,
                "destination_mac": None,
            }
        )


@pytest.mark.parametrize("identity", [None, [1], [1, True], [1, 0], [1, 3]])
def test_sender_requires_exact_owned_namespace_before_raw_socket(identity, monkeypatch):
    monkeypatch.setattr(ipv6, "_namespace_identity", lambda: [1, 2])
    monkeypatch.setattr(
        socket, "socket", lambda *_: pytest.fail("no socket before ownership proof")
    )
    with pytest.raises(ValueError, match="namespace_identity"):
        ipv6.send(
            {
                "mode": "send",
                "interface": "wg-client",
                "ifindex": 7,
                "run_dir": "unused",
                "deadline_seconds": 1,
                "namespace_inode": identity,
            }
        )


def test_namespace_snapshot_checks_both_device_and_inode(monkeypatch):
    monkeypatch.setattr(ipv6, "_namespace_identity", lambda: [9, 21])
    ipv6._require_namespace([9, 21])
    for wrong in ([8, 21], [9, 22]):
        with pytest.raises(ValueError, match="namespace_identity"):
            ipv6._require_namespace(wrong)


def test_sender_cannot_omit_namespace_projection():
    with pytest.raises(ValueError, match="configuration_invalid"):
        ipv6.send(
            {
                "mode": "send",
                "interface": "wg-client",
                "ifindex": 7,
                "run_dir": "unused",
                "deadline_seconds": 1,
            }
        )


def test_sender_emits_numbered_ipv6_only_streams_and_private_receipt(tmp_path, monkeypatch):
    from types import SimpleNamespace

    sent = []

    class RawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def bind(self, address):
            assert address == ("wg-client", 0)

        def send(self, frame):
            sent.append(frame)
            return len(frame)

    def create(family, kind, protocol):
        assert (family, kind, protocol) == (socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
        return RawSocket()

    original_stat = Path.stat

    def facts(path, *args, **kwargs):
        if str(path) == "/proc/self/ns/net":
            return SimpleNamespace(st_ino=21)
        if str(path) == "/proc/1/ns/net":
            return SimpleNamespace(st_ino=22)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", facts)
    monkeypatch.setattr(ipv6, "_namespace_identity", lambda: [9, 21])
    monkeypatch.setattr(socket, "socket", create)
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 7)
    monkeypatch.setattr(ipv6.evidence, "interface_hardware", lambda _: 65534)
    monkeypatch.setattr(ipv6, "_root", lambda _: tmp_path)
    (tmp_path / "control.json").write_text("{}")
    controls = iter(({"phase": "blocked6", "stop": False}, {"phase": "blocked6", "stop": True}))
    monkeypatch.setattr(ipv6, "private_json", lambda _: next(controls))
    monkeypatch.setattr(ipv6.time, "sleep", lambda _: None)
    assert (
        ipv6.send(
            {
                "mode": "send",
                "interface": "wg-client",
                "ifindex": 7,
                "run_dir": "unused",
                "deadline_seconds": 1,
                "namespace_inode": [9, 21],
            }
        )
        == 0
    )
    result = json.loads((tmp_path / "sender.json").read_text())
    assert result["family"] == 6 and result["errors"] == []
    assert len(sent) == 5 and len(result["attempts"]) == 5
    assert {item["sequence"] for item in result["attempts"]} == {1}
    assert (tmp_path / "sender.json").stat().st_mode & 0o777 == 0o600
    assert {ipv6.evidence.parse_packet(frame, linktype=101).identity[:2] for frame in sent} == set(
        ipv6.STREAMS
    )


def test_send_error_becomes_fixed_failed_receipt_boundary(monkeypatch):
    class RawSocket:
        def send(self, _):
            raise OSError("synthetic hidden detail")

    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 7)
    assert ipv6._send_checked(RawSocket(), "wg-client", 7, b"synthetic") is False


@pytest.mark.parametrize(
    "hardware,error,accepted",
    [(65534, 126, True), (1, 126, False), (65534, 1, False), (65534, 100, False)],
)
def test_only_raw_calibration_may_record_enokey_downstream_rejection(
    hardware, error, accepted, monkeypatch
):
    class RawSocket:
        def send(self, _):
            raise OSError(error, "synthetic hidden detail")

    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 7)
    status, rejection = ipv6._send_calibration(RawSocket(), "wg-office", 7, b"synthetic", hardware)
    assert status is accepted
    assert rejection == ("wireguard_no_peer" if accepted else None)
    # Client pressure must still fail, even for exactly the same ENOKEY.
    assert ipv6._send_checked(RawSocket(), "wg-client", 7, b"synthetic") is False


def test_calibration_enokey_never_accepts_changed_interface_generation(monkeypatch):
    class RawSocket:
        def send(self, _):
            raise OSError(126, "synthetic")

    indexes = iter((7, 8))
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: next(indexes))
    assert ipv6._send_calibration(RawSocket(), "wg-office", 7, b"synthetic", 65534) == (False, None)


def test_calibration_enokey_receipt_is_explicitly_not_delivery(tmp_path, monkeypatch):
    class RawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def bind(self, address):
            assert address == ("wg-office", 0)

        def send(self, _):
            raise OSError(126, "synthetic hidden detail")

    monkeypatch.setattr(socket, "socket", lambda *_: RawSocket())
    monkeypatch.setattr(socket, "if_nametoindex", lambda _: 7)
    monkeypatch.setattr(ipv6.evidence, "interface_hardware", lambda _: 65534)
    monkeypatch.setattr(ipv6, "_root", lambda _: tmp_path)
    assert (
        ipv6.calibrate(
            {
                "mode": "calibrate",
                "interface": "wg-office",
                "ifindex": 7,
                "phase": "calibration6",
                "run_dir": "unused",
                "source_mac": None,
                "destination_mac": None,
            }
        )
        == 0
    )
    result = json.loads((tmp_path / "calibration.json").read_text())
    assert result["errors"] == [] and len(result["attempts"]) == 5
    assert len(result["downstream_rejections"]) == 5
    assert all(
        item["delivery"] is False and item["reason"] == "wireguard_no_peer"
        for item in result["downstream_rejections"]
    )
    assert "hidden detail" not in (tmp_path / "calibration.json").read_text()
    # An injector receipt alone is never accepted as calibrated packet evidence.
    captures, sender = receipts()
    captures["office"]["calibration"] = []
    with pytest.raises(ipv6.evidence.EvidenceInvalid, match="calibration_missing"):
        validate(captures, sender)
