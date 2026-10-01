"""Packet-evidence parsing must not mistake ciphertext for protected traffic."""

import importlib.util
import json
import struct
import threading
import time
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "container_packet_capture",
    Path(__file__).parents[2] / "scripts/qualification/container_packet_capture.py",
)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


def udp(payload, *, port=7777, fragment=0):
    header = bytearray(20)
    header[0] = 0x45
    header[9] = 17
    struct.pack_into("!H", header, 6, fragment)
    return bytes(header) + struct.pack("!HHHH", 4444, port, 8 + len(payload), 0) + payload


@pytest.mark.parametrize("ethernet", [True, False])
def test_protected_marker_recognized_on_ethernet_and_wireguard(ethernet):
    packet = udp(b"exitlane-d3-protected-switch-failed:12")
    if ethernet:
        # A destination MAC starting with 4 must not be mistaken for IPv4.
        packet = b"\x45" + b"\0" * 11 + b"\x08\0" + packet
    assert capture.classify(packet, ethernet=ethernet) == ("markers", "switch-failed")


def test_ciphertext_with_marker_bytes_is_only_encrypted_metadata():
    packet = udp(b"exitlane-d3-protected-no-provider:1", port=51820)
    assert capture.classify(packet, ethernet=False) == ("encrypted", None)


@pytest.mark.parametrize(
    "payload", [b"exitlane-d3-protected-:1", b"exitlane-d3-protected-a/b:2", b"unrelated"]
)
def test_invalid_marker_does_not_create_evidence(payload):
    assert capture.classify(udp(payload), ethernet=False) is None


def test_fragments_and_truncated_packets_cannot_count_as_complete_markers():
    assert capture.classify(udp(b"exitlane-d3-protected-a:1", fragment=1), ethernet=False) is None
    assert capture.classify(b"\x45" * 10, ethernet=False) is None


def test_only_synthetic_dns_is_counted():
    assert capture.classify(udp(b"eld3-blocked\x07example\x04test", port=53), ethernet=False) == (
        "dns",
        None,
    )
    assert capture.classify(udp(b"unrelated.example", port=53), ethernet=False) is None


def observer_state():
    observer = capture.Capture.__new__(capture.Capture)
    observer.lock = threading.Lock()
    observer.active = {"eth0": 2}
    observer.last_poll = time.monotonic()
    observer.polls = 10
    observer.failed = False
    observer.facts = {"eth0": {"markers": {}, "dns": 0, "encrypted": 0}}
    observer.drops = 0
    observer.errors = set()
    return observer


def test_dead_capture_worker_invalidates_zero_packet_receipt(monkeypatch):
    observer = observer_state()
    monkeypatch.setattr(observer, "observe", lambda: (_ for _ in ()).throw(OSError("synthetic")))
    observer.run()
    receipt = json.loads(observer.snapshot())
    assert receipt["ready"] is False
    assert receipt["capture_errors"] == ["capture_worker_failed"]


def test_stale_poll_and_missing_sockets_are_not_ready():
    observer = observer_state()
    assert json.loads(observer.snapshot())["ready"] is True
    observer.last_poll -= 2
    assert json.loads(observer.snapshot())["ready"] is False
    observer.last_poll = time.monotonic()
    observer.active = {}
    assert json.loads(observer.snapshot())["ready"] is False
