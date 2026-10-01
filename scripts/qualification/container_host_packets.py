"""Pure bounded D6 packet decoding and fail-closed receipt acceptance.

Only synthetic payload identities are correlated: IP addresses and transport ports
are metadata, so Docker NAT cannot disguise a protected marker. No WireGuard
ciphertext is inspected. The optional collector uses filtered read-only packet
sockets on explicitly selected interfaces; it never changes networking.
"""

from __future__ import annotations

import ipaddress
import json
import re
import struct
from dataclasses import dataclass
from itertools import pairwise

PREFIX = b"exitlane-d6-protected-"
PHASE = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")
SEQUENCE = re.compile(r"[1-9][0-9]{0,9}\Z")
MARKER = re.compile(
    rb"exitlane-d6-protected-([a-z][a-z0-9_-]{0,39}):([1-9][0-9]{0,9})\Z"
)
DNS_NAME = re.compile(
    r"eld6-([a-z][a-z0-9_-]{0,39})-([1-9][0-9]{0,9})\.example\.test\Z"
)
MAX_SEQUENCE = 2**31 - 1
MAX_RECORDS = 100_000
EXTENSIONS = {0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254}
# The D6 IPv4 pressure contract is fixed independently of a sender receipt or
# its calibration. Missing an entire stream is missing evidence, not coverage.
STREAMS = (
    ("protected", "udp"),
    ("protected", "tcp"),
    ("protected", "icmp"),
    ("dns", "udp"),
    ("dns", "tcp"),
)

STREAMS6 = tuple(
    (kind, "icmp6" if protocol == "icmp" else protocol) for kind, protocol in STREAMS
)


class EvidenceInvalid(ValueError):
    """Fixed error codes only; never interpolate packet content into errors."""


@dataclass(frozen=True)
class PacketEvidence:
    kind: str
    protocol: str | None = None
    phase: str | None = None
    sequence: int | None = None
    source: str | None = None
    destination: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    error: str | None = None

    @property
    def identity(self):
        if self.kind not in {"protected", "dns"}:
            return None
        return self.kind, self.protocol, self.phase, self.sequence


def _require(value, code):
    if not value:
        raise EvidenceInvalid(code)


def _sequence(value):
    _require(
        isinstance(value, str) and SEQUENCE.fullmatch(value) is not None,
        "sequence_invalid",
    )
    result = int(value)
    _require(result <= MAX_SEQUENCE, "sequence_invalid")
    return result


def _marker(payload):
    match = MARKER.fullmatch(payload)
    if match:
        return match[1].decode("ascii"), _sequence(match[2].decode("ascii"))
    if payload.startswith(PREFIX) or PREFIX.startswith(payload) and payload:
        raise EvidenceInvalid("marker_invalid_or_segmented")
    return None


def _dns(payload, *, tcp):
    if tcp:
        _require(len(payload) >= 2, "dns_tcp_segmented")
        size = struct.unpack_from("!H", payload)[0]
        _require(size == len(payload) - 2, "dns_tcp_segmented")
        payload = payload[2:]
    _require(12 <= len(payload) <= 4096, "dns_message_invalid")
    flags, questions = struct.unpack_from("!HH", payload, 2)
    _require(flags & 0x7800 == 0 and questions == 1, "dns_question_invalid")
    labels, offset = [], 12
    while True:
        _require(offset < len(payload), "dns_question_truncated")
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        _require(
            length <= 63 and offset + length <= len(payload), "dns_question_invalid"
        )
        try:
            label = payload[offset : offset + length].decode("ascii")
        except UnicodeError:
            raise EvidenceInvalid("dns_question_invalid") from None
        _require(
            re.fullmatch(r"[A-Za-z0-9_-]+", label) is not None, "dns_question_invalid"
        )
        labels.append(label)
        _require(
            len(labels) <= 127 and sum(map(len, labels)) + len(labels) <= 254,
            "dns_question_invalid",
        )
        offset += length
    _require(offset + 4 <= len(payload), "dns_question_truncated")
    query_type, query_class = struct.unpack_from("!HH", payload, offset)
    name = ".".join(labels)
    if not name.startswith("eld6-"):
        return None
    match = DNS_NAME.fullmatch(name)
    _require(
        match is not None and query_type in {1, 28} and query_class == 1,
        "synthetic_dns_invalid",
    )
    return match[1], _sequence(match[2])


def parse_packet(
    frame: bytes, *, linktype: int = 1, wg_ports=(51820, 51821)
) -> PacketEvidence:
    """Ethernet, SLL/SLL2 and raw IP; uncertain relevant data is never a zero."""
    try:
        return _parse_packet(frame, linktype=linktype, wg_ports=wg_ports)
    except EvidenceInvalid as error:
        return PacketEvidence("invalid", error=str(error))
    except (ValueError, TypeError, IndexError, struct.error):
        return PacketEvidence("invalid", error="packet_malformed")


def _parse_packet(frame, *, linktype, wg_ports):
    _require(isinstance(frame, bytes) and len(frame) <= 65575, "packet_size_invalid")
    _require(
        isinstance(wg_ports, (tuple, list, set))
        and 1 <= len(wg_ports) <= 16
        and all(type(port) is int and 1 <= port <= 65535 for port in wg_ports),
        "wireguard_port_inventory_invalid",
    )
    if linktype == 1:
        _require(len(frame) >= 14, "ethernet_truncated")
        offset, ether_type = 14, struct.unpack_from("!H", frame, 12)[0]
        tags = 0
        while ether_type in {0x8100, 0x88A8}:
            _require(tags < 2 and len(frame) >= offset + 4, "vlan_invalid")
            ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
            tags += 1
    elif linktype == 113:
        _require(len(frame) >= 16, "cooked_truncated")
        offset, ether_type = 16, struct.unpack_from("!H", frame, 14)[0]
    elif linktype == 276:
        _require(len(frame) >= 20, "cooked_truncated")
        offset, ether_type = 20, struct.unpack_from("!H", frame)[0]
    elif linktype in {101, 12}:
        _require(bool(frame), "ip_truncated")
        offset, ether_type = 0, {4: 0x0800, 6: 0x86DD}.get(frame[0] >> 4)
        _require(ether_type is not None, "ip_version_invalid")
    else:
        raise EvidenceInvalid("linktype_unsupported")
    # Cooked captures can preserve VLAN tags after their own link header.
    tags = 0
    while ether_type in {0x8100, 0x88A8}:
        _require(tags < 2 and len(frame) >= offset + 4, "vlan_invalid")
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
        tags += 1
    if ether_type not in {0x0800, 0x86DD}:
        return PacketEvidence("other")
    _require(len(frame) > offset, "ip_truncated")
    version = frame[offset] >> 4
    if ether_type == 0x0800:
        _require(version == 4 and len(frame) >= offset + 20, "ipv4_truncated")
        header_size = (frame[offset] & 15) * 4
        total_size = struct.unpack_from("!H", frame, offset + 2)[0]
        _require(
            20 <= header_size <= 60
            and header_size <= total_size
            and offset + total_size <= len(frame),
            "ipv4_length_invalid",
        )
        _require(
            struct.unpack_from("!H", frame, offset + 6)[0] & 0xBFFF == 0,
            "ipv4_fragment_unsupported",
        )
        protocol = frame[offset + 9]
        source = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
        destination = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
    else:
        _require(version == 6 and len(frame) >= offset + 40, "ipv6_truncated")
        header_size = 40
        size = struct.unpack_from("!H", frame, offset + 4)[0]
        _require(
            size > 0 and offset + header_size + size <= len(frame),
            "ipv6_length_invalid",
        )
        total_size = size + header_size
        protocol = frame[offset + 6]
        _require(protocol not in EXTENSIONS, "ipv6_extension_unsupported")
        source = str(ipaddress.IPv6Address(frame[offset + 8 : offset + 24]))
        destination = str(ipaddress.IPv6Address(frame[offset + 24 : offset + 40]))
    _require(
        not (version == 4 and protocol == 58 or version == 6 and protocol == 1),
        "icmp_family_invalid",
    )
    payload = frame[offset + header_size : offset + total_size]
    name = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}.get(protocol)
    metadata = {"protocol": name, "source": source, "destination": destination}
    if protocol in {1, 58}:
        _require(len(payload) >= 8, "icmp_truncated")
        if (
            payload[0] not in ({0, 8} if protocol == 1 else {128, 129})
            or payload[1] != 0
        ):
            return PacketEvidence("other", **metadata)
        marker = _marker(payload[8:])
    elif protocol in {6, 17}:
        _require(len(payload) >= (8 if protocol == 17 else 20), "transport_truncated")
        source_port, destination_port = struct.unpack_from("!HH", payload)
        metadata.update(source_port=source_port, destination_port=destination_port)
        if protocol == 17:
            size = struct.unpack_from("!H", payload, 4)[0]
            _require(8 <= size == len(payload), "udp_length_invalid")
            payload = payload[8:]
        else:
            header_size = (payload[12] >> 4) * 4
            _require(20 <= header_size <= len(payload), "tcp_length_invalid")
            payload = payload[header_size:]
            if not payload:
                return PacketEvidence("other", **metadata)
        # Qualification marker sockets use dedicated ports. WireGuard ciphertext
        # arriving on its known endpoint remains opaque, even if bytes resemble a marker.
        marker_port = 7777 if protocol == 17 else 7778
        if protocol == 17 and (
            destination_port in wg_ports
            or source_port in wg_ports
            and marker_port not in {source_port, destination_port}
        ):
            return PacketEvidence("wireguard", **metadata)
        if 53 in {source_port, destination_port}:
            question = _dns(payload, tcp=protocol == 6)
            return (
                PacketEvidence(
                    "dns", phase=question[0], sequence=question[1], **metadata
                )
                if question
                else PacketEvidence("other", **metadata)
            )
        marker = (
            _marker(payload) if marker_port in {source_port, destination_port} else None
        )
    else:
        raise EvidenceInvalid("transport_unsupported")
    return (
        PacketEvidence("protected", phase=marker[0], sequence=marker[1], **metadata)
        if marker
        else PacketEvidence("other", **metadata)
    )


def _identity(record, phase):
    _require(isinstance(record, dict), "sample_invalid")
    kind, protocol = record.get("kind"), record.get("protocol")
    _require(
        kind in {"protected", "dns"}
        and protocol in {"udp", "tcp", "icmp", "icmp6"}
        and (kind != "dns" or protocol in {"udp", "tcp"}),
        "sample_invalid",
    )
    _require(record.get("phase") == phase, "sample_phase_mismatch")
    sequence = record.get("sequence")
    _require(
        type(sequence) is int and 1 <= sequence <= MAX_SEQUENCE,
        "sample_sequence_invalid",
    )
    return kind, protocol, phase, sequence


def _clock_alignment(measurement, start, end):
    """Derive reference-minus-local bounds from local authenticated RPC trips."""
    _require(
        isinstance(measurement, dict) and set(measurement) == {"before", "after"},
        "clock_measurement_invalid",
    )
    intervals = []
    for label in ("before", "after"):
        sample = measurement[label]
        _require(
            isinstance(sample, dict)
            and set(sample) == {"local_before_ns", "reference_ns", "local_after_ns"}
            and all(type(value) is int and value > 0 for value in sample.values()),
            "clock_measurement_invalid",
        )
        first, reference, last = (
            sample[key] for key in ("local_before_ns", "reference_ns", "local_after_ns")
        )
        _require(
            first <= last and last - first <= 100_000_000, "clock_interval_invalid"
        )
        intervals.append((reference - last, reference - first))
    before, after = measurement["before"], measurement["after"]
    _require(
        before["reference_ns"] <= start
        and after["reference_ns"] >= end
        and before["local_after_ns"] < after["local_before_ns"],
        "clock_measurement_not_bracketing",
    )
    _require(
        max(item[0] for item in intervals) <= min(item[1] for item in intervals),
        "clock_drift_detected",
    )
    lower, upper = (
        min(item[0] for item in intervals),
        max(item[1] for item in intervals),
    )
    _require(
        -1_000_000_000 <= lower <= upper <= 1_000_000_000
        and upper - lower <= 100_000_000,
        "clock_interval_invalid",
    )
    _require(
        before["local_after_ns"] + upper <= start
        and after["local_before_ns"] + lower >= end,
        "clock_measurement_not_bracketing",
    )
    return {
        "mode": "measured_interval",
        "lower_ns": lower,
        "upper_ns": upper,
        "measurements": measurement,
    }


def validate_receipts(
    captures,
    sender,
    *,
    phase,
    forbidden_points,
    delivery_points=(),
    required_points,
    calibration_phase="calibration",
    max_gap_ns=1_000_000_000,
    sender_points=("client",),
    clock_offsets=None,
    family=4,
):
    """Accept only complete, calibrated capture and continuously numbered sender evidence.

    Receipts default to one synchronized wall-clock ns timeline. Optional remote
    clock_offsets must contain measured before/after reference round trips, never
    arbitrary offsets or slack. Sender points remain on the reference clock.
    Capture
    fields: ready/start_ns/end_ns/last_poll_ns/polls/ifindex/drops/errors/gaps/
    invalid_packets/max_poll_gap_ns/samples/calibration. Samples/calibration carry
    observed_ns and ifindex from the actual bound capture socket. Sender: phase/start_ns/end_ns/errors/
    attempts; each attempt has kind/protocol/phase/sequence/sent_ns. Calibration
    is actual decoded samples, not an unchecked success boolean. A host outage
    must use an independently continuous witness; missing captures never pass.
    required_points is an explicit coordinator topology contract, never inferred
    from the supplied captures. Family 4 (default) or explicit family 6 selects
    its exact five-stream inventory; IPv6 records require decoded addresses.
    """
    _require(type(family) is int and family in {4, 6}, "evidence_family_invalid")
    expected_streams = STREAMS if family == 4 else STREAMS6

    def check_family(record):
        # Historical IPv4 receipts may omit address metadata. IPv6 qualification
        # always requires both actual decoded addresses; never infer from ICMP6.
        _require(isinstance(record, dict), "sample_invalid")
        for key in ("source", "destination"):
            address = record.get(key)
            if address is None and family == 4:
                continue
            try:
                valid = (
                    isinstance(address, str)
                    and ipaddress.ip_address(address).version == family
                )
            except ValueError:
                valid = False
            _require(valid, "capture_address_family_mismatch")

    _require(
        isinstance(phase, str)
        and PHASE.fullmatch(phase) is not None
        and isinstance(calibration_phase, str)
        and PHASE.fullmatch(calibration_phase) is not None
        and phase != calibration_phase,
        "phase_invalid",
    )
    _require(
        type(max_gap_ns) is int and 1 <= max_gap_ns <= 2_000_000_000,
        "gap_budget_invalid",
    )
    _require(
        isinstance(captures, dict) and 1 <= len(captures) <= 32,
        "capture_inventory_invalid",
    )
    _require(
        isinstance(required_points, (list, tuple))
        and 1 <= len(required_points) <= 32
        and all(
            isinstance(point, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", point) is not None
            for point in required_points
        )
        and len(set(required_points)) == len(required_points),
        "capture_topology_invalid",
    )
    points = tuple(required_points)
    _require(set(points) == set(captures), "capture_topology_mismatch")
    _require(
        set(forbidden_points) <= set(points)
        and set(delivery_points) <= set(points)
        and not set(forbidden_points) & set(delivery_points),
        "capture_roles_invalid",
    )
    _require(
        isinstance(sender, dict)
        and sender.get("phase") == phase
        and sender.get("errors") == []
        and sender.get("family", 4) == family,
        "sender_invalid",
    )
    start, end = sender.get("start_ns"), sender.get("end_ns")
    _require(
        type(start) is int and type(end) is int and 0 < start < end,
        "sender_window_invalid",
    )
    attempts = sender.get("attempts")
    _require(
        isinstance(attempts, list) and 1 <= len(attempts) <= MAX_RECORDS,
        "sender_missing",
    )
    identities, streams = set(), {}
    for attempt in attempts:
        identity = _identity(attempt, phase)
        _require(identity not in identities, "sender_duplicate")
        identities.add(identity)
        timestamp = attempt.get("sent_ns")
        _require(
            type(timestamp) is int and start <= timestamp <= end,
            "sender_timestamp_invalid",
        )
        streams.setdefault(identity[:2], []).append((identity[-1], timestamp))
    _require(set(streams) == set(expected_streams), "sender_stream_inventory_mismatch")
    for records in streams.values():
        _require(
            [item[0] for item in records] == list(range(1, len(records) + 1)),
            "sender_sequence_gap",
        )
        times = [start, *(item[1] for item in records), end]
        _require(
            all(0 <= b - a <= max_gap_ns for a, b in pairwise(times)),
            "sender_time_gap",
        )
    _require(
        isinstance(sender_points, (list, tuple))
        and bool(sender_points)
        and set(sender_points) <= set(points),
        "sender_capture_missing",
    )
    _require(
        clock_offsets is None
        or (
            isinstance(clock_offsets, dict)
            and set(clock_offsets) <= set(points)
            and not set(clock_offsets) & set(sender_points)
        ),
        "clock_inventory_invalid",
    )
    alignments = {
        point: (
            _clock_alignment(clock_offsets[point], start, end)
            if clock_offsets is not None and point in clock_offsets
            else {"mode": "same_reference", "lower_ns": 0, "upper_ns": 0}
        )
        for point in points
    }
    observations = {}
    for point in points:
        alignment = alignments[point]
        lower, upper = alignment["lower_ns"], alignment["upper_ns"]
        receipt = captures[point]
        _require(
            isinstance(receipt, dict) and receipt.get("ready") is True,
            "capture_not_ready",
        )
        _require(
            receipt.get("errors") == []
            and receipt.get("gaps") == []
            and type(receipt.get("drops")) is int
            and receipt["drops"] == 0
            and type(receipt.get("invalid_packets")) is int
            and receipt["invalid_packets"] == 0
            and type(receipt.get("max_poll_gap_ns")) is int
            and 0 <= receipt["max_poll_gap_ns"] <= max_gap_ns,
            "capture_evidence_invalid",
        )
        _require(
            type(receipt.get("polls")) is int
            and receipt["polls"] >= 2
            and type(receipt.get("ifindex")) is int
            and receipt["ifindex"] > 0,
            "capture_not_ready",
        )
        cstart, cend, last = (
            receipt.get(key) for key in ("start_ns", "end_ns", "last_poll_ns")
        )
        _require(
            all(type(value) is int for value in (cstart, cend, last))
            and 0 < cstart < cend
            and cstart + upper <= start < end <= cend + lower
            and cend - max_gap_ns <= last <= cend,
            "capture_window_gap",
        )
        calibration = receipt.get("calibration")
        _require(
            isinstance(calibration, list) and 1 <= len(calibration) <= MAX_RECORDS,
            "capture_calibration_missing",
        )
        for item in calibration:
            check_family(item)
            _require(
                type(item.get("ifindex")) is int
                and item["ifindex"] == receipt["ifindex"]
                and type(item.get("observed_ns")) is int
                and cstart <= item["observed_ns"] <= cend,
                "capture_calibration_generation_mismatch",
            )
        calibrated = {_identity(item, calibration_phase)[:2] for item in calibration}
        _require(set(streams) == calibrated, "capture_calibration_incomplete")
        samples = receipt.get("samples")
        _require(
            isinstance(samples, list) and len(samples) <= MAX_RECORDS,
            "capture_samples_invalid",
        )
        for item in samples:
            check_family(item)
            _require(
                type(item.get("ifindex")) is int
                and item["ifindex"] == receipt["ifindex"]
                and type(item.get("observed_ns")) is int
                and cstart <= item["observed_ns"] <= cend
                and item["observed_ns"] + lower <= end
                and item["observed_ns"] + upper >= start
                and (
                    alignment["mode"] == "same_reference"
                    or alignment["measurements"]["before"]["local_after_ns"]
                    <= item["observed_ns"]
                    <= alignment["measurements"]["after"]["local_before_ns"]
                ),
                "capture_sample_window_or_generation_mismatch",
            )
        observed = {_identity(item, phase) for item in samples}
        _require(observed <= identities, "capture_unknown_sequence")
        observations[point] = observed
    _require(
        all(identities <= observations[point] for point in sender_points),
        "sender_transmission_not_proven",
    )
    _require(
        not any(observations[point] for point in forbidden_points),
        "protected_plaintext_observed",
    )
    _require(
        all(identities <= observations[point] for point in delivery_points),
        "delivery_not_proven",
    )
    return {
        "phase": phase,
        "sent": len(identities),
        "points": len(points),
        "accepted": True,
        "clock_alignment": alignments,
    }


# The observer is deliberately separate from appliance code and uses only
# read-only packet sockets. A caller explicitly selects owned qualification
# interfaces/addresses. Credentials are neither accepted nor recorded.
def _capture_config(value):
    import os
    from pathlib import Path

    _require(
        isinstance(value, dict)
        and set(value) == {"interfaces", "addresses", "run_dir"},
        "observer_config_invalid",
    )
    interfaces, addresses = value["interfaces"], value["addresses"]
    _require(
        isinstance(interfaces, list)
        and 1 <= len(interfaces) <= 12
        and len(set(interfaces)) == len(interfaces)
        and all(
            isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name)
            for name in interfaces
        ),
        "observer_interfaces_invalid",
    )
    _require(
        isinstance(addresses, list) and 1 <= len(addresses) <= 32,
        "observer_addresses_invalid",
    )
    canonical = {str(ipaddress.ip_address(item)) for item in addresses}
    _require(
        all(
            isinstance(item, str) and str(ipaddress.ip_address(item)) == item
            for item in addresses
        ),
        "observer_addresses_invalid",
    )
    root = Path(value["run_dir"])
    _require(
        str(root) == value["run_dir"]
        and re.fullmatch(r"/run/exitlane-d6-[a-f0-9]{32}", str(root)) is not None,
        "observer_directory_invalid",
    )
    _require(os.geteuid() == 0, "observer_root_required")
    return tuple(interfaces), canonical, root


def _private_read(path, limit):
    import os
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        facts = os.fstat(source.fileno())
        _require(
            stat.S_ISREG(facts.st_mode)
            and facts.st_uid == os.geteuid()
            and facts.st_nlink == 1
            and facts.st_mode & 0o077 == 0
            and facts.st_size <= limit,
            "observer_control_unsafe",
        )
        result = source.read(limit + 1)
    _require(len(result) <= limit, "observer_control_unsafe")
    return result


def _uncertain_relevant(frame, addresses):
    """Conservative narrow filter for invalid cooked packets, not broad host DNS."""
    if len(frame) < 20:
        return False
    ether_type, offset = struct.unpack_from("!H", frame)[0], 20
    for _ in range(2):
        if ether_type not in {0x8100, 0x88A8}:
            break
        if len(frame) < offset + 4:
            return True
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    try:
        if ether_type == 0x0800 and len(frame) >= offset + 20:
            source = str(ipaddress.IPv4Address(frame[offset + 12 : offset + 16]))
            destination = str(ipaddress.IPv4Address(frame[offset + 16 : offset + 20]))
            protocol = frame[offset + 9]
            fragment = struct.unpack_from("!H", frame, offset + 6)[0]
            transport = offset + (frame[offset] & 15) * 4
        elif ether_type == 0x86DD and len(frame) >= offset + 40:
            source = str(ipaddress.IPv6Address(frame[offset + 8 : offset + 24]))
            destination = str(ipaddress.IPv6Address(frame[offset + 24 : offset + 40]))
            protocol, fragment, transport = frame[offset + 6], 0, offset + 40
        else:
            return False
        if source not in addresses and destination not in addresses:
            return False
        if fragment & 0xBFFF or protocol in EXTENSIONS:
            return True
        if protocol in {1, 58}:
            return (
                protocol == 1
                and len(frame) > transport
                and frame[transport] in {3, 11, 12}
                or PREFIX in frame[transport:]
                or b"exitlane-d6-" in frame[transport:]
            )
        if protocol in {6, 17} and len(frame) >= transport + 4:
            ports = struct.unpack_from("!HH", frame, transport)
            if set(ports) & {7777, 7778, 51820, 51821}:
                return True
            if 53 in ports:
                return b"eld6-" in frame[transport:]
        return False
    except (ValueError, struct.error):
        return False


def kernel_filter(addresses, hardware_type):
    """Build bounded Linux classic BPF for Ethernet or WireGuard raw IP.

    Absolute Ethernet offsets explicitly handle zero, one or two VLAN tags;
    raw-IP offsets are independent of libpcap link-type inference. Unknown IP
    protocols and fragments for selected addresses remain observable evidence.
    Only TCP/UDP on unrelated ports (notably SSH) are discarded in the kernel.
    """
    _require(hardware_type in {1, 65534}, "capture_hardware_unsupported")
    _require(1 <= len(addresses) <= 32, "capture_filter_addresses_invalid")
    parsed = sorted({ipaddress.ip_address(item) for item in addresses}, key=str)
    code, labels, relocations = [], {}, []

    def emit(op, k=0):
        code.append((op, 0, 0, k))

    def label(name):
        labels[name] = len(code)

    def jump(name):
        relocations.append((len(code), name))
        emit(0x05)  # JA: 32-bit forward offset avoids conditional jump limits.

    def condition(op, value, target):
        code.append((op, 0, 1, value))
        jump(target)

    offsets = (14, 18, 22) if hardware_type == 1 else (0,)
    if hardware_type == 1:
        for depth, offset in enumerate(offsets):
            label(f"ether{depth}")
            emit(0x28, offset - 2)  # LD H ABS
            condition(0x15, 0x0800, f"ip4_{offset}")
            condition(0x15, 0x86DD, f"ip6_{offset}")
            if depth < 2:
                condition(0x15, 0x8100, f"ether{depth + 1}")
                condition(0x15, 0x88A8, f"ether{depth + 1}")
            jump("reject")
    else:
        emit(0x30, 0)  # LD B ABS
        emit(0x54, 0xF0)  # AND K
        condition(0x15, 0x40, "ip4_0")
        condition(0x15, 0x60, "ip6_0")
        jump("reject")

    for offset in offsets:
        for version in (4, 6):
            label(f"ip{version}_{offset}")
            candidates = [item for item in parsed if item.version == version]
            for number, address in enumerate(candidates):
                for side, address_offset in enumerate(
                    (12, 16) if version == 4 else (8, 24)
                ):
                    words = struct.unpack(
                        "!" + "I" * (1 if version == 4 else 4), address.packed
                    )
                    for word_number, word in enumerate(words):
                        emit(0x20, offset + address_offset + word_number * 4)
                        # Equal continues; mismatch jumps to next address/side.
                        code.append((0x15, 1, 0, word))
                        jump(f"next_{offset}_{version}_{number}_{side}")
                    jump(f"matched_{offset}_{version}")
                    label(f"next_{offset}_{version}_{number}_{side}")
            jump("reject")
            label(f"matched_{offset}_{version}")
            if version == 4:
                emit(0x28, offset + 6)
                condition(0x45, 0xBFFF, "accept")  # JSET: fragment/reserved.
                emit(0x30, offset)
                emit(0x54, 15)
                condition(0x35, 5, f"ihl_ok_{offset}")  # JGE
                jump("accept")  # Malformed selected-address IP is evidence.
                label(f"ihl_ok_{offset}")
            emit(0x30, offset + (9 if version == 4 else 6))
            condition(0x15, 6, f"ports_{offset}_{version}")
            condition(0x15, 17, f"ports_{offset}_{version}")
            jump("accept")  # ICMP, IPv6 extensions and unknown protocols.
            label(f"ports_{offset}_{version}")
            if version == 4:
                emit(0xB1, offset)  # LDX B MSH: actual IPv4 header length.
                emit(0x87)  # TXA
                emit(0x04, offset + 4)  # ADD K
                emit(0x07)  # TAX
                emit(0x80)  # LD LEN
                condition(0x3D, 0, f"transport_ok_{offset}_{version}")  # JGE X
            else:
                emit(0x80)
                condition(0x35, offset + 44, f"transport_ok_{offset}_{version}")
            jump("accept")  # Truncation of a selected-address packet is evidence.
            label(f"transport_ok_{offset}_{version}")
            if version == 4:
                emit(0xB1, offset)
            for port_offset in (0, 2):
                emit(
                    0x48 if version == 4 else 0x28,
                    offset + (0 if version == 4 else 40) + port_offset,
                )
                for port in (53, 7777, 7778, 51820, 51821):
                    condition(0x15, port, "accept")
            jump("reject")
    label("reject")
    emit(0x06, 0)
    label("accept")
    emit(0x06, 65575)
    _require(len(code) <= 4096, "capture_filter_too_large")
    for index, target in relocations:
        distance = labels[target] - index - 1
        _require(distance >= 0, "capture_filter_invalid")
        code[index] = (0x05, 0, 0, distance)
    return tuple(code)


def interface_hardware(name):
    """Read current-netns hardware type without depending on mounted sysfs.

    SIOCGIFHWADDR is a read-only ioctl; the datagram socket sends no packets.
    Linux ifreq stores sockaddr.sa_family immediately after its 16-byte name.
    """
    import fcntl
    import socket

    _require(
        isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name),
        "capture_interface_invalid",
    )
    request = struct.pack("256s", name.encode("ascii"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as facts_socket:
        response = fcntl.ioctl(facts_socket.fileno(), 0x8927, request)  # SIOCGIFHWADDR
    _require(len(response) >= 18, "capture_hardware_unavailable")
    return struct.unpack_from("=H", response, 16)[0]


def attach_kernel_filter(sock, name, addresses):
    """Read-only interface facts, then attach before AF_PACKET activation.

    Verification does not require tcpdump: unit tests execute the emitted BPF.
    Live acceptance still requires positive calibration, current ifindex and
    zero kernel drops; a successful attach alone never establishes proof.
    """
    import ctypes
    import socket

    class Instruction(ctypes.Structure):
        _fields_ = [
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        ]

    class Program(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_ushort),
            ("instructions", ctypes.POINTER(Instruction)),
        ]

    try:
        hardware = interface_hardware(name)
        instructions = kernel_filter(addresses, hardware)
        backing = (Instruction * len(instructions))(
            *(Instruction(*row) for row in instructions)
        )
        program = Program(len(instructions), backing)
        sock.setsockopt(socket.SOL_SOCKET, 26, bytes(program))  # SO_ATTACH_FILTER
    except (OSError, ValueError) as exc:
        raise EvidenceInvalid("capture_filter_unavailable") from exc


def _output_control_relevant(frame, result):
    """Retain synthetic TCP controls/ICMP quotes without recording ordinary DNS.

    The caller has already decoded a valid packet and requires an explicitly
    selected endpoint. These packets have no marker identity: preserving their
    raw records lets the separate OUTPUT scanner inspect SYN/RST and quoted
    tuples; they must never count as calibrated marker streams.
    """
    ether_type, offset = struct.unpack_from("!H", frame)[0], 20
    for _ in range(2):
        if ether_type not in {0x8100, 0x88A8}:
            break
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if ether_type != 0x0800:
        return False
    transport = offset + (frame[offset] & 15) * 4
    end = offset + struct.unpack_from("!H", frame, offset + 2)[0]
    if result.protocol == "tcp" and {result.source_port, result.destination_port} & {53, 7778}:
        # Valid empty TCP segments, including SYN, RST and ACK. No arbitrary
        # application/DNS payload becomes part of this additional capture path.
        return transport + (frame[transport + 12] >> 4) * 4 == end
    return result.protocol == "icmp" and frame[transport] in {3, 11, 12}


class HostCapture:
    """One bounded observer, one point per explicitly selected interface."""

    def __init__(self, interfaces, addresses, root):
        import os
        import time

        self.interfaces, self.addresses, self.root = interfaces, addresses, root
        root.mkdir(mode=0o700)  # Never adopt an earlier observer's state/artifacts.
        self.control = root / "control.json"
        self.receipt = root / "receipts.json"
        self.phase, self.calibration_phase = None, "calibration"
        self.sockets, self.facts, self.files = {}, {}, {}
        self.errors = []
        self.start_ns, self.last_ns = time.time_ns(), time.time_ns()
        self.total_bytes, self.running = 0, True
        self.poll_monotonic_ns = time.monotonic_ns()
        os.umask(0o077)
        for interface in interfaces:
            self.facts[interface] = self._new_facts(self.start_ns, 0)
            descriptor = os.open(
                root / f"{interface}.pcap", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            output = os.fdopen(descriptor, "wb", buffering=0)
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65575, 276))
            self.files[interface] = output
            self.total_bytes += 24

    def _new_facts(self, stamp, index):
        return {
            "ready": False,
            "start_ns": stamp,
            "end_ns": stamp,
            "last_poll_ns": stamp,
            "polls": 0,
            "ifindex": index,
            "drops": 0,
            "lifetime_drops": 0,
            "errors": [],
            "gaps": [],
            "invalid_packets": 0,
            "max_poll_gap_ns": 0,
            "samples": [],
            "calibration": [],
            "wireguard_packets": 0,
            "wireguard_first_ns": None,
            "wireguard_last_ns": None,
        }

    def phase_control(self):
        if not self.control.exists():
            return
        value = json.loads(_private_read(self.control, 4096))
        _require(
            isinstance(value, dict)
            and set(value) == {"phase", "calibration_phase", "stop"}
            and isinstance(value["phase"], str)
            and PHASE.fullmatch(value["phase"])
            and isinstance(value["calibration_phase"], str)
            and PHASE.fullmatch(value["calibration_phase"])
            and type(value["stop"]) is bool,
            "observer_control_invalid",
        )
        if value["phase"] != self.phase:
            # PACKET_STATISTICS reads reset the kernel counters. Drain while
            # still in the old window, before announcing the new phase. Never
            # discard queued packets: late-phase packets remain explicit errors.
            for name, (_index, sock) in self.sockets.items():
                self.statistics(name, sock)
            self.phase = value["phase"]
            import time

            stamp = time.time_ns()
            for facts in self.facts.values():
                # Start a new explicit proof window; old calibration remains
                # bound to its actual interface generation. Fatal errors remain.
                facts["samples"] = []
                facts["gaps"] = []
                facts["drops"] = 0
                facts["invalid_packets"] = 0
                facts["max_poll_gap_ns"] = 0
                facts["polls"] = 0
                facts["last_poll_ns"] = stamp
                facts["wireguard_packets"] = 0
                facts["wireguard_first_ns"] = None
                facts["wireguard_last_ns"] = None
        self.calibration_phase = value["calibration_phase"]
        self.running = not value["stop"]

    def refresh(self, stamp):
        import socket

        for name in self.interfaces:
            try:
                index = socket.if_nametoindex(name)
            except OSError:
                index = 0
            current = self.sockets.get(name)
            facts = self.facts[name]
            if current and current[0] != index:
                self.statistics(name, current[1])
                current[1].close()
                del self.sockets[name]
                facts["gaps"].append(
                    {"at_ns": stamp, "old_ifindex": current[0], "new_ifindex": index}
                )
                facts["calibration"] = []
                facts["ready"] = False
            if index and name not in self.sockets:
                try:
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                    try:
                        attach_kernel_filter(sock, name, self.addresses)
                        sock.bind((name, 3))  # ETH_P_ALL, after filter attachment.
                    except (OSError, EvidenceInvalid):
                        sock.close()
                        raise
                    if socket.if_nametoindex(name) != index:
                        sock.close()
                        raise EvidenceInvalid("observer_interface_generation_race")
                    sock.setblocking(False)
                    self.sockets[name] = (index, sock)
                    facts["ifindex"] = index
                except (OSError, EvidenceInvalid):
                    if "capture_bind_failed" not in facts["errors"]:
                        facts["errors"].append("capture_bind_failed")
            facts["ready"] = name in self.sockets
            if len(facts["gaps"]) > 64:
                raise EvidenceInvalid("observer_gap_limit")

    def statistics(self, name, sock):
        try:
            _received, dropped = struct.unpack("II", sock.getsockopt(263, 6, 8))
            self.facts[name]["drops"] += dropped
            self.facts[name]["lifetime_drops"] += dropped
        except OSError:
            if "capture_statistics_unavailable" not in self.facts[name]["errors"]:
                self.facts[name]["errors"].append("capture_statistics_unavailable")

    def consume(self, name, frame, stamp):
        from dataclasses import asdict

        result = parse_packet(frame, linktype=276)
        facts = self.facts[name]
        if result.kind == "invalid":
            if _uncertain_relevant(frame, self.addresses):
                facts["invalid_packets"] += 1
            return
        if (
            result.source not in self.addresses
            and result.destination not in self.addresses
        ):
            return
        if result.kind == "other" and not _output_control_relevant(frame, result):
            return
        if result.kind == "wireguard":
            facts["wireguard_packets"] += 1
            if facts["wireguard_first_ns"] is None:
                facts["wireguard_first_ns"] = stamp
            facts["wireguard_last_ns"] = stamp
        if result.kind in {"protected", "dns"}:
            # Delayed packets cannot disappear into a later phase's zero.
            if (
                result.phase not in {self.phase, self.calibration_phase}
                and "unexpected_marker_phase" not in facts["errors"]
            ):
                facts["errors"].append("unexpected_marker_phase")
            if (
                result.phase == self.calibration_phase
                and self.phase != self.calibration_phase
                and "late_calibration_packet" not in facts["errors"]
            ):
                facts["errors"].append("late_calibration_packet")
            category = (
                "calibration" if result.phase == self.calibration_phase else "samples"
            )
            if len(facts[category]) >= MAX_RECORDS:
                raise EvidenceInvalid("observer_record_limit")
            facts[category].append(
                {**asdict(result), "observed_ns": stamp, "ifindex": facts["ifindex"]}
            )
        record = (
            struct.pack(
                "<IIII",
                stamp // 1_000_000_000,
                stamp % 1_000_000_000 // 1000,
                len(frame),
                len(frame),
            )
            + frame
        )
        if self.total_bytes + len(record) > 32 * 1024 * 1024:
            raise EvidenceInvalid("observer_size_limit")
        self.files[name].write(record)
        self.total_bytes += len(record)

    def snapshot(self, stamp):
        import os

        for facts in self.facts.values():
            facts["end_ns"] = stamp
            if self.errors:
                facts["ready"] = False
                facts["errors"] = sorted(set(facts["errors"] + self.errors))
        payload = json.dumps(
            {"phase": self.phase, "captures": self.facts}, sort_keys=True
        ).encode()
        if len(payload) > 32 * 1024 * 1024:
            # Even an exhausted receipt budget must replace the old ready
            # snapshot with an explicit invalid outcome, not leave stale zeros.
            for facts in self.facts.values():
                facts["ready"] = False
                facts["errors"] = sorted(
                    set(facts["errors"] + ["observer_receipt_limit"])
                )
                facts["samples"] = []
                facts["calibration"] = []
            self.running = False
            payload = json.dumps(
                {"phase": self.phase, "captures": self.facts}, sort_keys=True
            ).encode()
        temporary = self.root / ".receipts.new"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.receipt)

    def run(self):
        import select
        import signal
        import socket
        import time

        previous_handlers = {}

        def request_stop(_signal, _frame):
            self.running = False

        for selected in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[selected] = signal.signal(selected, request_stop)
        try:
            while self.running:
                stamp = time.time_ns()
                self.phase_control()
                self.refresh(stamp)
                readers = [value[1] for value in self.sockets.values()]
                ready, _, _ = select.select(readers, [], [], 0.1)
                stamp = time.time_ns()
                monotonic_ns = time.monotonic_ns()
                if stamp < self.last_ns:
                    raise EvidenceInvalid("observer_clock_regressed")
                self.last_ns = stamp
                poll_gap = monotonic_ns - self.poll_monotonic_ns
                self.poll_monotonic_ns = monotonic_ns
                for name, (index, sock) in self.sockets.items():
                    facts = self.facts[name]
                    facts["max_poll_gap_ns"] = max(facts["max_poll_gap_ns"], poll_gap)
                    facts["last_poll_ns"] = stamp
                    facts["polls"] += 1
                    self.statistics(name, sock)
                    if sock not in ready:
                        continue
                    for _ in range(256):
                        try:
                            packet, address = sock.recvfrom(65575)
                        except BlockingIOError:
                            break
                        (
                            interface,
                            protocol,
                            packet_type,
                            hardware_type,
                            hardware_address,
                        ) = address
                        if interface != name:
                            raise EvidenceInvalid("observer_interface_mismatch")
                        body = packet[14:] if hardware_type == 1 else packet
                        cooked = struct.pack(
                            "!HHIHBB8s",
                            protocol,
                            0,
                            index,
                            hardware_type,
                            packet_type,
                            min(len(hardware_address), 8),
                            hardware_address[:8].ljust(8, b"\0"),
                        )
                        self.consume(name, cooked + body, time.time_ns())
                    else:
                        # A bounded read budget cannot silently leave unknown
                        # protected packets queued at the final proof boundary.
                        try:
                            sock.recv(1, socket.MSG_PEEK)
                        except BlockingIOError:
                            pass
                        else:
                            raise EvidenceInvalid("observer_receive_backlog")
                self.snapshot(time.time_ns())
        except EvidenceInvalid as exc:
            # Evidence gates expose only bounded static identifiers, never an
            # exception representation, packet content or arbitrary diagnostics.
            if (
                len(exc.args) == 1
                and isinstance(exc.args[0], str)
                and re.fullmatch(r"[a-z][a-z_]{0,63}", exc.args[0])
            ):
                self.errors.append(exc.args[0])
            self.errors.append("observer_failed")
            self.snapshot(time.time_ns())
            return 1
        except OSError as exc:
            # Preserve a bounded syscall boundary without the path/data that an
            # OSError representation could disclose. Evidence remains invalid.
            number = exc.errno if type(exc.errno) is int and 0 <= exc.errno <= 4096 else 0
            self.errors.extend(["observer_os_error_" + str(number), "observer_failed"])
            self.snapshot(time.time_ns())
            return 1
        except Exception:  # noqa: BLE001 - any observer death invalidates every zero receipt
            self.errors.append("observer_unexpected_error")
            self.errors.append("observer_failed")
            self.snapshot(time.time_ns())
            return 1
        finally:
            for name, (_index, sock) in self.sockets.items():
                self.statistics(name, sock)
                sock.close()
            for output in self.files.values():
                output.close()
            self.snapshot(time.time_ns())
            for selected, previous in previous_handlers.items():
                signal.signal(selected, previous)
        return 1 if self.errors else 0


def main():
    import sys

    try:
        raw = sys.stdin.buffer.read(16_385)
        _require(len(raw) <= 16_384, "observer_config_invalid")
        interfaces, addresses, root = _capture_config(json.loads(raw))
        return HostCapture(interfaces, addresses, root).run()
    except Exception:  # noqa: BLE001 - no malformed config/private path in diagnostics
        print("D6 observer failed; packet evidence is invalid.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
