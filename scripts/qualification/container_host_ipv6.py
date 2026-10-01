#!/usr/bin/env python3
"""Bounded synthetic IPv6 isolation proof, outside the appliance.

All configuration arrives on stdin; no credentials or secret arguments are
accepted. Raw packet injection is limited to explicitly owned fixture interfaces
and fixed ULA addresses. It changes no route, address, neighbor or firewall.
Independent per-plane calibration must finish in a separate capture phase before
pressure begins. An IPv6 result always proves blocking, never IPv6 support.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time
from pathlib import Path

import container_host_packets as evidence
from container_host_sender import checksum, dns_query, private_json, publish

SOURCE = "fd99:77::2"
DESTINATION = "fd99::1"
STREAMS = evidence.STREAMS6


def packet(phase, sequence, kind, protocol):
    if (
        not isinstance(phase, str)
        or evidence.PHASE.fullmatch(phase) is None
        or type(sequence) is not int
        or not 1 <= sequence <= evidence.MAX_SEQUENCE
    ):
        raise ValueError("ipv6_identity_invalid")
    if (kind, protocol) not in STREAMS:
        raise ValueError("ipv6_stream_invalid")
    body = (
        dns_query(phase, sequence)
        if kind == "dns"
        else evidence.PREFIX
        + phase.encode("ascii")
        + b":"
        + str(sequence).encode("ascii")
    )
    number = {"udp": 17, "tcp": 6, "icmp6": 58}[protocol]
    port = 30000 + sequence % 10000
    destination_port = 53 if kind == "dns" else 7777 if protocol == "udp" else 7778
    if protocol == "icmp6":
        transport = struct.pack("!BBHHH", 128, 0, 0, 0xE6E6, sequence % 65536) + body
        position = 2
    elif protocol == "udp":
        transport = (
            struct.pack("!HHHH", port, destination_port, len(body) + 8, 0) + body
        )
        position = 6
    else:
        if kind == "dns":
            body = struct.pack("!H", len(body)) + body
        transport = (
            struct.pack(
                "!HHIIBBHHH", port, destination_port, sequence, 0, 0x50, 2, 65535, 0, 0
            )
            + body
        )
        position = 16
    source, destination = (
        ipaddress.IPv6Address(address).packed for address in (SOURCE, DESTINATION)
    )
    pseudo = source + destination + struct.pack("!I3xB", len(transport), number)
    digest = checksum(pseudo + transport) or 65535
    transport = (
        transport[:position] + struct.pack("!H", digest) + transport[position + 2 :]
    )
    return (
        struct.pack("!IHBB", 6 << 28, len(transport), number, 64)
        + source
        + destination
        + transport
    )


def validate_ipv6(
    captures,
    sender,
    *,
    phase,
    required_points,
    sender_points,
    encapsulation_points,
    calibration_phase="calibration6",
    clock_offsets=None,
):
    if (
        not isinstance(encapsulation_points, (tuple, list))
        or not encapsulation_points
        or len(set(encapsulation_points)) != len(encapsulation_points)
        or not set(encapsulation_points) <= set(required_points)
    ):
        raise evidence.EvidenceInvalid("ipv6_encapsulation_inventory_invalid")
    result = evidence.validate_receipts(
        captures,
        sender,
        phase=phase,
        family=6,
        required_points=required_points,
        sender_points=sender_points,
        forbidden_points=tuple(
            point for point in required_points if point not in sender_points
        ),
        calibration_phase=calibration_phase,
        clock_offsets=clock_offsets,
    )
    for point in encapsulation_points:
        receipt = captures[point]
        if not (
            type(receipt.get("wireguard_packets")) is int
            and receipt["wireguard_packets"] > 0
        ):
            raise evidence.EvidenceInvalid("ipv6_encapsulation_not_observed")
    result["family"] = 6
    result["ipv6_forwarding"] = "blocked"
    result["encapsulation_points"] = list(encapsulation_points)
    return result


def _name_index(config):
    name, index = config["interface"], config["ifindex"]
    if (
        not isinstance(name, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) is None
        or type(index) is not int
        or index < 1
        or socket.if_nametoindex(name) != index
    ):
        raise ValueError("ipv6_interface_invalid")
    return name, index


def _namespace_identity():
    facts = os.stat("/proc/self/ns/net")
    return [facts.st_dev, facts.st_ino]


def _require_namespace(expected):
    if (
        not isinstance(expected, list)
        or len(expected) != 2
        or any(type(item) is not int or item <= 0 for item in expected)
        or _namespace_identity() != expected
    ):
        raise ValueError("ipv6_namespace_identity_mismatch")


def _root(config):
    root = Path(config["run_dir"])
    if re.fullmatch(r"/run/exitlane-d6-[a-f0-9]{32}", str(root)) is None:
        raise ValueError("ipv6_directory_invalid")
    root.mkdir(mode=0o700, exist_ok=False)
    return root


def _ethernet(packet_bytes, hardware, source_mac, destination_mac):
    if hardware == 65534:
        if source_mac is not None or destination_mac is not None:
            raise ValueError("ipv6_mac_not_applicable")
        return packet_bytes
    if hardware != 1:
        raise ValueError("ipv6_hardware_unsupported")
    values = []
    for value in (source_mac, destination_mac):
        if (
            not isinstance(value, str)
            or re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value) is None
        ):
            raise ValueError("ipv6_mac_invalid")
        decoded = bytes.fromhex(value.replace(":", ""))
        if decoded == b"\0" * 6 or decoded[0] & 1:
            raise ValueError("ipv6_mac_invalid")
        values.append(decoded)
    return values[1] + values[0] + struct.pack("!H", 0x86DD) + packet_bytes


def _send_checked(raw, name, index, frame):
    try:
        return socket.if_nametoindex(name) == index and raw.send(frame) == len(frame)
    except OSError:
        return False


def _send_calibration(raw, name, index, frame, hardware):
    """ENOKEY can follow an outgoing tap; it explicitly proves no delivery.

    Only the independent collector's five decoded identities establish positive
    calibration. The pressure sender never accepts this downstream rejection.
    """
    import errno

    try:
        if socket.if_nametoindex(name) != index:
            return False, None
        try:
            sent = raw.send(frame)
        except OSError as exc:
            if exc.errno != errno.ENOKEY or hardware != 65534:
                return False, None
            if socket.if_nametoindex(name) != index:
                return False, None
            return True, "wireguard_no_peer"
        return socket.if_nametoindex(name) == index and sent == len(frame), None
    except OSError:
        return False, None


def calibrate(config):
    if set(config) != {
        "mode",
        "interface",
        "ifindex",
        "phase",
        "run_dir",
        "source_mac",
        "destination_mac",
    } and set(config) != {
        "mode",
        "interface",
        "ifindex",
        "phase",
        "run_dir",
        "source_mac",
        "destination_mac",
        "namespace_inode",
    }:
        raise ValueError("ipv6_configuration_invalid")
    phase = config["phase"]
    if not isinstance(phase, str) or evidence.PHASE.fullmatch(phase) is None:
        raise ValueError("ipv6_identity_invalid")
    if "namespace_inode" in config:
        _require_namespace(config["namespace_inode"])
    name, index = _name_index(config)
    hardware = evidence.interface_hardware(name)
    frames = [
        _ethernet(
            packet(phase, 1, *stream),
            hardware,
            config["source_mac"],
            config["destination_mac"],
        )
        for stream in STREAMS
    ]
    root = _root(config)
    receipt = {
        "family": 6,
        "phase": phase,
        "interface": name,
        "ifindex": index,
        "downstream_rejections": [],
        "start_ns": time.time_ns(),
        "end_ns": 0,
        "errors": [],
        "attempts": [],
    }
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD)) as raw:
        raw.bind((name, 0))
        for stream, frame in zip(STREAMS, frames, strict=True):
            emitted, rejection = _send_calibration(raw, name, index, frame, hardware)
            if not emitted:
                receipt["errors"].append("ipv6_send_or_generation_failed")
                break
            if rejection:
                receipt["downstream_rejections"].append(
                    {
                        "kind": stream[0],
                        "protocol": stream[1],
                        "sequence": 1,
                        "reason": rejection,
                        "delivery": False,
                    }
                )
            receipt["attempts"].append(
                {
                    "kind": stream[0],
                    "protocol": stream[1],
                    "phase": phase,
                    "sequence": 1,
                    "source": SOURCE,
                    "destination": DESTINATION,
                    "sent_ns": time.time_ns(),
                }
            )
    receipt["end_ns"] = time.time_ns()
    publish(root / "calibration.json", receipt)
    return int(bool(receipt["errors"]))


def send(config):
    if set(config) != {
        "mode",
        "interface",
        "ifindex",
        "run_dir",
        "deadline_seconds",
        "namespace_inode",
    }:
        raise ValueError("ipv6_configuration_invalid")
    _require_namespace(config["namespace_inode"])
    name, index = _name_index(config)
    if name != "wg-client" or evidence.interface_hardware(name) != 65534:
        raise ValueError("ipv6_client_interface_invalid")
    if Path("/proc/self/ns/net").stat().st_ino == Path("/proc/1/ns/net").stat().st_ino:
        raise ValueError("ipv6_namespace_required")
    if (
        type(config["deadline_seconds"]) is not int
        or not 1 <= config["deadline_seconds"] <= 3600
    ):
        raise ValueError("ipv6_deadline_invalid")
    root = _root(config)
    deadline = time.monotonic() + config["deadline_seconds"]
    receipt = {
        "family": 6,
        "phase": None,
        "start_ns": 0,
        "end_ns": 0,
        "errors": [],
        "attempts": [],
    }
    counters = {}
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD)) as raw:
        raw.bind((name, 0))
        while time.monotonic() < deadline:
            control = (
                private_json(root / "control.json")
                if (root / "control.json").exists()
                else None
            )
            if control is None:
                time.sleep(0.05)
                continue
            if (
                not isinstance(control, dict)
                or set(control) != {"phase", "stop"}
                or not isinstance(control["phase"], str)
                or evidence.PHASE.fullmatch(control["phase"]) is None
                or type(control["stop"]) is not bool
            ):
                raise ValueError("ipv6_control_invalid")
            if control["stop"]:
                break
            if control["phase"] != receipt["phase"]:
                receipt = {
                    "family": 6,
                    "phase": control["phase"],
                    "start_ns": time.time_ns(),
                    "end_ns": 0,
                    "errors": [],
                    "attempts": [],
                }
                counters = dict.fromkeys(STREAMS, 0)
            for stream in STREAMS:
                counters[stream] += 1
                data = packet(receipt["phase"], counters[stream], *stream)
                if not _send_checked(raw, name, index, data):
                    receipt["errors"].append("ipv6_send_or_generation_failed")
                    receipt["end_ns"] = time.time_ns()
                    publish(root / "sender.json", receipt)
                    return 1
                receipt["attempts"].append(
                    {
                        "kind": stream[0],
                        "protocol": stream[1],
                        "phase": receipt["phase"],
                        "sequence": counters[stream],
                        "source": SOURCE,
                        "destination": DESTINATION,
                        "sent_ns": time.time_ns(),
                    }
                )
            receipt["end_ns"] = time.time_ns()
            if len(receipt["attempts"]) > evidence.MAX_RECORDS:
                raise ValueError("ipv6_record_limit")
            publish(root / "sender.json", receipt)
            time.sleep(0.25)
    time.sleep(0.5)  # Bounded observer drain, included in the actual proof window.
    receipt["end_ns"] = time.time_ns()
    if time.monotonic() >= deadline:
        receipt["errors"].append("ipv6_deadline_exceeded")
    publish(root / "sender.json", receipt)
    return int(bool(receipt["errors"]))


def main():
    try:
        if os.geteuid() != 0:
            raise ValueError("ipv6_root_required")
        os.umask(0o077)
        data = sys.stdin.buffer.read(8193)
        if len(data) > 8192:
            raise ValueError("ipv6_configuration_invalid")
        config = json.loads(data)
        if not isinstance(config, dict):
            raise TypeError("ipv6_configuration_invalid")
        if config.get("mode") == "send":
            return send(config)
        if config.get("mode") == "calibrate":
            return calibrate(config)
        raise ValueError("ipv6_mode_invalid")
    except Exception:  # noqa: BLE001 - fixed diagnostics, no config or exception representation
        print("D6 IPv6 evidence failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
