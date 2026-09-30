#!/usr/bin/env python3
"""Read-only, bounded synthetic packet observer; never part of the appliance.

Run in a test-owned network namespace with NET_RAW only. Records only marked
qualification traffic and WireGuard outer metadata, without configuration keys.
"""
from __future__ import annotations

import http.server
import json
import os
import select
import socket
import struct
import sys
import threading
import time

PREFIX = b"exitlane-d3-protected-"
LIMIT = 16 * 1024 * 1024


def classify(packet: bytes, *, ethernet=True):
    """Handle Ethernet and raw-IP WireGuard frames, excluding cipher payloads."""
    if len(packet) < 20:
        return None
    offset = 14 if ethernet else 0
    if len(packet) <= offset:
        return None
    version = packet[offset] >> 4
    if version == 4:
        length = (packet[offset] & 15) * 4
        if length < 20 or len(packet) < offset + length:
            return None
        protocol = packet[offset + 9]
        # Fragmented datagrams cannot prove a complete marker.
        if struct.unpack_from("!H", packet, offset + 6)[0] & 0x3FFF:
            return None
        offset += length
    elif version == 6:
        if len(packet) < offset + 40:
            return None
        protocol = packet[offset + 6]
        offset += 40
    else:
        return None
    if protocol not in (6, 17) or len(packet) < offset + 8:
        return None
    source, destination = struct.unpack_from("!HH", packet, offset)
    if protocol == 17:
        payload = packet[offset + 8:]
        if destination == 7777 and payload.startswith(PREFIX):
            phase = payload[len(PREFIX):].split(b":", 1)[0]
            if phase and len(phase) <= 64 and all(c in b"abcdefghijklmnopqrstuvwxyz0123456789-_" for c in phase):
                return "markers", phase.decode("ascii")
        if source == 51820 or destination == 51820:
            return "encrypted", None
    else:
        if len(packet) < offset + 20:
            return None
        size = (packet[offset + 12] >> 4) * 4
        if size < 20:
            return None
        payload = packet[offset + size:]
        if destination == 7778 and payload.startswith(PREFIX):
            phase = payload[len(PREFIX):].split(b":", 1)[0]
            if phase and len(phase) <= 64 and all(c in b"abcdefghijklmnopqrstuvwxyz0123456789-_" for c in phase):
                return "markers", phase.decode("ascii")
    if (source == 53 or destination == 53) and (b"eld3-" in payload or b"exitlane-d3-" in payload):
        return "dns", None
    return None


class Capture:
    def __init__(self, interfaces):
        self.interfaces = tuple(interfaces)
        self.facts = {name: {"markers": {}, "dns": 0, "encrypted": 0} for name in interfaces}
        self.drops = 0
        self.errors = set()
        self.lock = threading.Lock()
        self.sockets = {}
        self.active = {}
        self.last_poll = 0.0
        self.polls = 0
        self.failed = False
        os.umask(0o077)
        # Owned for the observer's entire bounded process lifetime.
        self.file = open("/run/d3-capture.pcap", "xb", buffering=0)  # noqa: SIM115
        # Linux cooked capture: preserve protocol/type for mixed Ethernet/WG.
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 2048, 113))
        self.size = 24

    def statistics(self, sock):
        try:
            _, dropped = struct.unpack("II", sock.getsockopt(263, 6, 8))
            with self.lock:
                self.drops += dropped
        except OSError:
            with self.lock:
                self.errors.add("packet_statistics_unavailable")

    def run(self):
        try:
            self.observe()
        except Exception:  # noqa: BLE001 - every unexpected observer failure invalidates evidence
            # HTTP must never turn a dead capture worker into false zero proof.
            with self.lock:
                self.failed = True
                self.errors.add("capture_worker_failed")

    def observe(self):
        while True:
            for name in self.interfaces:
                try:
                    index = socket.if_nametoindex(name)
                except OSError:
                    index = None
                current = self.sockets.get(name)
                if current and current[0] != index:
                    self.statistics(current[1])
                    current[1].close()
                    del self.sockets[name]
                if index is not None and name not in self.sockets:
                    try:
                        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                        sock.bind((name, 0))
                        sock.setblocking(False)
                        self.sockets[name] = index, sock
                    except OSError:
                        with self.lock:
                            self.errors.add("capture_socket_failed:" + name)
            readers = [item[1] for item in self.sockets.values()]
            ready, _, _ = select.select(readers, [], [], 0.1)
            for sock in readers:
                self.statistics(sock)
            with self.lock:
                self.active = {name: item[0] for name, item in self.sockets.items()}
                self.last_poll = time.monotonic()
                self.polls += 1
            for sock in ready:
                try:
                    packet, address = sock.recvfrom(65535)
                except OSError:
                    continue
                kind = classify(packet, ethernet=address[3] == 1)
                if kind is None:
                    continue
                name, protocol, packet_type, hardware_type, hardware_address = address
                with self.lock:
                    category, phase = kind
                    if category == "markers":
                        counters = self.facts[name][category]
                        if phase not in counters and len(counters) >= 128:
                            self.errors.add("capture_phase_limit")
                            continue
                        counters[phase] = counters.get(phase, 0) + 1
                    else:
                        self.facts[name][category] += 1
                    # Root-only bounded pcap contains exclusively synthetic data.
                    body = packet if hardware_type != 1 else packet[14:]
                    cooked = struct.pack("!HHH8sH", packet_type, hardware_type,
                                         min(len(hardware_address), 8), hardware_address[:8].ljust(8, b"\0"), protocol)
                    stamp = time.time()
                    data = cooked + body[:2032]
                    record = struct.pack("<IIII", int(stamp), int(stamp % 1 * 1_000_000), len(data), len(cooked) + len(body)) + data
                    if self.size + len(record) > LIMIT:
                        self.errors.add("capture_size_limit")
                    else:
                        self.file.write(record)
                        self.size += len(record)

    def snapshot(self):
        with self.lock:
            return json.dumps({"ready": bool(self.active) and not self.failed and time.monotonic() - self.last_poll < 1,
                               "active_interfaces": self.active, "polls": self.polls,
                               "interfaces": self.facts,
                               "drops": self.drops, "capture_errors": sorted(self.errors)}).encode()


def main():
    names = sys.argv[1:]
    if not names or len(names) > 12 or len(set(names)) != len(names):
        raise SystemExit("invalid capture interface selection")
    for name in names:
        if not name or len(name) > 15 or not all(c.isalnum() or c in "-_" for c in name):
            raise SystemExit("invalid capture interface selection")
    capture = Capture(names)
    threading.Thread(target=capture.run, daemon=True).start()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            payload = capture.snapshot()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    http.server.HTTPServer(("127.0.0.1", 8991), Handler).serve_forever()


if __name__ == "__main__":
    main()
