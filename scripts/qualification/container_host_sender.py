#!/usr/bin/env python3
"""Numbered synthetic D6 pressure, only in a disposable fixture namespace.

Raw sockets belong to this external qualification process, never ExitLane's
NET_ADMIN-only container. Valid SYN-with-data makes TCP attempts observable even
when the protected path is blocked before a handshake can complete. Application
TCP/DNS success is checked separately; these packets prove forwarding isolation.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import stat
import struct
import sys
import time
from pathlib import Path

PREFIX = b'exitlane-d6-protected-'
PHASE = re.compile(r'[a-z][a-z0-9_-]{0,39}\Z')
STREAMS = (('protected', 'udp'), ('protected', 'tcp'), ('protected', 'icmp'),
           ('dns', 'udp'), ('dns', 'tcp'))


def checksum(value):
    value += b'\0' * (len(value) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(value) // 2), value))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def dns_query(phase, sequence):
    name = f'eld6-{phase}-{sequence}.example.test'
    question = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.'))
    return struct.pack('!HHHHHH', sequence % 65536, 0x100, 1, 0, 0, 0) + question + b'\0\0\1\0\1'


def packet(source, phase, sequence, kind, protocol, *, dns='1.1.1.1'):
    if PHASE.fullmatch(phase) is None or type(sequence) is not int or not 1 <= sequence <= 2**31 - 1:
        raise ValueError('sender_identity_invalid')
    if (kind, protocol) not in STREAMS:
        raise ValueError('sender_stream_invalid')
    source = ipaddress.IPv4Address(source).packed
    destination = ipaddress.IPv4Address(dns if kind == 'dns' else '1.1.1.1').packed
    body = dns_query(phase, sequence) if kind == 'dns' else PREFIX + phase.encode() + b':' + str(sequence).encode()
    number = {'udp': 17, 'tcp': 6, 'icmp': 1}[protocol]
    source_port = 30000 + sequence % 10000
    destination_port = 53 if kind == 'dns' else 7777 if protocol == 'udp' else 7778
    if protocol == 'icmp':
        transport = struct.pack('!BBHHH', 8, 0, 0, 0xE6E6, sequence % 65536) + body
        transport = transport[:2] + struct.pack('!H', checksum(transport)) + transport[4:]
    else:
        if protocol == 'udp':
            transport = struct.pack('!HHHH', source_port, destination_port, 8 + len(body), 0) + body
            position = 6
        else:
            if kind == 'dns':
                body = struct.pack('!H', len(body)) + body
            transport = struct.pack('!HHIIBBHHH', source_port, destination_port, sequence, 0,
                                    0x50, 2, 65535, 0, 0) + body
            position = 16
        pseudo = source + destination + struct.pack('!BBH', 0, number, len(transport))
        digest = checksum(pseudo + transport) or 65535
        transport = transport[:position] + struct.pack('!H', digest) + transport[position + 2:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(transport), sequence % 65536,
                         0, 64, number, 0, source, destination)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return header + transport


def private_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        facts = os.fstat(descriptor)
        if (not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0
                or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_size > 4096):
            raise ValueError('sender_control_unsafe')
        with os.fdopen(descriptor) as stream:
            descriptor = None
            return json.load(stream)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def publish(path, value):
    temporary = path.parent / '.sender.new'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary, path)


def run(config):
    if not isinstance(config, dict) or set(config) != {'source', 'interface', 'run_dir', 'deadline_seconds', 'dns', 'namespace_inode', 'ifindex'}:
        raise ValueError('sender_configuration_invalid')
    address = ipaddress.IPv4Address(config['source'])
    if not address.is_private or address.is_loopback or address.is_unspecified:
        raise ValueError('sender_source_invalid')
    if config['interface'] != 'wg-client' or config['dns'] not in {'1.1.1.1', '10.64.0.1', '10.65.0.1', '10.66.0.1'}:
        raise ValueError('sender_configuration_invalid')
    if type(config['deadline_seconds']) is not int or not 1 <= config['deadline_seconds'] <= 3600:
        raise ValueError('sender_deadline_invalid')
    if Path('/proc/self/ns/net').stat().st_ino == Path('/proc/1/ns/net').stat().st_ino:
        raise ValueError('sender_namespace_required')
    inode = config['namespace_inode']
    current = Path('/proc/self/ns/net').stat()
    if (not isinstance(inode, list) or len(inode) != 2
            or any(type(v) is not int or v <= 0 for v in inode)
            or [current.st_dev, current.st_ino] != inode
            or type(config['ifindex']) is not int or config['ifindex'] <= 0
            or socket.if_nametoindex('wg-client') != config['ifindex']):
        raise ValueError('sender_namespace_ownership_invalid')
    root = Path(config['run_dir'])
    if re.fullmatch(r'/run/exitlane-d6-[a-f0-9]{32}', str(root)) is None:
        raise ValueError('sender_directory_invalid')
    root.mkdir(mode=0o700, exist_ok=False)
    receipt = {'phase': None, 'start_ns': 0, 'end_ns': 0, 'errors': [], 'attempts': []}
    deadline = time.monotonic() + config['deadline_seconds']
    counters = {}
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, config['interface'].encode() + b'\0')
        while time.monotonic() < deadline:
            control = private_json(root / 'control.json') if (root / 'control.json').exists() else None
            if control is None:
                time.sleep(.05)
                continue
            if set(control) != {'phase', 'stop'} or PHASE.fullmatch(control['phase']) is None or type(control['stop']) is not bool:
                raise ValueError('sender_control_invalid')
            if control['stop']:
                break
            if control['phase'] != receipt['phase']:
                receipt = {'phase': control['phase'], 'start_ns': time.time_ns(), 'end_ns': 0,
                           'errors': [], 'attempts': []}
                counters = {stream: 0 for stream in STREAMS}
            for stream in STREAMS:
                counters[stream] += 1
                raw = packet(str(address), receipt['phase'], counters[stream], *stream, dns=config['dns'])
                try:
                    client.sendto(raw, (config['dns'] if stream[0] == 'dns' else '1.1.1.1', 0))
                except OSError:
                    receipt['errors'].append('sender_send_failed')
                    publish(root / 'sender.json', receipt)
                    return 1
                receipt['attempts'].append({'kind': stream[0], 'protocol': stream[1],
                    'phase': receipt['phase'], 'sequence': counters[stream], 'sent_ns': time.time_ns()})
            receipt['end_ns'] = time.time_ns()
            if len(receipt['attempts']) > 100000:
                raise ValueError('sender_record_limit')
            publish(root / 'sender.json', receipt)
            time.sleep(.25)
    # Include a bounded drain interval in the historical phase window. The
    # coordinator must keep observers alive through this interval.
    time.sleep(.5)
    receipt['end_ns'] = time.time_ns()
    if time.monotonic() >= deadline:
        receipt['errors'].append('sender_deadline_exceeded')
    publish(root / 'sender.json', receipt)
    return int(bool(receipt['errors']))


def main():
    try:
        if os.geteuid() != 0:
            raise ValueError('sender_root_required')
        os.umask(0o077)
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError('sender_configuration_invalid')
        return run(json.loads(raw))
    except Exception:  # noqa: BLE001 - every sender error invalidates packet evidence
        print('D6 sender failed; packet evidence is invalid.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
