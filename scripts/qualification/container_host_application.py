"""Actual socket round trips inside the owned synthetic client namespace.

Raw SYN packet isolation is complementary evidence; it does not prove successful
TCP application delivery. This component records UDP/TCP echo and DNS UDP/TCP
answers while the independently calibrated numbered traffic remains continuous.
No host routes, credentials or application lifecycle implementation are changed.
"""
from __future__ import annotations

import json
import secrets

from container_host_providers import DIRECT, ProviderQualification

PROGRAM = "import socket,struct,json\nq=struct.pack('!HHHHHH',4660,256,1,0,0,0)+bytes.fromhex('047465737407696e76616c69640000010001')\nr={}\nfor protocol,port in [('udp',7777),('tcp',7778),('dns_udp',53),('dns_tcp',53)]:\n try:\n  b=q if protocol.startswith('dns') else b'synthetic-d6-application-proof'\n  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if protocol.endswith('udp') or protocol=='udp' else socket.SOCK_STREAM);s.settimeout(3);s.connect(('1.1.1.1',port))\n  s.send(struct.pack('!H',len(b))+b if protocol=='dns_tcp' else b)\n  if protocol=='dns_tcp':\n   n=struct.unpack('!H',s.recv(2))[0];body=b''\n   while len(body)<n:body+=s.recv(n-len(body))\n  else:body=s.recv(1024)\n  r[protocol]=body[:2]==q[:2] and body[-4:]==bytes([1,1,1,1]) if protocol.startswith('dns') else body==b;s.close()\n except Exception as e:r[protocol]=type(e).__name__\nprint(json.dumps(r))\n"


class ApplicationEvidenceError(RuntimeError):
    pass


def qualify(harness, captures, *, provider, receipts):
    if provider not in DIRECT:
        raise ApplicationEvidenceError('application_provider_invalid')
    proof = ProviderQualification(harness, captures, receipts=receipts)
    proof._authorized()
    if not proof._selected(provider, True):
        raise ApplicationEvidenceError('application_connected_baseline_required')
    ownership = json.loads(proof._command(harness.peer,
        ['/usr/bin/python3', '/var/lib/exitlane-qualification/container_host_peer.py', 'ownership'],
        data=json.dumps({'run_id': harness.config['run_id'], 'role': 'client'})))
    namespace = 'ed6-' + harness.config['run_id'].replace('-', '')[:10] + '-client'
    if ownership.get('run_id') != harness.config['run_id'] or ownership.get('namespace') != namespace:
        raise ApplicationEvidenceError('application_namespace_ownership_invalid')
    pinned = ownership.get('namespace_inode')
    if not isinstance(pinned, list) or len(pinned) != 2 or any(type(item) is not int or item <= 0 for item in pinned):
        raise ApplicationEvidenceError('application_namespace_ownership_invalid')
    guard = ("from pathlib import Path\n"
             + "facts=Path('/proc/self/ns/net').stat()\n"
             + "if [facts.st_dev,facts.st_ino] != " + repr(pinned)
             + ":raise SystemExit('application_namespace_changed')\n")
    phase = 'application-' + provider + '-' + secrets.token_hex(4)
    metadata = {'phase': phase, 'provider': provider, 'result': 'RUNNING',
                'full_d6_result': 'OUTSTANDING'}
    receipts.write(phase + '-metadata.json', metadata)
    def operation():
        result = json.loads(proof._command(harness.peer,
            ['ip', 'netns', 'exec', namespace, 'python3', '-'], data=guard + PROGRAM))
        if set(result) != {'udp', 'tcp', 'dns_udp', 'dns_tcp'}:
            raise ApplicationEvidenceError('application_protocol_inventory_invalid')
        # Failures contain exception type only, not remote data or addresses.
        receipts.write(phase + '-roundtrips.json', result)
        if any(value is not True for value in result.values()):
            raise ApplicationEvidenceError('application_roundtrip_failed')
    try:
        result = harness.packet_phase(phase, captures, operation=operation)
        receipt = result.get('receipt') if isinstance(result, dict) else None
        if (not isinstance(receipt, dict) or receipt.get('accepted') is not True
                or receipt.get('phase') != phase
                or receipt.get('expected_state') != 'provider_or_block_with_fresh_recovery'):
            raise ApplicationEvidenceError('application_packet_proof_unproven')
        metadata.update(result='PACKET_COMPONENT_PASS', packets=receipts.write(phase + '-packets.json', result))
        receipts.write(phase + '-metadata.json', metadata)
        return metadata
    except BaseException:  # noqa: BLE001 -- retain interrupted proof without private exception text
        metadata['result'] = 'FAILED'
        receipts.write(phase + '-metadata.json', metadata)
        raise ApplicationEvidenceError('application_component_failed') from None
