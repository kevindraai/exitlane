#!/usr/bin/env python3
"""Prepared D6 IPv6 component. No automatic retry and no whole-D6 support claim."""
import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
from container_host import IMAGE, HostHarness, QualificationError
from container_host_ipv6 import STREAMS
from container_host_matrix import Receipts, private_json, validate_handles

PEER_ROOT = '/var/lib/exitlane-qualification'

LINK_FACTS_PROGRAM = '''from pathlib import Path
import json,subprocess,sys
v=json.load(sys.stdin);facts=Path('/proc/self/ns/net').stat()
links=json.loads(subprocess.run(['ip','-j','link','show','dev',v['interface']],check=True,capture_output=True,text=True).stdout)
if len(links)!=1 or links[0]['ifname']!=v['interface']:raise SystemExit('ipv6_calibration_interface_invalid')
print(json.dumps({'namespace_inode':[facts.st_dev,facts.st_ino],'ifindex':links[0]['ifindex'],'mac':links[0].get('address'),'link_type':links[0]['link_type']}))
'''


def handles(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        f = os.fstat(stream.fileno())
        if not stat.S_ISREG(f.st_mode) or f.st_uid != 0 or stat.S_IMODE(f.st_mode) != 0o600 or f.st_size > 131072:
            raise QualificationError('ipv6_handles_unsafe')
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise QualificationError('ipv6_handles_unsafe')
    value = json.loads(raw)
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {'captures': value}
    raise QualificationError('ipv6_handles_invalid')


def archive(h, handle):
    """Stop is caller-owned; preserve raw old capture files without changing them."""
    return json.loads(h.peer.run('''from pathlib import Path
import hashlib,stat,shutil
root=Path(payload['root']);f=root.lstat()
if not stat.S_ISDIR(f.st_mode) or f.st_uid!=0 or stat.S_IMODE(f.st_mode)!=0o700:raise SystemExit('ipv6_archive_unsafe')
parent=Path('/var/lib/exitlane-qualification/epochs')
if parent.is_symlink():raise SystemExit('ipv6_archive_unsafe')
parent.mkdir(mode=0o700,exist_ok=True)
f=parent.lstat()
if not stat.S_ISDIR(f.st_mode) or f.st_uid!=0 or stat.S_IMODE(f.st_mode)!=0o700:raise SystemExit('ipv6_archive_unsafe')
destination=parent/(root.name+'-ipv6-'+str(time.time_ns()));destination.mkdir(mode=0o700,exist_ok=False)
result={}
for entry in root.iterdir():
 if entry.name not in {'control.json','receipts.json'} and not entry.name.endswith('.pcap'):continue
 fd=os.open(entry,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as source:
  f=os.fstat(source.fileno())
  if not stat.S_ISREG(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077 or f.st_size>256*1024*1024:raise SystemExit('ipv6_archive_unsafe')
  target=destination/entry.name
  outfd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  digest=hashlib.sha256();size=0
  with os.fdopen(outfd,'wb') as out:
   while chunk:=source.read(1024*1024):
    size+=len(chunk)
    if size>256*1024*1024:raise SystemExit('ipv6_archive_unsafe')
    out.write(chunk);digest.update(chunk)
   out.flush();os.fsync(out.fileno())
  result[entry.name]={'sha256':digest.hexdigest(),'bytes':size}
if 'receipts.json' not in result:raise SystemExit('ipv6_archive_missing')
print(json.dumps({'archive':str(destination),'files':result}))
''', data=handle, timeout=90))


def upload(h, filename, receipts):
    source = (BASE / filename).read_text()
    compile(source, filename, 'exec')
    result = json.loads(h.peer.run('''from pathlib import Path
import stat,hashlib
root=Path('/var/lib/exitlane-qualification');f=root.lstat()
if not stat.S_ISDIR(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077:raise SystemExit('ipv6_upload_unsafe')
p=root/payload['filename'];previous=None
if os.path.lexists(p):
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as stream:
  f=os.fstat(stream.fileno())
  if not stat.S_ISREG(f.st_mode) or f.st_uid!=0 or stat.S_IMODE(f.st_mode)!=0o600 or f.st_size>1024*1024:raise SystemExit('ipv6_upload_unsafe')
  old=stream.read(1024*1024+1)
 if len(old)>1024*1024:raise SystemExit('ipv6_upload_unsafe')
 previous=hashlib.sha256(old).hexdigest()
 backup=root/(payload['filename']+'.before-ipv6-'+payload['nonce'])
 fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(old);stream.flush();os.fsync(stream.fileno())
new=root/('.ipv6-upload-'+payload['nonce'])
fd=os.open(new,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as stream:stream.write(payload['source']);stream.flush();os.fsync(stream.fileno())
os.replace(new,p)
print(json.dumps({'filename':payload['filename'],'previous':previous,'sha256':hashlib.sha256(payload['source'].encode()).hexdigest()}))
''', data={'filename': filename, 'source': source, 'nonce': secrets.token_hex(8)}))
    receipts.write('source-' + filename.replace('.', '-') + '.json', result)


def _mac_for_link(link_type, address):
    if link_type == 'none':
        return None
    if link_type != 'ether' or not isinstance(address, str) or re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', address) is None:
        raise QualificationError('ipv6_calibration_hardware_invalid')
    return address


def calibrate(h, capture, interface, receipts, nonce):
    namespace = capture['namespace']
    prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
    ownership = None
    if namespace:
        role = namespace.rsplit('-', 1)[-1]
        ownership = json.loads(h.command(h.peer, ['python3', PEER_ROOT + '/container_host_peer.py', 'ownership'],
            data=json.dumps({'run_id': h.config['run_id'], 'role': role}))['stdout'])
        if ownership.get('run_id') != h.config['run_id'] or ownership.get('namespace') != namespace:
            raise QualificationError('ipv6_calibration_ownership_invalid')
    facts = json.loads(h.command(h.peer, prefix + ['python3', '-c', LINK_FACTS_PROGRAM],
                                 data=json.dumps({'interface': interface}))['stdout'])
    if ownership and (facts['namespace_inode'] != ownership['namespace_inode'] or facts['ifindex'] != ownership['interface_ifindexes'].get(interface)):
        raise QualificationError('ipv6_calibration_ownership_invalid')
    if facts['link_type'] not in {'ether', 'none'}:
        raise QualificationError('ipv6_calibration_hardware_invalid')
    mac = _mac_for_link(facts['link_type'], facts.get('mac'))
    config = {'mode': 'calibrate', 'interface': interface, 'ifindex': facts['ifindex'],
        'namespace_inode': facts['namespace_inode'], 'phase': 'calibration6',
        'run_dir': '/run/exitlane-d6-' + secrets.token_hex(16), 'source_mac': mac, 'destination_mac': mac}
    command_result = h.command(h.peer, prefix + ['python3', PEER_ROOT + '/container_host_ipv6.py'],
                               data=json.dumps(config), check=False)
    if command_result.get('code') != 0:
        artifact = h.peer.run('''from pathlib import Path
import json,os,stat
root=Path(payload['root']);out={'directory_exists':False,'calibration_exists':False,'files':[]}
try:
 f=root.lstat()
 if not stat.S_ISDIR(f.st_mode) or f.st_uid!=0 or stat.S_IMODE(f.st_mode)!=0o700:raise SystemExit('ipv6_calibration_artifact_unsafe')
 out['directory_exists']=True;out['files']=sorted(x.name for x in root.iterdir())
 p=root/'calibration.json'
 if p.exists():
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd) as stream:
   f=os.fstat(stream.fileno())
   if not stat.S_ISREG(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077 or f.st_size>16384:raise SystemExit('ipv6_calibration_artifact_unsafe')
   x=json.loads(stream.read(16385))
  out['calibration_exists']=True;out['errors']=x.get('errors');out['attempts']=[{'kind':a.get('kind'),'protocol':a.get('protocol')} for a in x.get('attempts',[])];out['downstream_rejections']=[{'kind':a.get('kind'),'protocol':a.get('protocol'),'reason':a.get('reason')} for a in x.get('downstream_rejections',[])]
except FileNotFoundError:pass
print(json.dumps(out))''', data={'root':config['run_dir']})
        receipts.write('calibration-helper-failure-' + capture['role'] + '-' + interface + '.json', {
            'role':capture['role'],'interface':interface,'exit_code':command_result.get('code'),
            'stderr_sha256':__import__('hashlib').sha256(command_result.get('stderr','').encode()).hexdigest(),
            'fixed_stderr':command_result.get('stderr','').strip() == 'D6 IPv6 evidence failed.',
            'remote_artifact':json.loads(artifact)})
        raise QualificationError('ipv6_calibration_helper_failed')
    value = json.loads(h.peer.run('''from pathlib import Path
import stat
p=Path(payload)/'calibration.json';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd) as stream:
 f=os.fstat(stream.fileno())
 if not stat.S_ISREG(f.st_mode) or f.st_uid!=0 or f.st_mode&0o077 or f.st_size>16384:raise SystemExit('ipv6_calibration_receipt_unsafe')
 print(stream.read(16385))
''', data=config['run_dir']))
    if value.get('errors') != [] or len(value.get('attempts', [])) != 5 or value.get('ifindex') != facts['ifindex']:
        raise QualificationError('ipv6_calibration_injection_invalid')
    receipts.write('calibration-' + capture['role'] + '-' + interface + '-' + nonce + '.json', {'facts': facts, 'injector': value})
    def observed():
        evidence = h.evidence(capture)
        actual = evidence['captures'].get(interface)
        return evidence.get('phase') == 'calibration6' and actual and set(STREAMS) <= {
            (s['kind'], s['protocol']) for s in actual['calibration']}
    h.wait(observed, 'ipv6-' + capture['role'] + '-' + interface + '-positive', timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--captures', type=Path, required=True)
    parser.add_argument('--expected-image', required=True)
    parser.add_argument('--receipts-dir', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or IMAGE.fullmatch(args.expected_image) is None:
        raise QualificationError('ipv6_root_image_required')
    os.umask(0o077)
    h = HostHarness(private_json(args.config))
    value = handles(args.captures)
    captures = value.get('captures')
    validate_handles({'run_id': value.get('run_id', h.config['run_id']), 'captures': captures, 'candidate_epochs': []}, h.config['run_id'])
    if any(c.get('family', 4) not in {4, 6} for c in captures) or len({c.get('family', 4) for c in captures}) != 1:
        raise QualificationError('ipv6_old_capture_family_invalid')
    receipts = Receipts(args.receipts_dir)
    metadata = {'result': 'RUNNING', 'full_d6_result': 'OUTSTANDING', 'production_supported': False,
        'run_id': h.config['run_id'], 'image': args.expected_image, 'claim': 'IPv6-attempt blocking; opaque WG presence is not per-attempt encapsulation proof'}
    with receipts.lock():
        if os.path.lexists(receipts.root / 'ipv6-metadata.json'):
            raise QualificationError('ipv6_previous_attempt_requires_inspection')
        receipts.write('ipv6-metadata.json', metadata)
        try:
            h.assert_disposable()
            if h.assert_owned('container', h.container)['Image'] != args.expected_image:
                raise QualificationError('ipv6_image_changed')
            receipts.write('previous-retained-handles.json', {'captures': captures})
            for c in captures:
                receipts.write('previous-' + c['role'] + '-before.json', h.evidence(c))
                old_phase = h.evidence(c)['phase']
                h.control(c, old_phase, stop=True)
                h.wait(lambda c=c: h.command(h.peer, ['systemctl', 'show', c['unit'], '--property=SubState', '--value'])['stdout'].strip() in {'dead', 'failed'}, 'previous-' + c['role'] + '-stopped', timeout=15)
                receipts.write('previous-' + c['role'] + '-final.json', h.evidence(c))
                receipts.write('previous-' + c['role'] + '-archive.json', archive(h, c))
            for filename in ('container_host_packets.py', 'container_host_sender.py', 'container_host_ipv6.py'):
                upload(h, filename, receipts)
            ns = 'ed6-' + h.config['run_id'].replace('-', '')[:10] + '-'
            new = [h.external_process('capture', 'wan', interfaces=('eth0',), family=6)]
            for role, suffix in [('client', 'client'), ('provider-a', 'a'), ('provider-b', 'b')]:
                new.append(h.external_process('capture', role, interfaces=('wg-client' if role == 'client' else 'wg-peer',), namespace=ns + suffix, family=6))
            new.append(h.external_process('capture', 'target', interfaces=('pa', 'pb', 'uplink'), namespace=ns + 'target', family=6))
            receipts.write('ipv6-handles.json', {'run_id': h.config['run_id'], 'captures': new, 'candidate_epochs': []})
            for c in new:
                h.control(c, 'calibration6', calibration_phase='calibration6')
                h.wait(lambda c=c: h.evidence(c).get('phase') == 'calibration6' and all(f['ready'] and f['polls'] >= 2 for f in h.evidence(c)['captures'].values()), 'ipv6-' + c['role'] + '-ready', timeout=15)
            nonce = secrets.token_hex(4)
            for c in new:
                for interface in c['interfaces']:
                    metadata['stage'] = 'calibration-' + c['role'] + '-' + interface
                    receipts.write('ipv6-metadata.json', metadata)
                    calibrate(h, c, interface, receipts, nonce)
            final = {c['role']: h.evidence(c) for c in new}
            receipts.write('ipv6-calibration.json', final)
            for evidence in final.values():
                for facts in evidence['captures'].values():
                    if facts['errors'] or facts['drops'] or facts['invalid_packets'] or facts['gaps']:
                        raise QualificationError('ipv6_calibration_invalid')
            phase = 'ipv6-blocked-' + secrets.token_hex(4)
            result = h.packet_phase(phase, new, blocked=True, require_recovery=False, family=6)
            receipt = result.get('receipt', {})
            if receipt.get('accepted') is not True or receipt.get('phase') != phase or receipt.get('expected_state') != 'ipv6_blocked':
                raise QualificationError('ipv6_packet_proof_invalid')
            metadata.update(result='PACKET_COMPONENT_PASS', phase=phase, packets=receipts.write('ipv6-packets.json', result))
            receipts.write('ipv6-metadata.json', metadata)
            print(json.dumps({'result': 'PARTIAL', 'ipv6': 'PACKET_COMPONENT_PASS', 'full_d6_result': 'OUTSTANDING', 'receipts': str(receipts.root)}))
        except BaseException:
            metadata.update(result='FAILED', error='ipv6_component_failed', failed_stage=metadata.get('stage'))
            receipts.write('ipv6-metadata.json', metadata)
            raise


if __name__ == '__main__':
    try:
        main()
    except BaseException:  # noqa: BLE001 -- redact private host/packet state at CLI boundary
        print('IPv6 component failed; inspect private retained evidence.', file=sys.stderr)
        raise SystemExit(1) from None
