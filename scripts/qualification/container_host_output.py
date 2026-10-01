"""Bounded D6 locally originated OUTPUT proof, not a complete D6 verdict.

An external root injector enters an opened, pinned appliance network namespace;
production receives no additional capability. No SO_BINDTODEVICE, route/state
write or firewall edit makes the desired result true. Source receipts originate
from a validated persisted ACTIVE generation and must be captured by this same
coordinator before becoming retired. All five regular/source-bound probes run
without external client pressure. Empty TCP SYN/RST and quoted ICMP are checked
in raw PCAP too: payload-marker zeros alone are never accepted.

PCAP originals remain at the supplied root-only capture handles and their hashes
are retained. The caller must retain/archive those owned artifacts before guest
cleanup. Positive calibration must already exist for every observer generation.
This component covers explicit outbound probes, not every kernel reply form.
"""
from __future__ import annotations

import errno
import hashlib
import inspect
import ipaddress
import json
import os
import re
import socket
import struct
import time
import uuid
from pathlib import Path

from container_host_packets import _clock_alignment
from container_host_sender import STREAMS, checksum, dns_query, packet

SOURCES = {'mullvad': '10.64.0.2', 'pia': '10.65.0.2', 'proton': '10.66.0.2'}
DESTINATIONS = {'1.1.1.1', '10.64.0.1', '10.65.0.1', '10.66.0.1'}
PORTS = {53, 7777, 7778}
KNOWN_FAILURES = frozenset({
    'output_attempts_missing', 'output_attempts_invalid', 'output_topology_incomplete',
    'output_capture_invalid', 'output_capture_window_gap', 'output_calibration_missing',
    'output_plaintext_detected', 'output_positive_delivery_missing', 'output_namespace_unproven',
    'output_phase_changed', 'output_phase_reused', 'output_clock_changed', 'output_pcap_invalid',
    'output_fragment_unproven', 'output_pcap_record_limit', 'output_handle_invalid',
    'output_delivery_invalid', 'output_syscall_unproven', 'output_injector_invalid',
    'output_sample_invalid', 'output_link_unsupported', 'output_unmarked_calibration_missing', 'output_image_changed',
})
LIMIT = 32 * 1024 * 1024
REFUSALS = {errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH,
            errno.EADDRNOTAVAIL, errno.ECONNREFUSED, errno.ETIMEDOUT}
PUBLIC_STATE = '''import json,subprocess
from pathlib import Path
from exitlane.container_state import ContainerState
from exitlane.container_paths import ContainerLayout
from exitlane.container_runtime import IngressConfig,ContainerWireGuardLifecycle
v=ContainerState(ContainerLayout(Path('/data'))).validate()
g=ContainerWireGuardLifecycle(IngressConfig.from_file(Path('/data/state/wireguard/wg-office.conf')))
r=subprocess.run(['nft','-j','list','table','inet','exitlane_container_guard'],capture_output=True,check=True,timeout=5)
g.validate_previous_policy(json.loads(r.stdout))
print(json.dumps({'sources':list(g.source_addresses),'selected_provider':v.selected_provider,
 'intents':[{'provider':i.provider_id,'status':i.status,'generation':i.generation,
 'source':i.config.address if i.config else None,'endpoint':i.config.endpoint_address if i.config else None} for i in v.intents]}))
'''


class OutputEvidenceError(RuntimeError):
    """Only fixed identifiers, no arbitrary subprocess or configuration text."""


def _require(condition, code):
    if not condition:
        raise OutputEvidenceError(code)


def _tuple(ip, *, quoted=False):
    """Minimal IPv4 tuple inspection; fragmented/truncated evidence fails shut."""
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    offset = (ip[0] & 15) * 4
    if offset < 20 or len(ip) < offset:
        raise OutputEvidenceError('output_pcap_invalid')
    source, destination = (str(ipaddress.IPv4Address(value)) for value in (ip[12:16], ip[16:20]))
    relevant = source in DESTINATIONS or destination in DESTINATIONS
    total = struct.unpack('!H', ip[2:4])[0]
    if relevant and (total < offset or not quoted and total > len(ip)):
        raise OutputEvidenceError('output_pcap_invalid')
    if struct.unpack('!H', ip[6:8])[0] & 0x3fff:
        if relevant:
            raise OutputEvidenceError('output_fragment_unproven')
        return None
    protocol = ip[9]
    body = ip[offset:]
    if protocol in (6, 17):
        if len(body) < 4:
            if relevant:
                raise OutputEvidenceError('output_pcap_invalid')
            return None
        if relevant and not quoted and len(body) < (20 if protocol == 6 else 8):
            raise OutputEvidenceError('output_pcap_invalid')
        sport, dport = struct.unpack('!HH', body[:4])
        if relevant and ({sport, dport} & PORTS):
            form = 'icmp_quote' if quoted else 'udp' if protocol == 17 else (
                'tcp_rst' if len(body) >= 14 and body[13] & 4 else 'tcp_syn' if len(body) >= 14 and body[13] & 2 else 'tcp')
            return {'source': source, 'destination': destination, 'protocol': 'tcp' if protocol == 6 else 'udp',
                    'source_port': sport, 'destination_port': dport, 'quoted': quoted, 'form': form}
    elif protocol == 1 and body:
        if body[0] in (3, 11, 12) and not quoted:
            if len(body) < 28:
                raise OutputEvidenceError('output_pcap_invalid')
            return _tuple(body[8:], quoted=True)
        if relevant and body[0] in (0, 8):
            return {'source': source, 'destination': destination, 'protocol': 'icmp', 'quoted': quoted,
                    'form': 'icmp_reply' if body[0] == 0 else 'icmp_request'}
    return None


def scan_pcap(raw, start_ns, end_ns):
    """Inspect complete SLL2 PCAP records, including packets with no marker."""
    _require(type(start_ns) is int and type(end_ns) is int and 0 < start_ns < end_ns, 'output_window_invalid')
    _require(len(raw) <= LIMIT and len(raw) >= 24, 'output_pcap_invalid')
    header = struct.unpack('<IHHIIII', raw[:24])
    _require(header == (0xA1B2C3D4, 2, 4, 0, 0, 65575, 276), 'output_pcap_invalid')
    cursor, records, hits = 24, 0, []
    while cursor < len(raw):
        _require(cursor + 16 <= len(raw), 'output_pcap_invalid')
        sec, usec, included, original = struct.unpack('<IIII', raw[cursor:cursor + 16])
        cursor += 16
        _require(usec < 1000000 and 20 <= included <= 65575 and original == included
                 and cursor + included <= len(raw), 'output_pcap_invalid')
        frame = raw[cursor:cursor + included]
        cursor += included
        records += 1
        if not start_ns <= sec * 10**9 + usec * 1000 <= end_ns:
            continue
        protocol, offset = struct.unpack('!H', frame[:2])[0], 20
        for _ in range(2):
            if protocol not in {0x8100, 0x88a8}:break
            _require(len(frame) >= offset + 4, 'output_pcap_invalid')
            protocol = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
            offset += 4
        _require(protocol not in {0x8100, 0x88a8}, 'output_link_unsupported')
        if protocol != 0x0800:
            continue
        item = _tuple(frame[offset:])
        if item:
            _require(len(hits) < 4096, 'output_pcap_record_limit')
            hits.append({'observed_ns': sec * 10**9 + usec * 1000, **item})
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'records': records, 'tuples': hits}


def inject(configuration):
    """Executed only by external root in the pinned network namespace."""
    _require(isinstance(configuration, dict) and set(configuration) == {
        'source', 'dns', 'phase', 'namespace', 'eth0_ifindex'}, 'output_injector_invalid')
    source, dns, phase = configuration['source'], configuration['dns'], configuration['phase']
    _require(source in SOURCES.values() and dns == source.rsplit('.', 1)[0] + '.1'
             and isinstance(phase, str) and re.fullmatch('[a-z][a-z0-9_-]{0,39}', phase) is not None,
             'output_injector_invalid')
    ns = Path('/proc/self/ns/net').stat()
    _require(os.geteuid() == 0 and [ns.st_dev, ns.st_ino] == configuration['namespace']
             and ns.st_ino != Path('/proc/1/ns/net').stat().st_ino
             and socket.if_nametoindex('eth0') == configuration['eth0_ifindex'], 'output_namespace_unproven')
    start, attempts = time.time_ns(), []
    for sequence in range(1, 4):
        for kind, protocol in STREAMS:
            destination = dns if kind == 'dns' else '1.1.1.1'
            port = 53 if kind == 'dns' else 7777 if protocol == 'udp' else 7778
            item = {'kind': kind, 'protocol': protocol, 'sequence': sequence, 'sent_ns': time.time_ns()}
            client = None
            network_call = False
            try:
                client = socket.socket(socket.AF_INET, {'udp': socket.SOCK_DGRAM, 'tcp': socket.SOCK_STREAM,
                                                        'icmp': socket.SOCK_RAW}[protocol],
                                       socket.IPPROTO_ICMP if protocol == 'icmp' else 0)
                client.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND; no forced egress interface.
                client.settimeout(.3)
                client.bind((source, 0))
                network_call = True
                body = dns_query(phase, sequence) if kind == 'dns' else (
                    b'exitlane-d6-protected-' + phase.encode() + b':' + str(sequence).encode())
                if protocol == 'tcp':
                    client.connect((destination, port))
                    client.sendall(struct.pack('!H', len(body)) + body if kind == 'dns' else body)
                elif protocol == 'icmp':
                    client.sendto(packet(source, phase, sequence, kind, protocol)[20:], (destination, 0))
                else:
                    client.sendto(body, (destination, port))
                item['result'] = 'submitted'
            except OSError as error:
                _require(network_call and (error.errno in REFUSALS or isinstance(error, TimeoutError)),
                         'output_syscall_unproven')
                item.update(result='refused', errno=error.errno if error.errno in REFUSALS else errno.ETIMEDOUT)
            finally:
                if client is not None:
                    client.close()
            attempts.append(item)
    _require(socket.if_nametoindex('eth0') == configuration['eth0_ifindex'], 'output_namespace_unproven')
    # Bounded collection drain; observer windows independently prove this period.
    time.sleep(.5)
    return {'phase': phase, 'start_ns': start, 'end_ns': time.time_ns(), 'attempts': attempts,
            'namespace': configuration['namespace'], 'eth0_ifindex': configuration['eth0_ifindex']}


def _program(functions):
    header = ('import errno,hashlib,ipaddress,json,os,re,socket,stat,struct,time\nfrom pathlib import Path\n'
              + 'SOURCES=' + repr(SOURCES) + '\nDESTINATIONS=' + repr(DESTINATIONS)
              + '\nPORTS=' + repr(PORTS) + '\nLIMIT=' + repr(LIMIT) + '\nREFUSALS=' + repr(REFUSALS)
              + '\nSTREAMS=' + repr(STREAMS) + "\nPREFIX=b'exitlane-d6-protected-'\nPHASE=re.compile(r'[a-z][a-z0-9_-]{0,39}\\Z')\n")
    return header + '\n'.join(inspect.getsource(item) for item in functions)


class OutputQualification:
    def __init__(self, harness, captures, *, receipts, calibration_phase='calibration'):
        _require(isinstance(calibration_phase, str) and re.fullmatch('[a-z][a-z0-9_-]{0,39}', calibration_phase) is not None,
                 'output_calibration_missing')
        self.calibration_phase = calibration_phase
        self.h, self.captures, self.receipts = harness, captures, receipts
        self.sources = {}
        self.unmarked_controls = {}
        self.unmarked_ifindexes = {}

    def _state(self):
        result = self.h.docker('exec', self.h.container, 'python', '-c', PUBLIC_STATE)
        _require(isinstance(result, dict) and result.get('code') == 0, 'output_state_unproven')
        try:
            state = json.loads(result['stdout'])
        except (ValueError, KeyError, TypeError):
            raise OutputEvidenceError('output_state_unproven') from None
        _require(isinstance(state, dict) and set(state) == {'sources', 'selected_provider', 'intents'}
                 and isinstance(state['sources'], list) and isinstance(state['intents'], list), 'output_state_unproven')
        return state

    def capture_source(self, provider):
        _require(provider in SOURCES, 'output_provider_invalid')
        self.h.assert_disposable()
        facts = self.h.assert_owned('container', self.h.container)
        state = self._state()
        intents = [item for item in state['intents'] if item.get('provider') == provider and item.get('status') == 'active']
        _require(len(intents) == 1 and state['selected_provider'] == provider
                 and intents[0]['source'].split('/')[0] == SOURCES[provider]
                 and SOURCES[provider] in state['sources'] and intents[0].get('endpoint') in {'192.0.0.9','192.0.0.10'},
                 'output_source_unproven')
        receipt = {'run_id': self.h.config['run_id'], 'image': self.h.config['image'], 'provider': provider,
                   'generation': intents[0]['generation'], 'source': SOURCES[provider],
                   'running_image': facts['Image'], 'endpoint':intents[0]['endpoint']}
        self.sources[provider] = dict(receipt)
        self.receipts.write('output-source-' + provider + '.json', receipt)
        return dict(receipt)

    def _inject(self, receipt, phase, *, controls=False):
        facts = self.h.assert_owned('container', self.h.container)
        _require(receipt.get('running_image') == facts.get('Image'), 'output_image_changed')
        pid = facts['State']['Pid']
        _require(type(pid) is int and pid > 0, 'output_namespace_unproven')
        function = inject_controls if controls else inject
        source = _program([OutputEvidenceError, _require, checksum, dns_query, packet, calibration_packets, function])
        result = self.h.candidate.run('''from pathlib import Path
pid=payload['pid']
verified=json.loads(subprocess.run(['docker','container','inspect',payload['container']],capture_output=True,text=True,check=True,timeout=5).stdout)[0]
if verified['State']['Pid']!=pid or verified['Image']!=payload['running_image'] or verified['Config']['Labels'].get('org.exitlane.qualification.run')!=payload['run_id']:raise SystemExit('output_namespace_unproven')
fd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY|os.O_CLOEXEC)
try:
 n=os.fstat(fd)
 if n.st_ino==Path('/proc/1/ns/net').stat().st_ino:raise SystemExit('output_namespace_unproven')
 config={'source':payload['source'],'dns':payload['source'].rsplit('.',1)[0]+'.1',
         'phase':payload['phase'],'namespace':[n.st_dev,n.st_ino],'eth0_ifindex':0}
 probe=subprocess.run(['nsenter','--net=/proc/self/fd/'+str(fd),'python3','-c',
  'import socket;print(socket.if_nametoindex("eth0"))'],pass_fds=(fd,),capture_output=True,text=True,check=True,timeout=5)
 config['eth0_ifindex']=int(probe.stdout)
 r=subprocess.run(['nsenter','--net=/proc/self/fd/'+str(fd),'python3','-c',payload['program']+
  '\\nprint(json.dumps('+payload['function']+'(json.load(__import__("sys").stdin))))'],
  input=json.dumps(config),pass_fds=(fd,),capture_output=True,text=True,timeout=20)
 if r.returncode:raise SystemExit('output_injector_failed')
 print(r.stdout)
finally:os.close(fd)
''', data={'pid': pid, 'container': self.h.container, 'run_id': self.h.config['run_id'],
                 'source': receipt['source'], 'phase': phase, 'program': source, 'function': function.__name__,
                 'running_image': receipt['running_image']}, timeout=30)
        return json.loads(result)

    def _pcaps(self, handle, start, end):
        _require(re.fullmatch('/run/exitlane-d6-[0-9a-f]{32}', handle.get('root', '')) is not None
                 and isinstance(handle.get('interfaces'), list)
                 and all(isinstance(name, str) and re.fullmatch('[A-Za-z0-9_.-]{1,15}', name)
                         for name in handle['interfaces']), 'output_handle_invalid')
        host = self.h.candidate if handle.get('host') == 'candidate' else self.h.peer
        source = _program([OutputEvidenceError, _require, _tuple, scan_pcap])
        source += '''\nroot=Path(payload['root']);f=root.lstat()
_require(stat.S_ISDIR(f.st_mode) and f.st_uid==0 and stat.S_IMODE(f.st_mode)==0o700,'output_pcap_unsafe')
result={}
for name in payload['interfaces']:
 fd=os.open(root/(name+'.pcap'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  f=os.fstat(fd)
  _require(stat.S_ISREG(f.st_mode) and f.st_uid==0 and stat.S_IMODE(f.st_mode)==0o600 and f.st_size<=LIMIT,'output_pcap_unsafe')
  with os.fdopen(fd,'rb') as stream:
   fd=None;raw=stream.read(f.st_size)
  result[name]=dict(scan_pcap(raw,payload['start'],payload['end']),path=str(root/(name+'.pcap')))
 finally:
  if fd is not None:os.close(fd)
print(json.dumps(result))
'''
        return json.loads(host.run(source, data={'root': handle['root'], 'interfaces': handle['interfaces'],
                                                'start': start, 'end': end}, output_limit=8 * 1024 * 1024))

    def _pin_topology(self):
        net = self.h.assert_owned('network', self.h.network)
        bridge = net['Options'].get('com.docker.network.bridge.name','br-'+net['Id'][:12])
        result = self.h.command(self.h.candidate,['ip','-j','route','get','1.1.1.1'])
        candidate_device = json.loads(result['stdout'])[0]['dev']
        result = self.h.command(self.h.peer,['ip','-j','route','get',self.h.config['candidate']['address']])
        peer_device = json.loads(result['stdout'])[0]['dev']
        for handle in self.captures:
            if handle['role']=='candidate-host':
                _require(set(handle['interfaces'])=={candidate_device,bridge},'output_topology_incomplete')
            elif handle['role']=='wan':
                _require(handle['interfaces']==[peer_device],'output_topology_incomplete')
        return {'candidate_uplink':candidate_device,'docker_bridge':bridge,'peer_uplink':peer_device}

    def raw_calibration(self, *, clock_token, source_receipt=None):
        """Observe actual unmarked controls without relaxing protected policy.

        None selects the ordinary container IP. A supplied source must still be
        its selected ACTIVE generation. Calibrate both real peer paths via normal
        API outside measurement. Original PCAP and public projections are kept.
        """
        validate_handles(self.captures, self.h.config['run_id'])
        self.h.assert_disposable()
        self._pin_topology()
        facts = self.h.assert_owned('container', self.h.container)
        if source_receipt is None:
            source = facts['NetworkSettings']['Networks'][self.h.network]['IPAddress']
            receipt = {'source': source, 'running_image': facts['Image']}
        else:
            _require(self.sources.get(source_receipt.get('provider')) == source_receipt, 'output_source_unproven')
            state = self._state()
            _require(state['selected_provider'] == source_receipt['provider'] and any(
                i['provider'] == source_receipt['provider'] and i['status'] == 'active'
                and i['generation'] == source_receipt['generation'] for i in state['intents']), 'output_source_unproven')
            receipt = source_receipt
        before = self.h.measure_clock(token=clock_token)
        emitted = self._inject(receipt, self.calibration_phase, controls=True)
        self.h.wait(lambda: all(all(f['end_ns'] > emitted['end_ns'] for f in self.h.evidence(h)['captures'].values())
                               for h in self.captures), 'd6-output-control-drained', timeout=20)
        after = self.h.measure_clock(token=clock_token)
        _require(before['reference_boot_id'] == after['reference_boot_id'], 'output_clock_changed')
        measurement = {'before': before['measurement'], 'after': after['measurement']}
        bounds = [(v['reference_ns']-v['local_after_ns'],v['reference_ns']-v['local_before_ns']) for v in measurement.values()]
        alignment = _clock_alignment(measurement, emitted['start_ns']+min(i[0] for i in bounds),
                                     emitted['end_ns']+max(i[1] for i in bounds))
        raw = {}
        for h in self.captures:
            lower, upper = (0,0) if h.get('host') == 'candidate' else (alignment['lower_ns'],alignment['upper_ns'])
            raw[h['role']] = self._pcaps(h,emitted['start_ns']+lower,emitted['end_ns']+upper)
            evidence = self.h.evidence(h)
            for interface, projection in raw[h['role']].items():
                point = h['role']+':'+interface
                current = evidence['captures'][interface]
                _require(current['ready'] is True and current['errors']==[] and current['gaps']==[]
                         and current['drops']==0 and current['invalid_packets']==0
                         and current['start_ns']<=emitted['start_ns']+lower<emitted['end_ns']+upper<=current['end_ns'],
                         'output_capture_invalid')
                if self.unmarked_ifindexes.get(point) != current['ifindex']:
                    self.unmarked_controls[point]=set()
                self.unmarked_ifindexes[point]=current['ifindex']
                forms = {i.get('form') for i in projection['tuples']} & {'tcp_syn','tcp_rst','icmp_quote'}
                self.unmarked_controls.setdefault(point,set()).update(forms)
        result = {'run_id':self.h.config['run_id'],'source':receipt,'emitted':emitted,'pcaps':raw,
                  'clock_alignment':alignment,'observed_forms':{p:sorted(v) for p,v in self.unmarked_controls.items()}}
        self.receipts.write('output-raw-calibration-'+uuid.uuid4().hex[:16]+'.json',result)
        return result

    def _require_unmarked_controls(self):
        for handle in self.captures:
            facts=self.h.evidence(handle)['captures']
            for interface in handle['interfaces']:
                if interface=='wg-office':continue
                point=handle['role']+':'+interface
                _require(self.unmarked_controls.get(point)=={'tcp_syn','tcp_rst','icmp_quote'}
                         and self.unmarked_ifindexes.get(point)==facts[interface]['ifindex'],
                         'output_unmarked_calibration_missing')

    def kernel_reply(self, source_receipt, *, clock_token):
        """Actual candidate-kernel echo reply and closed-port RST, ACTIVE only."""
        validate_handles(self.captures,self.h.config['run_id'])
        self._pin_topology()
        self._require_unmarked_controls()
        _require(self.sources.get(source_receipt.get('provider'))==source_receipt,'output_source_unproven')
        self.h.assert_disposable()
        current=self.h.assert_owned('container',self.h.container)
        _require(current['Image']==source_receipt['running_image'],'output_image_changed')
        namespace_handle=next(h for h in self.captures if h['role']=='candidate-namespace')
        _require(namespace_handle['container_pid']==current['State']['Pid'],'output_namespace_unproven')
        state=self._state()
        _require(state['selected_provider']==source_receipt['provider'] and any(
            i['provider']==source_receipt['provider'] and i['status']=='active'
            and i['generation']==source_receipt['generation'] for i in state['intents']),'output_source_unproven')
        role={'192.0.0.9':'a','192.0.0.10':'b'}[source_receipt['endpoint']]
        ownership=json.loads(self.h.command(self.h.peer,['/usr/bin/python3',
            '/var/lib/exitlane-qualification/container_host_peer.py','ownership'],
            data=json.dumps({'run_id':self.h.config['run_id'],'role':role}))['stdout'])
        _require(ownership['run_id']==self.h.config['run_id'] and ownership['role']==role
                 and ownership['namespace']=='ed6-'+self.h.config['run_id'].replace('-','')[:10]+'-'+role
                 and isinstance(ownership['namespace_inode'],list) and len(ownership['namespace_inode'])==2
                 and all(type(v) is int and v>0 for v in ownership['namespace_inode'])
                 and type(ownership['interface_ifindexes']['wg-peer']) is int
                 and ownership['interface_ifindexes']['wg-peer']>0,'output_namespace_unproven')
        closed=self.h.docker('exec',self.h.container,'ss','-H','-ltn','sport = :7778')
        _require(closed['code']==0 and closed['stdout'].strip()=='','output_kernel_port_not_closed')
        manifest=json.loads(self.h.command(self.h.peer,['/usr/bin/python3',
            '/var/lib/exitlane-qualification/container_host_peer.py','status'],
            data=json.dumps({'run_id':self.h.config['run_id']}))['stdout'])
        peer=manifest['peers'][role]
        _require(peer['endpoint']==source_receipt['endpoint'],'output_source_unproven')
        observed=self.h.docker('exec',self.h.container,'wg','show','wg-'+source_receipt['provider'],'endpoints')['stdout'].strip()
        _require(observed==peer['public_key']+'\t'+peer['endpoint']+':'+str(peer['port']),'output_source_unproven')
        phase='kernel-output-'+uuid.uuid4().hex[:12]
        name=phase+'.json'
        metadata={'run_id':self.h.config['run_id'],'phase':phase,'source':source_receipt,'result':'RUNNING',
                  'scope':['kernel_icmp_echo_reply','kernel_closed_port_tcp_rst'],'production_support':False,'handles':self.captures}
        self.receipts.write(name,metadata)
        try:
            for h in self.captures:self.h.control(h,phase,calibration_phase=self.calibration_phase)
            self.h.wait(lambda:all(self.h.evidence(h)['phase']==phase for h in self.captures),'d6-kernel-capture-ready',timeout=20)
            before=self.h.measure_clock(token=clock_token)
            program=_program([OutputEvidenceError,_require,checksum,dns_query,packet,kernel_packets,inject_kernel_requests])
            emitted=json.loads(self.h.peer.run('''from pathlib import Path
p=Path('/run/netns')/payload['namespace']
fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
try:
 f=os.fstat(fd)
 if [f.st_dev,f.st_ino]!=payload['inode']:raise SystemExit('output_namespace_unproven')
 config={'source':payload['source'],'phase':payload['phase'],'namespace':payload['inode'],'ifindex':payload['ifindex']}
 r=subprocess.run(['nsenter','--net=/proc/self/fd/'+str(fd),'python3','-c',payload['program']+
  '\\nprint(json.dumps(inject_kernel_requests(json.load(__import__("sys").stdin))))'],
  input=json.dumps(config),pass_fds=(fd,),capture_output=True,text=True,timeout=10)
 if r.returncode:raise SystemExit('output_kernel_injector_failed')
 print(r.stdout)
finally:os.close(fd)
''',data={'namespace':ownership['namespace'],'inode':ownership['namespace_inode'],
              'ifindex':ownership['interface_ifindexes']['wg-peer'],'source':source_receipt['source'],
              'phase':phase,'program':program},timeout=20))
            metadata['emitted']=emitted
            self.h.wait(lambda:all(all(f['end_ns']>emitted['end_ns']+10**9 for f in self.h.evidence(h)['captures'].values())
                                  for h in self.captures),'d6-kernel-capture-drained',timeout=20)
            after=self.h.measure_clock(token=clock_token)
            _require(before['reference_boot_id']==after['reference_boot_id'],'output_clock_changed')
            alignment=_clock_alignment({'before':before['measurement'],'after':after['measurement']},emitted['start_ns'],emitted['end_ns'])
            metadata['clock_alignment']=alignment
            raw={};observations={};windows={}
            for h in self.captures:
                lower,upper=(alignment['lower_ns'],alignment['upper_ns']) if h.get('host')=='candidate' else (0,0)
                start,end=emitted['start_ns']-upper,emitted['end_ns']-lower
                evidence=self.h.evidence(h)
                _require(evidence['phase']==phase,'output_phase_changed')
                for interface,facts in evidence['captures'].items():
                    validate_observer(facts,start,end,calibration_phase=self.calibration_phase)
                    point=h['role']+':'+interface
                    if interface!='wg-office':
                        _require(self.unmarked_ifindexes.get(point)==facts['ifindex'],
                                 'output_unmarked_calibration_missing')
                    observations[point]=facts;windows[point]=[start,end]
                raw[h['role']]=self._pcaps(h,start,end)
                metadata.update(captures=observations,pcaps=raw)
            validate_kernel_replies(source_receipt,phase,observations,raw,windows)
            metadata.update(result='KERNEL_REPLY_COMPONENT_PASS',limitations=['icmp_echo_reply_and_closed_port_rst_only',
                            'icmp_error_quote_is_sensitivity_control_only','retired_address_kernel_reply_not_claimed'])
            self.receipts.write(name,metadata)
            return metadata
        except Exception:  # noqa: BLE001 -- only fixed failure, never subprocess text
            metadata.update(result='FAIL',error='output_kernel_reply_unproven')
            self.receipts.write(name,metadata)
            raise OutputEvidenceError('output_kernel_reply_unproven') from None

    def run(self, source_receipt, *, clock_token, expected='blocked', operation=None, require_delivery=False):
        _require(expected in {'blocked', 'provider_or_block'} and type(require_delivery) is bool
                 and isinstance(source_receipt, dict) and self.sources.get(source_receipt.get('provider')) == source_receipt,
                 'output_source_unproven')
        _require(isinstance(clock_token, str) and re.fullmatch('[a-f0-9]{64}', clock_token) is not None,
                 'output_clock_invalid')
        validate_handles(self.captures, self.h.config['run_id'])
        topology = self._pin_topology()
        self.h.assert_disposable()
        _require(self.h.assert_owned('container', self.h.container)['Image'] == source_receipt['running_image'], 'output_image_changed')
        required = {h['role'] + ':' + i for h in self.captures for i in h['interfaces'] if i != 'wg-office'}
        _require(all(self.unmarked_controls.get(point) == {'tcp_syn','tcp_rst','icmp_quote'} for point in required),
                 'output_unmarked_calibration_missing')
        _require(source_receipt['source'] in self._state()['sources'], 'output_source_unproven')
        phase = 'output-' + uuid.uuid4().hex[:16]
        metadata = {'run_id': self.h.config['run_id'], 'phase': phase, 'source': source_receipt,
                    'expected': expected, 'result': 'RUNNING', 'production_support': False, 'handles': self.captures, 'topology': topology}
        name = phase + '.json'
        self.receipts.write(name, metadata)
        try:
            metadata['stage'] = 'capture_preparation'
            before = self.h.measure_clock(token=clock_token)
            for handle in self.captures:
                _require(self.h.evidence(handle).get('phase') != phase, 'output_phase_reused')
                self.h.control(handle, phase, calibration_phase=self.calibration_phase)
            self.h.wait(lambda: all(self.h.evidence(h).get('phase') == phase for h in self.captures),
                        'd6-output-capture-ready', timeout=20)
            metadata['stage'] = 'requested_operation'
            if operation is not None:
                operation()
            metadata['stage'] = 'namespace_injection'
            injected = self._inject(source_receipt, phase)
            metadata['injector'] = injected
            namespace_handle = next(h for h in self.captures if h['role'] == 'candidate-namespace')
            _require(namespace_handle.get('container_pid') == self.h.assert_owned('container', self.h.container)['State']['Pid'],
                     'output_namespace_unproven')
            _require(injected.get('phase') == phase, 'output_attempts_invalid')
            metadata['stage'] = 'capture_drain'
            self.h.wait(lambda: all(all(f['end_ns'] > injected['end_ns'] for f in self.h.evidence(h)['captures'].values())
                                   for h in self.captures), 'd6-output-capture-drained', timeout=20)
            metadata['stage'] = 'clock_alignment'
            after = self.h.measure_clock(token=clock_token)
            _require(before['reference_boot_id'] == after['reference_boot_id'], 'output_clock_changed')
            measurement = {'before': before['measurement'], 'after': after['measurement']}
            bounds = [(v['reference_ns'] - v['local_after_ns'], v['reference_ns'] - v['local_before_ns'])
                      for v in measurement.values()]
            alignment = _clock_alignment(measurement, injected['start_ns'] + min(v[0] for v in bounds),
                                         injected['end_ns'] + max(v[1] for v in bounds))
            metadata['clock_alignment'] = alignment
            metadata['stage'] = 'raw_pcap_inspection'
            observations, raw, windows = {}, {}, {}
            for handle in self.captures:
                evidence = self.h.evidence(handle)
                _require(evidence.get('phase') == phase, 'output_phase_changed')
                candidate = handle.get('host') == 'candidate'
                lower, upper = (0, 0) if candidate else (alignment['lower_ns'], alignment['upper_ns'])
                for interface, facts in evidence['captures'].items():
                    validate_observer(facts, injected['start_ns'] + lower, injected['end_ns'] + upper,
                                      calibration_phase=self.calibration_phase)
                    if interface != 'wg-office':
                        _require(self.unmarked_ifindexes.get(handle['role']+':'+interface)==facts['ifindex'],
                                 'output_unmarked_calibration_missing')
                    windows[handle['role'] + ':' + interface] = [injected['start_ns'] + lower, injected['end_ns'] + upper]
                    observations[handle['role'] + ':' + interface] = facts
                _require(set(evidence['captures']) == set(handle['interfaces']), 'output_topology_incomplete')
                if handle['role'] == 'candidate-namespace':
                    _require(evidence['captures']['eth0']['ifindex'] == injected['eth0_ifindex'],
                             'output_namespace_unproven')
                raw[handle['role']] = self._pcaps(handle, injected['start_ns'] + lower, injected['end_ns'] + upper)
                metadata.update(captures=observations, pcaps=raw)
            metadata.update(captures=observations, pcaps=raw)
            metadata['stage'] = 'output_acceptance'
            validate_output(injected, observations, raw, expected=expected, require_delivery=require_delivery, capture_windows=windows)
            metadata.update(result='OUTPUT_COMPONENT_PASS', limitations=['explicit_outbound_probes_only',
                             'kernel_reply_forms_outstanding', 'full_d6_matrix_outstanding'])
            self.receipts.write(name, metadata)
            return metadata
        except Exception as error:  # noqa: BLE001 -- never expose remote state or secret bodies
            known = error.args[0] if isinstance(error, OutputEvidenceError) and len(error.args) == 1 else None
            metadata.update(result='FAIL', error=known if known in KNOWN_FAILURES else 'output_evidence_unproven')
            partial = {}
            for handle in self.captures:
                try:
                    partial[handle['role']] = self.h.evidence(handle)
                except Exception:  # noqa: BLE001 -- retain available public capture facts only
                    partial[handle['role']] = {'error': 'output_capture_unavailable'}
            metadata['last_captures'] = partial
            self.receipts.write(name, metadata)
            raise OutputEvidenceError('output_evidence_unproven') from None


def validate_observer(facts, start, end, *, calibration_phase='calibration'):
    _require(isinstance(facts, dict) and facts.get('ready') is True and facts.get('errors') == []
             and facts.get('gaps') == [] and facts.get('drops') == 0 and facts.get('invalid_packets') == 0
             and type(facts.get('ifindex')) is int and facts['ifindex'] > 0
             and type(facts.get('polls')) is int and facts['polls'] >= 2
             and type(facts.get('max_poll_gap_ns')) is int and 0 <= facts['max_poll_gap_ns'] <= 10**9,
             'output_capture_invalid')
    _require(type(facts.get('start_ns')) is int and type(facts.get('end_ns')) is int
             and facts['start_ns'] <= start < end <= facts['end_ns']
             and type(facts.get('last_poll_ns')) is int and facts['end_ns'] - 10**9 <= facts['last_poll_ns'] <= facts['end_ns'],
             'output_capture_window_gap')
    calibration = facts.get('calibration')
    _require(isinstance(calibration, list) and 1 <= len(calibration) <= 100000, 'output_calibration_missing')
    for item in calibration:
        validate_sample(item, facts, calibration_phase, facts['start_ns'], start)
    _require({(i['kind'], i['protocol']) for i in calibration} == set(STREAMS), 'output_calibration_missing')


def validate_output(injected, observations, pcaps, *, expected, require_delivery=False, capture_windows=None):
    _require(isinstance(injected, dict) and isinstance(injected.get('attempts'), list)
             and len(injected['attempts']) == 15, 'output_attempts_missing')
    _require(type(injected.get('start_ns')) is int and type(injected.get('end_ns')) is int
             and 0 < injected['start_ns'] < injected['end_ns']
             and all(type(i.get('sent_ns')) is int and injected['start_ns'] <= i['sent_ns'] <= injected['end_ns']
                     for i in injected['attempts']), 'output_attempts_invalid')
    _require({(i.get('kind'), i.get('protocol'), i.get('sequence')) for i in injected['attempts']}
             == {(kind, protocol, sequence) for kind, protocol in STREAMS for sequence in range(1, 4)}
             and all(i.get('result') in {'submitted', 'refused'} and
                     (i['result'] == 'submitted' or i.get('errno') in REFUSALS) for i in injected['attempts']),
             'output_attempts_invalid')
    _require(set(pcaps) == {'candidate-host', 'candidate-namespace', 'wan', 'provider-a', 'provider-b', 'target'}
             and all(isinstance(v, dict) and v for v in pcaps.values())
             and 'eth0' in pcaps['candidate-namespace'] and len(pcaps['candidate-host']) == 2
             and all(role + ':' + interface in observations for role, interfaces in pcaps.items()
                     for interface in interfaces), 'output_topology_incomplete')
    forbidden = {'candidate-host', 'wan'}
    if expected == 'blocked':
        forbidden |= {'provider-a', 'provider-b', 'target'}
    for role, interfaces in pcaps.items():
        for interface, facts in interfaces.items():
            if role in forbidden or role == 'candidate-namespace' and interface == 'eth0':
                _require(facts.get('tuples') == [], 'output_plaintext_detected')
    if require_delivery:
        _require(expected == 'provider_or_block', 'output_delivery_invalid')
        _require(isinstance(capture_windows, dict), 'output_sample_invalid')
        delivered = set()
        for point, facts in observations.items():
            if not point.startswith('provider-') or not point.endswith(':wg-peer'):continue
            window = capture_windows.get(point)
            _require(isinstance(window, list) and len(window) == 2, 'output_sample_invalid')
            for item in facts.get('samples', []):
                validate_sample(item, facts, injected['phase'], *window)
                _require(item['sequence'] <= 3, 'output_sample_invalid')
                delivered.add((item['kind'], item['protocol']))
        _require(delivered == set(STREAMS), 'output_positive_delivery_missing')


def validate_handles(handles, run_id):
    _require(isinstance(handles, list) and len(handles) == 6 and all(isinstance(h, dict) for h in handles),
             'output_topology_incomplete')
    _require({h.get('role') for h in handles} == {'candidate-host', 'candidate-namespace', 'wan',
             'provider-a', 'provider-b', 'target'}, 'output_topology_incomplete')
    units = set()
    prefix = 'ed6-' + run_id.replace('-', '')[:10] + '-'
    for h in handles:
        root, unit, interfaces = h.get('root'), h.get('unit'), h.get('interfaces')
        _require(isinstance(root, str) and re.fullmatch('/run/exitlane-d6-[0-9a-f]{32}', root) is not None
                 and unit == 'exitlane-d6-capture-' + root.rsplit('-', 1)[1] + '.service'
                 and unit not in units and h.get('kind') == 'capture'
                 and isinstance(interfaces, list) and 1 <= len(interfaces) <= 6
                 and len(set(interfaces)) == len(interfaces)
                 and all(isinstance(i, str) and re.fullmatch('[A-Za-z0-9_.-]{1,15}', i) for i in interfaces),
                 'output_handle_invalid')
        units.add(unit)
        role = h['role']
        if role.startswith('candidate-'):
            _require(h.get('host') == 'candidate' and type(h.get('namespace')) is bool
                     and h['namespace'] == (role == 'candidate-namespace') and 'eth0' in interfaces,
                     'output_handle_invalid')
            if role == 'candidate-host':
                _require(len(interfaces) == 2, 'output_topology_incomplete')
        else:
            _require(h.get('host', 'peer') == 'peer' and h.get('namespace') == (
                None if role == 'wan' else prefix + {'provider-a': 'a', 'provider-b': 'b', 'target': 'target'}[role]),
                'output_handle_invalid')
            if role.startswith('provider-'):
                _require(set(interfaces) in ({'wg-peer'}, {'wg-peer','target'}), 'output_topology_incomplete')
            elif role == 'target':
                _require(set(interfaces) == {'pa','pb','uplink'}, 'output_topology_incomplete')


def validate_sample(item, facts, phase, start, end):
    _require(isinstance(item, dict) and item.get('phase') == phase
             and (item.get('kind'), item.get('protocol')) in STREAMS
             and type(item.get('sequence')) is int and 1 <= item['sequence'] <= 2**31-1
             and type(item.get('ifindex')) is int and item['ifindex'] == facts['ifindex']
             and type(item.get('observed_ns')) is int and start <= item['observed_ns'] <= end,
             'output_sample_invalid')
    try:
        _require(all(isinstance(item.get(k), str) and str(ipaddress.IPv4Address(item[k])) == item[k]
                     for k in ('source','destination')), 'output_sample_invalid')
    except ValueError:
        raise OutputEvidenceError('output_sample_invalid') from None


def calibration_packets(source, phase):
    """Checksum-valid empty SYN/RST and ICMP3 quote, fixed synthetic target."""
    values = []
    for flag in (2,4):
        raw = bytearray(packet(source,phase,1,'protected','tcp')[:40])
        raw[2:4] = struct.pack('!H',40);raw[10:12] = b'\0\0'
        raw[33] = flag;raw[36:38] = b'\0\0'
        pseudo = raw[12:20]+struct.pack('!BBH',0,6,20)
        raw[36:38] = struct.pack('!H',checksum(bytes(pseudo+raw[20:])))
        raw[10:12] = struct.pack('!H',checksum(bytes(raw[:20])))
        values.append(bytes(raw))
    quote = packet(source,phase,1,'protected','tcp')[:28]
    body = b'\x03\x03'+b'\0'*6+quote
    body = body[:2]+struct.pack('!H',checksum(body))+body[4:]
    header = bytearray(packet(source,phase,1,'protected','icmp')[:20])
    header[2:4] = struct.pack('!H',20+len(body));header[10:12] = b'\0\0'
    header[10:12] = struct.pack('!H',checksum(bytes(header)))
    return values+[bytes(header)+body]


def inject_controls(configuration):
    source, phase = configuration['source'],configuration['phase']
    address = ipaddress.IPv4Address(source)
    _require(address.is_private and not address.is_loopback and not address.is_link_local
             and not address.is_unspecified and re.fullmatch('[a-z][a-z0-9_-]{0,39}',phase), 'output_injector_invalid')
    ns = Path('/proc/self/ns/net').stat()
    _require(os.geteuid()==0 and [ns.st_dev,ns.st_ino]==configuration['namespace']
             and ns.st_ino != Path('/proc/1/ns/net').stat().st_ino
             and socket.if_nametoindex('eth0')==configuration['eth0_ifindex'], 'output_namespace_unproven')
    start=time.time_ns()
    with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) as client:
        for raw in calibration_packets(source,phase):client.sendto(raw,('1.1.1.1',0))
    time.sleep(.5)
    return {'start_ns':start,'end_ns':time.time_ns(),'source':source,'forms':['tcp_syn','tcp_rst','icmp_quote']}


def kernel_packets(source, phase):
    peer=source.rsplit('.',1)[0]+'.1'
    frames=[]
    for protocol in ('icmp','tcp'):
        raw=bytearray(packet(peer,phase,1,'protected',protocol))
        raw[16:20]=ipaddress.IPv4Address(source).packed
        if protocol=='tcp':
            raw=raw[:40];raw[2:4]=struct.pack('!H',40);raw[36:38]=b'\0\0'
            raw[36:38]=struct.pack('!H',checksum(bytes(raw[12:20]+struct.pack('!BBH',0,6,20)+raw[20:])))
        raw[10:12]=b'\0\0';raw[10:12]=struct.pack('!H',checksum(bytes(raw[:20])))
        frames.append(bytes(raw))
    return frames


def inject_kernel_requests(configuration):
    source=configuration['source'];ns=Path('/proc/self/ns/net').stat()
    _require(source in SOURCES.values() and os.geteuid()==0
             and [ns.st_dev,ns.st_ino]==configuration['namespace']
             and ns.st_ino!=Path('/proc/1/ns/net').stat().st_ino
             and socket.if_nametoindex('wg-peer')==configuration['ifindex'],'output_namespace_unproven')
    start=time.time_ns()
    with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) as client:
        client.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'wg-peer\0')
        for raw in kernel_packets(source,configuration['phase']):client.sendto(raw,(source,0))
    time.sleep(.5)
    return {'start_ns':start,'end_ns':time.time_ns(),'source':source,'kernel_request_count':2}


def validate_kernel_replies(source,phase,observations,pcaps,windows):
    role='provider-a' if source['endpoint']=='192.0.0.9' else 'provider-b'
    point=role+':wg-peer';facts=observations[point];peer=source['source'].rsplit('.',1)[0]+'.1'
    replies=[]
    for item in facts['samples']:
        validate_sample(item,facts,phase,*windows[point])
        if item['protocol']=='icmp' and item['sequence']==1 and item['source']==source['source'] and item['destination']==peer:
            replies.append(item)
    tuples=pcaps[role]['wg-peer']['tuples']
    _require(replies and any(t.get('form')=='icmp_reply' and t['source']==source['source'] and t['destination']==peer for t in tuples)
             and any(t.get('form')=='tcp_rst' and t['source']==source['source'] and t['destination']==peer
                     and t.get('source_port')==7778 and t.get('destination_port')==30001 for t in tuples),
             'output_kernel_reply_unproven')
    for r,interfaces in pcaps.items():
        for interface,facts in interfaces.items():
            if r in {'candidate-host','wan'} or r=='candidate-namespace' and interface=='eth0':
                _require(facts['tuples']==[],'output_plaintext_detected')
