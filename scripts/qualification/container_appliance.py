#!/usr/bin/env python3
"""D5 real image/management proof, using only uniquely owned local resources.

Never publishes an image, restarts Docker or changes host firewall configuration.
All credentials are ephemeral synthetic values transferred on stdin, not argv.
This does not substitute for D6's disposable-host packet/restart qualification.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

HTTP = r'''
import http.client,json,sys
v=json.load(sys.stdin)
c=http.client.HTTPConnection(v['address'],v.get('port',8787),timeout=8)
headers=v.get('headers',{})
body=v.get('body')
if body is not None:
    body=json.dumps(body).encode();headers['Content-Type']='application/json'
try:
    c.request(v.get('method','GET'),v['path'],body,headers)
    r=c.getresponse();data=r.read(1048577)
except (OSError,http.client.HTTPException):
    print(json.dumps({'status':0,'headers':{},'cookies':[],'body':None}))
    c.close();raise SystemExit(0)
assert len(data)<=1048576
try:body=json.loads(data)
except ValueError:body=None
print(json.dumps({'status':r.status,'headers':dict(r.getheaders()),
                  'cookies':r.headers.get_all('set-cookie',[]),'body':body}))
c.close()
'''

PROXY = r'''
import http.client,http.server,json,sys
v=json.loads(sys.stdin.readline())
class Proxy(http.server.BaseHTTPRequestHandler):
    def forward(self):
        size=int(self.headers.get('Content-Length','0'))
        if not 0<=size<=1048576:self.send_error(413);return
        body=self.rfile.read(size) if size else None
        headers={k:val for k,val in self.headers.items() if k.lower() not in
                 {'host','forwarded','x-forwarded-for','x-forwarded-proto','x-forwarded-host','connection'}}
        headers.update({'Host':'exitlane.example.internal','X-Forwarded-For':self.client_address[0],
                        'X-Forwarded-Proto':'https'})
        c=http.client.HTTPConnection(v['upstream'],8787,timeout=8)
        c.request(self.command,self.path,body,headers);r=c.getresponse()
        data=r.read(1048577);assert len(data)<=1048576
        self.send_response(r.status)
        for k,val in r.getheaders():
            if k.lower() not in {'connection','transfer-encoding','content-length','server','date'}:
                self.send_header(k,val)
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);c.close()
    do_GET=forward
    do_POST=forward
    do_DELETE=forward
    def log_message(self,*args):pass
http.server.ThreadingHTTPServer(('0.0.0.0',8990),Proxy).serve_forever()
'''

PAIR = r'''
import hashlib,json,sqlite3
from exitlane.container_state import ContainerLayout,ContainerState
from pathlib import Path
s=ContainerState(ContainerLayout(Path('/data')));v=s.validate()
with sqlite3.connect('file:/data/state/exitlane.db?mode=ro',uri=True) as c:
    users=c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
print(json.dumps({'schema':v.schema,'key':hashlib.sha256(s.layout.master_key.read_bytes()).hexdigest(),
                  'users':users,'manifest':hashlib.sha256(s.layout.manifest.read_bytes()).hexdigest()}))
'''

DIAGNOSTIC_ENTRY = r'''
import asyncio,json,traceback,re
from pathlib import Path
from exitlane.container_entrypoint import ContainerEntrypoint
try:asyncio.run(ContainerEntrypoint().run())
except Exception as e:
    causes=[];current=e
    for _ in range(6):
        if current is None:break
        code=getattr(current,'code',None)
        if type(current).__name__=='ControlError':code=str(current)
        causes.append({'type':type(current).__name__,
            'code':code if isinstance(code,str) and re.fullmatch('[a-z_]{1,80}',code) else None,
            'frames':[[Path(f.filename).name,f.name,f.lineno] for f in traceback.extract_tb(current.__traceback__)[-5:]]})
        current=current.__context__
    print(json.dumps({'type':type(e).__name__,'code':getattr(e,'code',None),
        'causes':causes,'frames':[[Path(f.filename).name,f.name,f.lineno] for f in traceback.extract_tb(e.__traceback__)[-8:]]}),flush=True)
    raise SystemExit(1)
'''

TARGET = r'''
import http.server,socket,threading
count=0
def receive():
    global count
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(('0.0.0.0',7777))
        while True:
            payload,_=s.recvfrom(1024)
            if payload.startswith(b'exitlane-d5-protected-'):count+=1
threading.Thread(target=receive,daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(str(count).encode())
    def log_message(self,*args):pass
http.server.HTTPServer(('0.0.0.0',8991),Handler).serve_forever()
'''

CLIENT = r'''
import configparser,ipaddress,json,subprocess,sys
v=json.load(sys.stdin);p=configparser.ConfigParser(interpolation=None);p.optionxform=str;p.read_string(v['config'])
def run(*args,input=None,check=True):
    r=subprocess.run(args,input=input,text=True,capture_output=True,check=False)
    if check and r.returncode:raise RuntimeError('synthetic peer configuration failed')
    return r.returncode
if run('ip','link','show','dev','wg-client',check=False):run('ip','link','add','dev','wg-client','type','wireguard')
payload='[Interface]\nPrivateKey = '+p['Interface']['PrivateKey']+'\n[Peer]\n'
for key in ('PublicKey','PresharedKey','AllowedIPs','PersistentKeepalive'):
    if key in p['Peer']:payload+=key+' = '+p['Peer'][key]+'\n'
payload+='Endpoint = '+str(ipaddress.IPv4Address(v['endpoint']))+':51820\n'
run('wg','setconf','wg-client','/dev/stdin',input=payload)
run('ip','address','replace',p['Interface']['Address'],'dev','wg-client')
run('ip','link','set','dev','wg-client','up')
for destination in ('10.77.0.1',v['target']):
    run('ip','route','replace',str(ipaddress.IPv4Address(destination))+'/32','dev','wg-client')
print(json.dumps({'configured':True}))
'''


class ApplianceHarness:
    def __init__(self, image, *, diagnostic=False):
        self.image = image
        self.prefix = 'exitlane-d5-' + uuid.uuid4().hex[:12]
        self.network = self.prefix + '-network'
        self.volume = self.prefix + '-state'
        self.containers = []
        self.images = []
        self.network_created = self.volume_created = False
        self.receipts = []
        self.diagnostic = diagnostic
        self.secrets = []
        self.artifacts = Path(tempfile.mkdtemp(prefix='exitlane-d5-'))

    @staticmethod
    def docker(*args, data=None, check=True, timeout=40):
        result = subprocess.run(['docker', *args], input=data, capture_output=True,
                                text=True, timeout=timeout, check=False)
        if check and result.returncode:
            raise RuntimeError('appliance Docker operation failed')
        return result

    def execute(self, name, *args, data=None, check=True):
        return self.docker('exec', '-i', name, *args, data=data, check=check)

    def python(self, name, source, *, data=None, check=True):
        return self.execute(name, 'python', '-c', source, data=data, check=check)

    def address(self, name):
        return json.loads(self.docker('inspect', name).stdout)[0]['NetworkSettings']['Networks'][self.network]['IPAddress']

    def wait(self, probe, stage, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if probe():
                self.receipts.append(stage)
                return
            time.sleep(.1)
        raise RuntimeError('appliance bounded gate failed: ' + stage)

    def helper(self, role, *, source=None, networking=False):
        name = self.prefix + '-' + role
        command = source or 'import time;time.sleep(1800)'
        arguments = ['create', '--name', name, '--network', self.network, '--init',
                    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                    '--tmpfs', '/run:rw,noexec,nosuid,mode=0700,size=8m', '--tmpfs', '/tmp:rw,noexec,nosuid,size=8m',
                    '--no-healthcheck', '-i']
        if networking:
            arguments.extend(('--cap-add', 'NET_ADMIN', '--device', '/dev/net/tun'))
        arguments.extend((self.image, 'python', '-u', '-c', command))
        self.docker(*arguments)
        self.containers.append(name)
        self.docker('start', name)
        return name

    def appliance(self, role, *, environment=(), image=None, ready=True):
        name = self.prefix + '-' + role
        arguments = ['create', '--name', name, '--network', self.network,
                     '--network-alias', 'exitlane-app', '--init',
                     '--read-only', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                     '--device', '/dev/net/tun', '--security-opt', 'no-new-privileges:true',
                     '--sysctl', 'net.ipv4.ip_forward=1', '--sysctl', 'net.ipv6.conf.all.forwarding=0',
                     '--sysctl', 'net.ipv6.conf.default.forwarding=0',
                     '--sysctl', 'net.ipv4.ping_group_range=0 0',
                     '--tmpfs', '/run:rw,noexec,nosuid,mode=0700,size=32m',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,mode=0700,size=32m',
                     '--mount', 'type=volume,src=' + self.volume + ',dst=/data',
                     '--memory', '512m', '--cpus', '1', '--pids-limit', '128',
                     '--log-opt', 'max-size=5m', '--log-opt', 'max-file=2']
        for entry in environment:
            arguments.extend(('--env', entry))
        arguments.append(image or self.image)
        if self.diagnostic:
            arguments.extend(('python', '-u', '-c', DIAGNOSTIC_ENTRY))
        self.docker(*arguments)
        self.containers.append(name)
        self.docker('start', name)
        if ready:
            self.wait(lambda: self.execute(name, 'python', '-m', 'exitlane.container_entrypoint',
                                           'health', check=False).returncode == 0, role + ' readiness')
            self.inspect(name)
        return name

    def replacement_image(self):
        # A distinct immutable identity with the same installed code/schema.
        # This proves replacement mechanics, not cross-version migrations.
        base = self.prefix + '-base:fixture'
        replacement = self.prefix + '-replacement:fixture'
        self.docker('image', 'tag', self.image, base)
        self.images.append(base)
        self.docker('build', '--pull=false', '--network=none', '-t', replacement, '-',
                    data=f'FROM {base}\nLABEL org.exitlane.qualification="D5-replacement-fixture"\n',
                    timeout=120)
        self.images.append(replacement)
        identity = json.loads(self.docker('image', 'inspect', replacement).stdout)[0]['Id']
        assert identity != self.image
        return identity

    def offline_schema(self, value):
        name = self.prefix + '-schema-' + str(value)
        self.docker('create', '--name', name, '--network', 'none', '--read-only',
                    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                    '--no-healthcheck', '--mount', 'type=volume,src=' + self.volume + ',dst=/data',
                    self.image, 'python', '-c',
                    'import sqlite3; '
                    'c=sqlite3.connect("file:/data/state/exitlane.db?mode=rw",uri=True); '
                    f'c.execute("UPDATE schema_version SET version=? WHERE singleton=1",({value},)); '
                    'c.commit();c.close()')
        self.containers.append(name)
        self.docker('start', name)
        self.wait(lambda: json.loads(self.docker('inspect', name).stdout)[0]['State']['Status'] == 'exited',
                  'offline synthetic schema ' + str(value))
        assert json.loads(self.docker('inspect', name).stdout)[0]['State']['ExitCode'] == 0

    def inspect(self, name):
        facts = json.loads(self.docker('inspect', name).stdout)[0]
        host = facts['HostConfig']
        assert host['ReadonlyRootfs'] and not host['Privileged'] and host['Init']
        assert host['CapDrop'] == ['ALL']
        assert host['CapAdd'] in (['NET_ADMIN'], ['CAP_NET_ADMIN'])
        assert host['NetworkMode'] == self.network and host['PidMode'] != 'host'
        assert not host['Binds'] and host['PidsLimit'] == 128
        assert any('no-new-privileges' in value for value in host['SecurityOpt'])
        assert [(m['Type'], m['Destination']) for m in facts['Mounts']] == [('volume', '/data')]
        code = "from pathlib import Path; import json; v=Path('/proc/self/status').read_text().splitlines(); print(json.dumps({k:next(x.split()[1] for x in v if x.startswith(k+':')) for k in ('CapEff','NoNewPrivs')}))"
        status = json.loads(self.python(name, code).stdout)
        assert int(status['CapEff'], 16) == 1 << 12 and status['NoNewPrivs'] == '1'
        assert self.python(name, "from pathlib import Path;Path('/image-write-refused').touch()", check=False).returncode != 0
        self.receipts.append('readonly minimal privilege inspect')

    def request(self, client, address, path, *, method='GET', body=None, cookie='', headers=None, port=8787):
        selected = dict(headers or {})
        if cookie:
            selected['Cookie'] = cookie
        payload = {'address': address, 'port': port, 'path': path, 'method': method,
                   'body': body, 'headers': selected}
        return json.loads(self.python(client, HTTP, data=json.dumps(payload)).stdout)

    @staticmethod
    def cookie(response):
        values = response['cookies']
        for name in ('exitlane_session=', 'exitlane_mfa_challenge='):
            for value in values:
                if value.startswith(name) and 'Max-Age=0' not in value:
                    return value.split(';', 1)[0]
        raise RuntimeError('expected live synthetic authentication cookie missing')

    def cleanup(self):
        for name in reversed(self.containers):
            logs = self.docker('logs', '--tail', '100', name, check=False)
            safe = (logs.stdout + logs.stderr)[-32768:]
            for value in self.secrets:
                safe = safe.replace(value, '[synthetic secret omitted]')
            descriptor = os.open(self.artifacts / (name + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                output.write(safe)
            self.docker('rm', '-f', name, check=False)
        if self.volume_created:
            self.docker('volume', 'rm', self.volume, check=False)
        if self.network_created:
            self.docker('network', 'rm', self.network, check=False)
        for image in reversed(self.images):
            self.docker('image', 'rm', image, check=False)

    def run(self):
        self.image = json.loads(self.docker('image', 'inspect', self.image).stdout)[0]['Id']
        replacement_image = self.replacement_image()
        self.docker('network', 'create', self.network)
        self.network_created = True
        self.docker('volume', 'create', self.volume)
        self.volume_created = True
        client = self.helper('client', networking=True)
        target = self.helper('target', source=TARGET)
        target_address = self.address(target)
        first = self.appliance('first')
        address = self.address(first)
        assert self.request(client, address, '/')['status'] == 200
        assert self.request(client, address, '/api/runtime/capabilities')['status'] == 401
        password = 'synthetic-only-' + secrets.token_hex(18)
        self.secrets.append(password)
        created = self.request(client, address, '/api/setup/admin', method='POST',
                               body={'username': 'synthetic_admin', 'password': password})
        assert created['status'] == 200
        cookie = self.cookie(created)
        caps = self.request(client, address, '/api/runtime/capabilities', cookie=cookie)['body']
        assert caps['runtime'] == 'container' and caps['supported'] is False
        assert set(caps['providers']) == {'mullvad', 'pia', 'proton'}
        assert not caps['native_upgrade'] and not caps['package_installation'] and not caps['direct_egress']
        self.wait(lambda: self.request(client, target_address, '/', port=8991)['status'] == 200,
                  'synthetic fallback observer available')
        self.python(client, "import socket,json,sys;v=json.load(sys.stdin);s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'exitlane-d5-protected-positive-control',(v['target'],7777))",
                    data=json.dumps({'target': target_address}))
        self.wait(lambda: self.request(client, target_address, '/', port=8991)['body'] == 1,
                  'plaintext observer positive control')
        ingress = self.request(client, address, '/api/ingress/wireguard', method='POST', cookie=cookie,
                               body={'endpoint': address, 'interface': 'wg-office', 'subnet': '10.77.0.0/24',
                                     'client': 'synthetic_router', 'dns': '10.64.0.1', 'port': 51820})
        assert ingress['status'] == 200
        profile = self.request(client, address, '/api/ingress/wireguard/config', cookie=cookie)
        assert profile['status'] == 200 and profile['body']['available']
        configuration = profile['body']['configuration']
        self.secrets.append(configuration)
        self.python(client, CLIENT, data=json.dumps({'config': configuration, 'endpoint': address,
                                                     'target': target_address}))
        self.wait(lambda: self.request(client, '10.77.0.1', '/api/health')['status'] == 200,
                  'actual API ingress encrypted client positive')
        self.docker('exec', '--detach', client, 'python', '-c',
                    "import json,socket,time;from pathlib import Path; "
                    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);attempts=0; "
                    "deadline=time.monotonic()+600\nwhile time.monotonic()<deadline:\n"
                    f" s.sendto(b'exitlane-d5-protected-continuous',('{target_address}',7777));attempts+=1;"
                    "Path('/run/d5-probe.json').write_text(json.dumps({'attempts':attempts,'time':time.monotonic()}));time.sleep(.05)")
        self.receipts.append('real parent child ingress no-provider block')
        spoofed = self.request(client, address, '/api/deployment/security', cookie=cookie,
                               headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '198.51.100.8'})
        assert spoofed['body']['https'] is False and spoofed['body']['direct_peer_trusted'] is False
        assert 'forwarded_headers_ignored' in spoofed['body']['warnings']
        rejected = self.request(client, address, '/api/auth/login', method='POST',
                                body={'username': 'synthetic_admin', 'password': password},
                                headers={'Origin': 'https://untrusted.example'})
        assert rejected['status'] == 403
        enrollment = self.request(client, address, '/api/auth/mfa/enrollment', method='POST',
                                  cookie=cookie, body={'current_password': password})
        assert enrollment['status'] == 200
        setup = enrollment['body']
        self.secrets.append(setup['setup_key'])
        code = self.python(client, "import json,sys,pyotp;print(pyotp.TOTP(json.load(sys.stdin)['key']).now())",
                           data=json.dumps({'key': setup['setup_key']})).stdout.strip()
        confirmed = self.request(client, address, '/api/auth/mfa/enrollment/confirm', method='POST',
                                 cookie=cookie, body={'enrollment': setup['enrollment'], 'code': code})
        assert confirmed['status'] == 200
        recovery_code = confirmed['body']['recovery_codes'][0]
        self.secrets.extend(confirmed['body']['recovery_codes'])
        self.receipts.append('actual first-run auth MFA and untrusted headers')
        original = json.loads(self.python(first, PAIR).stdout)
        self.docker('stop', '--time', '15', first)
        self.docker('rm', first)
        self.containers.remove(first)
        second = self.appliance('replacement', image=replacement_image)
        assert json.loads(self.docker('inspect', second).stdout)[0]['Image'] == replacement_image
        assert json.loads(self.python(second, PAIR).stdout) == original
        second_address = self.address(second)
        self.python(client, CLIENT, data=json.dumps({'config': configuration, 'endpoint': second_address,
                                                     'target': target_address}))
        self.wait(lambda: self.request(client, '10.77.0.1', '/api/health')['status'] == 200,
                  'guarded ingress recreation encrypted client positive')
        assert self.request(second, target_address, '/', port=8991)['body'] == 1
        login = self.request(client, second_address, '/api/auth/login', method='POST',
                             body={'username': 'synthetic_admin', 'password': password})
        assert login['status'] == 200 and login['body']['mfa_required']
        challenge = self.cookie(login)
        verified = self.request(client, second_address, '/api/auth/mfa', method='POST', cookie=challenge,
                                body={'code': recovery_code, 'mode': 'recovery'})
        assert verified['status'] == 200
        self.receipts.append('digest replacement preserves DB key and MFA')
        self.docker('stop', '--time', '15', second)
        self.docker('rm', second)
        self.containers.remove(second)
        proxy = self.helper('proxy', source=PROXY.replace(
            'v=json.loads(sys.stdin.readline())', "v={'upstream':'exitlane-app'}"))
        proxy_address = self.address(proxy)
        third = self.appliance('proxy-replacement', environment=(
            'EXITLANE_PUBLIC_URL=https://exitlane.example.internal',
            'EXITLANE_TRUSTED_PROXIES=' + proxy_address + '/32'))
        assert json.loads(self.python(third, PAIR).stdout) == original
        self.python(client, CLIENT, data=json.dumps({'config': configuration, 'endpoint': self.address(third),
                                                     'target': target_address}))
        self.wait(lambda: self.request(client, '10.77.0.1', '/api/health')['status'] == 200,
                  'second ingress recreation encrypted client positive')
        origin = {'Origin': 'https://exitlane.example.internal',
                  'X-Forwarded-Proto': 'http', 'X-Forwarded-For': '198.51.100.8'}
        self.wait(lambda: self.request(client, proxy_address, '/api/health', port=8990)['status'] == 200,
                  'actual proxy transport')
        login = self.request(client, proxy_address, '/api/auth/login', method='POST', port=8990,
                             body={'username': 'synthetic_admin', 'password': password}, headers=origin)
        assert login['status'] == 200 and login['body']['mfa_required']
        assert 'Secure' in login['headers']['set-cookie']
        verified = self.request(client, proxy_address, '/api/auth/mfa', method='POST', port=8990,
                                cookie=self.cookie(login), headers=origin,
                                body={'code': confirmed['body']['recovery_codes'][1], 'mode': 'recovery'})
        assert verified['status'] == 200 and 'Secure' in verified['headers']['set-cookie']
        cookie = self.cookie(verified)
        security = self.request(client, proxy_address, '/api/deployment/security', port=8990,
                                cookie=cookie, headers=origin)
        assert security['status'] == 200
        assert security['body']['https'] and security['body']['reverse_proxy']
        assert security['body']['direct_peer_trusted'] and security['body']['direct_peer'] == proxy_address
        assert security['headers']['strict-transport-security'] == 'max-age=31536000'
        bad_origin = self.request(client, proxy_address, '/api/auth/login', method='POST', port=8990,
                                  body={'username': 'synthetic_admin', 'password': password},
                                  headers={'Origin': 'https://untrusted.example'})
        assert bad_origin['status'] == 403
        untrusted = self.request(client, self.address(third), '/api/deployment/security', cookie=cookie,
                                headers={'X-Forwarded-Proto': 'https', 'X-Forwarded-For': '198.51.100.8'})
        assert not untrusted['body']['direct_peer_trusted'] and not untrusted['body']['https']
        self.receipts.append('actual proxy peer HTTPS origin MFA cookies and direct spoof refusal')
        passphrase = 'synthetic-backup-' + secrets.token_hex(16)
        self.secrets.append(passphrase)
        backup = self.execute(third, 'python', '-m', 'exitlane.container_cli', 'backup',
                              '--passphrase-stdin', data=passphrase + '\n')
        backup_name = json.loads(backup.stdout)['name']
        restored = self.execute(third, 'python', '-m', 'exitlane.container_cli', 'restore',
                                '--name', backup_name, '--confirm', 'RESTORE EXITLANE',
                                '--passphrase-stdin', data=passphrase + '\n')
        assert json.loads(restored.stdout)['restored'] is True
        self.wait(lambda: self.execute(third, 'python', '-m', 'exitlane.container_entrypoint',
                                       'health', check=False).returncode == 0, 'real worker restore health')
        self.wait(lambda: self.request(client, '10.77.0.1', '/api/health')['status'] == 200,
                  'restore guarded ingress encrypted client positive')
        assert self.request(third, target_address, '/', port=8991)['body'] == 1
        logs_result = self.docker('logs', third)
        logs = logs_result.stdout + logs_result.stderr
        assert password not in logs and passphrase not in logs and setup['setup_key'] not in logs
        self.receipts.append('real supervisor backup restore and secret omission')
        self.docker('stop', '--time', '15', third)
        self.offline_schema(999)
        refused = self.appliance('incompatible-schema', image=replacement_image, ready=False)
        self.wait(lambda: json.loads(self.docker('inspect', refused).stdout)[0]['State']['Status'] == 'exited',
                  'actual incompatible schema startup refusal')
        assert json.loads(self.docker('inspect', refused).stdout)[0]['State']['ExitCode'] != 0
        self.offline_schema(1)  # Restore the synthetic fault, not an application migration.
        rollback = self.appliance('rollback', image=self.image)
        assert json.loads(self.python(rollback, PAIR).stdout) == original
        self.python(client, CLIENT, data=json.dumps({'config': configuration, 'endpoint': self.address(rollback),
                                                     'target': target_address}))
        self.wait(lambda: self.request(client, '10.77.0.1', '/api/health')['status'] == 200,
                  'previous image rollback encrypted client positive')
        assert self.request(rollback, target_address, '/', port=8991)['body'] == 1
        active = self.python(client, "import json,time;from pathlib import Path; "
                             "v=json.loads(Path('/run/d5-probe.json').read_text()); "
                             "assert v['attempts']>100 and time.monotonic()-v['time']<3;print('active')")
        assert active.stdout.strip() == 'active'
        self.receipts.append('same schema previous digest rollback preserves DB key and guard')
        return {'result': 'PASS', 'image': self.image, 'replacement_image': replacement_image, 'checks': self.receipts,
                'scope': 'D5 local image/management; no host or daemon restart qualification'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', default='exitlane-appliance:test')
    parser.add_argument('--diagnostic', action='store_true', help='Bounded exception-frame receipt for local diagnosis')
    args = parser.parse_args()
    harness = ApplianceHarness(args.image, diagnostic=args.diagnostic)
    try:
        print(json.dumps(harness.run(), sort_keys=True))
    finally:
        harness.cleanup()


if __name__ == '__main__':
    main()
