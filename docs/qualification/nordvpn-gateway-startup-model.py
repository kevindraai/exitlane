"""Credential-free model of a reachable pre-firewall gateway state, not upstream-image proof."""
import json
import subprocess
import time
import uuid

image = 'sha256:b107c1765cadd93e17d274881030b5028417b6c1a425692cdf338365bac099e7'
prefix = 'el-gateway-model-' + uuid.uuid4().hex[:10]
networks, containers = [], []

def docker(*args, data=None):
    result=subprocess.run(['docker', *args], input=data, text=True, capture_output=True, timeout=40)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout

def run(role, network):
    name = prefix + '-' + role
    docker('run', '-d', '--name', name, '--label', 'org.exitlane.qualification='+prefix,
           '--network', network, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
           '--security-opt', 'no-new-privileges:true', '--sysctl', 'net.ipv4.ip_forward=1',
           image)
    containers.append(name)
    docker('exec',name,'ip','route','del','default')
    return name

def address(container, network):
    return json.loads(docker('inspect', container))[0]['NetworkSettings']['Networks'][network]['IPAddress']

def observe(sender, destination, marker):
    code = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',45678)); s.settimeout(2); print('READY',flush=True)\ntry: print(s.recv(2048).decode(),flush=True)\nexcept TimeoutError: print('DROP',flush=True)"
    process = subprocess.Popen(['docker','exec',target,'python','-u','-c',code], stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert process.stdout.readline().strip() == 'READY'
    docker('exec',sender,'python','-c',"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto("+repr(marker.encode())+",("+repr(destination)+",45678))")
    output, error = process.communicate(timeout=6)
    assert process.returncode == 0, error
    return output.strip()

try:
    for role in ('transit','uplink'):
        name=prefix+'-'+role
        docker('network','create','--opt','com.docker.network.bridge.enable_ip_masquerade=false','--label','org.exitlane.qualification='+prefix,name)
        networks.append(name)
    transit,uplink=networks
    helper=run('helper',uplink)
    docker('network','connect',transit,helper)
    # Docker can install another default when attaching the second network.
    docker('exec',helper,'ip','route','del','default')
    client=run('client',transit)
    target=run('target',uplink)
    hip=address(helper,transit); tip=address(target,uplink)
    docker('exec',client,'ip','route','add',tip+'/32','via',hip)
    # Internal networks have no default route: explicitly return to the sender
    # through this helper, including strict reverse-path validation at target.
    docker('exec',target,'ip','route','add',address(client,transit)+'/32','via',address(helper,uplink))
    before_rules=docker('exec',helper,'nft','list','ruleset')
    assert 'default' not in docker('exec',helper,'ip','route')
    links=json.loads(docker('exec',helper,'ip','-j','link'))
    assert not any(x['ifname'].startswith('wg') for x in links)
    print(json.dumps({'helper_routes':docker('exec',helper,'ip','route'),
      'helper_forwarding':docker('exec',helper,'cat','/proc/sys/net/ipv4/ip_forward'),
      'helper_rules':before_rules}),flush=True)
    pid=json.loads(docker('inspect',helper))[0]['State']['Pid']
    capture_code="import socket,time; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3)); s.bind(('eth0',0)); s.settimeout(0.2); end=time.monotonic()+4; print('READY',flush=True); found=False\nwhile time.monotonic()<end:\n try:\n  data=s.recv(65535)\n  if "+repr((prefix+'-pre-init').encode())+" in data: found=True\n except TimeoutError: pass\nprint('MARKER' if found else 'ABSENT',flush=True)"
    capture=subprocess.Popen(['nsenter','-t',str(pid),'-n','python3','-u','-c',capture_code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert capture.stdout.readline().strip()=='READY'
    before=observe(client,tip,prefix+'-pre-init')
    captured,error=capture.communicate(timeout=6)
    print(json.dumps({'target':before,'helper_uplink_capture':captured.strip(),'capture_error':error}),flush=True)
    assert captured.strip()=='MARKER', captured
    docker('exec','-i',helper,'nft','-f','-',data='add table inet gateway_model\nadd chain inet gateway_model guard { type filter hook forward priority 0; policy drop; }\n')
    after=observe(client,tip,prefix+'-guarded')
    assert after=='DROP',after
    control=observe(helper,tip,prefix+'-control')
    assert control==prefix+'-control',control
    print(json.dumps({'result':'MODEL CONFIRMED','upstream_image_exploitability':'INCONCLUSIVE',
      'scope':'Synthetic pre-entrypoint namespace; no upstream image or Nord credentials used',
      'image':image,'initial_rules':before_rules,'pre_guard_target_observation':before,
      'post_guard_target_observation':after,'positive_control':control,
      'boundary':'Dedicated non-masquerading Docker bridges, all container default routes removed; no published ports or physical uplink target'}))
finally:
    for name in reversed(containers): docker('rm','-f',name)
    for name in reversed(networks): docker('network','rm',name)
