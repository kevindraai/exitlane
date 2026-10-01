#!/usr/bin/env python3
"""Isolated D2 kernel proof; never publishes an image or restarts the Docker host.

Run after building docker/testing/Dockerfile.lifecycle. Every resource has a unique
test-owned name. Cleanup deletes only resources created by this invocation.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import uuid

WORKER = '''
import http.server, os, socket, threading
from pathlib import Path
Path("/run/worker.pid").write_text(str(os.getpid()))
def echo():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("10.77.0.1", 5666))
        while True:
            data, peer = s.recvfrom(1024)
            s.sendto(data, peer)
threading.Thread(target=echo, daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"synthetic worker")
    def log_message(self, *args): pass
http.server.HTTPServer(("0.0.0.0", 8989), Handler).serve_forever()
'''

ENTRY = '''
import asyncio, json, os, sys
from pathlib import Path
from exitlane.container_runtime import IngressConfig, ContainerWireGuardLifecycle, ContainerSupervisor
Path("/run/supervisor.pid").write_text(str(os.getpid()))
os.mkfifo("/run/exitlane-boot", 0o600)
with open("/run/exitlane-boot") as source:
    boot = json.load(source)
os.unlink("/run/exitlane-boot")
async def main():
    network = ContainerWireGuardLifecycle(IngressConfig(**boot["config"]))
    async def worker():
        return await asyncio.create_subprocess_exec(sys.executable, "-u", "-c", boot["worker"])
    return await ContainerSupervisor(network, worker, restart_budget=2, stop_timeout=2).run()
try:
    sys.exit(asyncio.run(main()))
except Exception as error:
    print(getattr(error, "code", "synthetic_lifecycle_failed"), flush=True)
    sys.exit(2)
'''

TARGET = '''
import http.server, socket, threading
packets = []
def receive():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 7777))
        while True:
            data, peer = s.recvfrom(1024)
            if data.startswith(b"exitlane-d2-protected-"):
                packets.append(data.decode("ascii"))
threading.Thread(target=receive, daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(str(len(packets)).encode())
    def log_message(self, *args): pass
http.server.HTTPServer(("0.0.0.0", 8989), Handler).serve_forever()
'''


class Harness:
    def __init__(self, image: str):
        self.image = image
        self.prefix = "exitlane-d2-" + uuid.uuid4().hex[:12]
        self.network = self.prefix + "-network"
        self.resources: list[str] = []
        self.network_created = False

    @staticmethod
    def docker(*args: str, data: str | None = None, check=True, timeout=30):
        result = subprocess.run(
            ["docker", *args], input=data, text=True, capture_output=True, timeout=timeout,
            check=False,
        )
        if check and result.returncode:
            # Docker stderr can contain the invoked command. Keep secrets and
            # configuration out of failure evidence; logs are inspected separately.
            raise RuntimeError("synthetic Docker operation failed")
        return result

    def execute(self, name: str, *args: str, data=None, check=True):
        return self.docker("exec", "-i", name, *args, data=data, check=check)

    def python(self, name: str, source: str, *, data=None, check=True):
        return self.execute(name, "python", "-c", source, data=data, check=check)

    def create(self, role: str, source: str | None = None):
        name = self.prefix + "-" + role
        args = [
            "create", "--name", name, "--network", self.network, "--init",
            "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
            "--device", "/dev/net/tun", "--security-opt", "no-new-privileges:true",
            "--sysctl", "net.ipv4.ip_forward=1", "--tmpfs", "/run:rw,mode=0700",
            "--tmpfs", "/data:rw,mode=0700", self.image,
        ]
        if source is not None:
            args.extend(("python", "-u", "-c", source))
        self.docker(*args)
        self.resources.append(name)
        self.docker("start", name)
        return name

    def address(self, name: str):
        facts = json.loads(self.docker("inspect", name).stdout)[0]
        validate_capabilities(facts["HostConfig"]["CapAdd"])
        assert facts["HostConfig"]["CapDrop"] == ["ALL"]
        assert not facts["HostConfig"]["Privileged"]
        assert facts["HostConfig"]["NetworkMode"] == self.network
        effective = self.python(name, 'from pathlib import Path; print(next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:")))').stdout.strip()
        assert int(effective, 16) == 1 << 12, "effective capabilities must be NET_ADMIN only"
        return facts["NetworkSettings"]["Networks"][self.network]["IPAddress"]

    def wait(self, predicate, description: str, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.1)
        raise RuntimeError("bounded synthetic probe failed: " + description)

    def http(self, client: str, address: str):
        return self.python(client, f'import urllib.request; print(urllib.request.urlopen("http://{address}:8989/", timeout=1).read().decode())', check=False)

    def keypair(self, client: str):
        private = self.execute(client, "wg", "genkey").stdout.strip()
        public = self.execute(client, "wg", "pubkey", data=private + "\n").stdout.strip()
        return private, public

    def send(self, client: str, target: str, marker: str):
        self.python(client, f'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"exitlane-d2-protected-{marker}", ("{target}",7777))')

    def run(self):
        self.docker("network", "create", "--internal", self.network)
        self.network_created = True
        client = self.create("client")
        target = self.create("target", TARGET)
        appliance = self.create("appliance", ENTRY)
        target_ip, appliance_ip = self.address(target), self.address(appliance)
        private, public = self.keypair(client)
        server_private, server_public = self.keypair(client)
        boot = {"config": {
            "interface": "wg-office", "address": "10.77.0.1/24",
            "private_key": server_private, "public_key": public,
            "allowed_ips": "10.77.0.2/32", "listen_port": 51820,
        }, "worker": WORKER}
        self.wait(lambda: self.execute(appliance, "test", "-p", "/run/exitlane-boot", check=False).returncode == 0, "private bootstrap pipe")
        self.python(appliance, 'import sys; f=open("/run/exitlane-boot","w"); f.write(sys.stdin.read()); f.close()', data=json.dumps(boot))
        self.wait(lambda: self.http(client, appliance_ip).returncode == 0, "protected startup before worker")
        self.execute(client, "ip", "link", "add", "dev", "wg-client", "type", "wireguard")
        payload = f"[Interface]\nPrivateKey = {private}\n[Peer]\nPublicKey = {server_public}\nEndpoint = {appliance_ip}:51820\nAllowedIPs = 10.77.0.1/32,{target_ip}/32\nPersistentKeepalive = 1\n"
        self.execute(client, "wg", "setconf", "wg-client", "/dev/stdin", data=payload)
        self.execute(client, "ip", "address", "add", "10.77.0.2/32", "dev", "wg-client")
        self.execute(client, "ip", "link", "set", "wg-client", "up")
        for destination in ("10.77.0.1", target_ip):
            self.execute(client, "ip", "route", "replace", destination + "/32", "dev", "wg-client")
        echo = 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b"d2-wg-proof",("10.77.0.1",5666)); assert s.recv(1024)==b"d2-wg-proof"'
        self.wait(lambda: self.python(client, echo, check=False).returncode == 0, "usable encrypted ingress")
        # Keep bounded fixture traffic active through every lifecycle transition,
        # so the final zero count also catches delayed delivery after a read.
        heartbeat = f'''import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
deadline=time.monotonic()+180
while time.monotonic()<deadline:
    s.sendto(b"exitlane-d2-protected-heartbeat",("{target_ip}",7777))
    time.sleep(0.05)
'''
        self.docker("exec", "--detach", client, "python", "-c", heartbeat)
        self.send(client, target_ip, "no-provider")
        assert self.http(client, appliance_ip).returncode == 0
        # Target HTTP must use the normal management route, not protected WG.
        count = self.http(appliance, target_ip)
        assert count.returncode == 0 and count.stdout.strip() == "0"
        print("PASS: minimal capabilities, usable WireGuard, no-provider plaintext blocked, management available")
        # Repeated worker crashes exercise the actual PID/init/restart budget.
        for attempt in range(3):
            old_pid = self.python(appliance, 'from pathlib import Path; print(Path("/run/worker.pid").read_text())').stdout.strip()
            self.python(appliance, 'import os,signal; from pathlib import Path; os.kill(int(Path("/run/worker.pid").read_text()),signal.SIGKILL)')
            if attempt < 2:
                self.wait(lambda previous=old_pid: self.python(appliance, 'from pathlib import Path; print(Path("/run/worker.pid").read_text())', check=False).stdout.strip() not in ("", previous), "new worker generation")
                self.wait(lambda: self.python(client, echo, check=False).returncode == 0, "guarded worker restart")
                self.send(client, target_ip, "restart-" + str(attempt))
                assert self.http(appliance, target_ip).stdout.strip() == "0"
            else:
                self.wait(lambda: not json.loads(self.docker("inspect", appliance).stdout)[0]["State"]["Running"], "bounded exhaustion exits container")
        facts = json.loads(self.docker("inspect", appliance).stdout)[0]
        assert facts["State"]["ExitCode"] == 1
        print("PASS: bounded guarded worker restart; exhaustion exits the init-owned container")
        # A container recreation/start gets a new namespace: protection must be
        # reconstructed before the fixture worker or ingress becomes usable.
        def restart_appliance():
            self.docker("start", appliance)
            self.wait(lambda: self.execute(appliance, "test", "-p", "/run/exitlane-boot", check=False).returncode == 0, "new namespace bootstrap pipe")
            self.python(appliance, 'import sys; f=open("/run/exitlane-boot","w"); f.write(sys.stdin.read()); f.close()', data=json.dumps(boot))
            self.wait(lambda: self.python(client, echo, check=False).returncode == 0, "guarded container start")
            self.send(client, target_ip, "container-start")
            assert self.http(appliance, target_ip).stdout.strip() == "0"
        restart_appliance()
        self.docker("stop", "--time", "5", appliance)
        assert json.loads(self.docker("inspect", appliance).stdout)[0]["State"]["ExitCode"] == 0
        print("PASS: guarded container start and graceful SIGTERM")
        restart_appliance()
        self.python(appliance, 'import os,signal; from pathlib import Path; os.kill(int(Path("/run/supervisor.pid").read_text()),signal.SIGKILL)', check=False)
        self.wait(lambda: not json.loads(self.docker("inspect", appliance).stdout)[0]["State"]["Running"], "supervisor death terminates container")
        assert self.http(target, "127.0.0.1").stdout.strip() == "0"
        print("PASS: supervisor death leaves no surviving container worker")
        # Positive packet-path control has its own deliberately unsafe namespace;
        # never remove or weaken the candidate's permanent protection.
        unsafe = self.create("unsafe-control")
        unsafe_ip = self.address(unsafe)
        self.execute(unsafe, "ip", "link", "add", "dev", "wg-office", "type", "wireguard")
        payload = f"[Interface]\nPrivateKey = {server_private}\nListenPort = 51820\n[Peer]\nPublicKey = {public}\nAllowedIPs = 10.77.0.2/32\n"
        self.execute(unsafe, "wg", "setconf", "wg-office", "/dev/stdin", data=payload)
        self.execute(unsafe, "ip", "address", "add", "10.77.0.1/24", "dev", "wg-office")
        self.execute(unsafe, "ip", "link", "set", "wg-office", "up")
        # The intentionally unsafe gateway imitates ordinary plaintext fallback
        # with SNAT. This also provides a return route on the internal bridge;
        # it changes only this separate control container's namespace.
        self.execute(unsafe, "nft", "-f", "/dev/stdin", data='''table ip d2_unsafe_control {
chain postrouting {
type nat hook postrouting priority srcnat; policy accept;
iifname "wg-office" oifname "eth0" masquerade
}
}
''')
        payload = f"[Interface]\nPrivateKey = {private}\n[Peer]\nPublicKey = {server_public}\nEndpoint = {unsafe_ip}:51820\nAllowedIPs = 10.77.0.1/32,{target_ip}/32\nPersistentKeepalive = 1\n"
        self.execute(client, "wg", "setconf", "wg-client", "/dev/stdin", data=payload)
        def control_packet_received():
            self.send(client, target_ip, "unsafe-control")
            result = self.http(unsafe, target_ip)
            return result.returncode == 0 and int(result.stdout.strip()) > 0
        self.wait(control_packet_received, "positive unsafe plaintext detection")
        print("PASS: separate unsafe control proves target detects protected plaintext")

    def cleanup(self):
        for name in reversed(self.resources):
            self.docker("rm", "--force", name, check=False)
        if self.network_created:
            self.docker("network", "rm", self.network, check=False)


def validate_capabilities(capabilities):
    # Docker API versions may normalize the Linux CAP_ prefix. Preserve the
    # exact one-capability contract and verify the effective kernel mask too.
    assert capabilities in (["NET_ADMIN"], ["CAP_NET_ADMIN"]), capabilities


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="exitlane-lifecycle:test")
    harness = Harness(parser.parse_args().image)
    try:
        harness.run()
    finally:
        harness.cleanup()
