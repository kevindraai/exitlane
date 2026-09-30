#!/usr/bin/env python3
"""Bounded D3 synthetic packet qualification; never production host networking.

All bridges/containers belong to this invocation. Synthetic globally classified
endpoints use owned bridges with explicit tiny IPAM. The normal bridge has
masquerading disabled; every fixture loses its host-gateway route before starting.
The external bridge is internal. Secrets travel on stdin only.
Observers use NET_RAW externally; every candidate/fixture has only NET_ADMIN.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from container_lifecycle import Harness, validate_capabilities


def validate_rollback_receipt(result, snapshot, *, source_loss):
    assert result.get("ok") is False
    assert result.get("error_code") == "provider_switch_failed", result
    assert result.get("http_status") == 400, result
    assert snapshot.get("ok") is True, snapshot
    assert snapshot.get("operation_state") == "idle", snapshot
    assert snapshot.get("outer_transition") is source_loss, snapshot
    if source_loss:
        assert snapshot.get("candidate_committed") is False, snapshot
    else:
        assert snapshot.get("candidate_provider") == "mullvad", snapshot
        assert snapshot.get("candidate_committed") is True, snapshot

TARGET = """
import http.server,json,socket,threading
counts={}
def record(data,protocol):
    prefix=b"exitlane-d3-protected-"
    if data.startswith(prefix):
        phase=data[len(prefix):].split(b":",1)[0].decode("ascii")
        counts[phase]=counts.get(phase,0)+1
        tagged=phase+"-"+protocol;counts[tagged]=counts.get(tagged,0)+1
def listeners(udp_port=7777,tcp_port=7778):
    opened=[]
    try:
        udp4=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);opened.append(udp4)
        udp4.bind(("0.0.0.0",udp_port))
        udp6=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);opened.append(udp6)
        udp6.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        udp6.bind(("::",udp4.getsockname()[1]))
        tcp4=socket.socket();opened.append(tcp4)
        tcp4.bind(("0.0.0.0",tcp_port));tcp4.listen()
        return udp4,udp6,tcp4
    except Exception:
        for listener in opened: listener.close()
        raise
def udp(s,protocol):
    while True: record(s.recvfrom(2048)[0],protocol)
def tcp(s):
    while True:
        c,_=s.accept()
        with c: record(c.recv(2048),"tcp")
# All binds happen synchronously; any missing listener aborts before HTTP readiness.
udp4,udp6,tcp4=listeners()
counts["_listeners"]=["udp4","udp6","tcp4"]
threading.Thread(target=udp,args=(udp4,"udp"),daemon=True).start()
threading.Thread(target=udp,args=(udp6,"udp6"),daemon=True).start()
threading.Thread(target=tcp,args=(tcp4,),daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data=json.dumps(counts).encode(); self.send_response(200);self.end_headers();self.wfile.write(data)
    def log_message(self,*a): pass
http.server.HTTPServer(("0.0.0.0",8989),Handler).serve_forever()
"""
DNS = """
import socket,struct,threading,time
def answer(query):
    return query[:2]+struct.pack("!HHHHH",0x8180,1,1,0,0)+query[12:]+b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x04\\x01\\x01\\x01\\x01"
def udp():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0",53))
        while True:
            q,p=s.recvfrom(2048);s.sendto(answer(q),p)
def tcp():
    with socket.socket() as s:
        s.bind(("0.0.0.0",53));s.listen()
        while True:
            c,_=s.accept()
            with c:
                c.settimeout(2);h=c.recv(2)
                if len(h)!=2: continue
                n=struct.unpack("!H",h)[0];q=b""
                while len(q)<n:
                    piece=c.recv(n-len(q))
                    if not piece: break
                    q+=piece
                a=answer(q);c.sendall(struct.pack("!H",len(a))+a)
threading.Thread(target=udp,daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
time.sleep(900)
"""
SENDER = """
import socket,time,struct
from pathlib import Path
sequence=0;deadline=time.monotonic()+600
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
while time.monotonic()<deadline:
    try:
        phase=Path("/run/d3-phase").read_text().strip()
        marker=f"exitlane-d3-protected-{phase}:{sequence}".encode()
        udp.sendto(marker,("1.1.1.1",7777))
        if sequence%5==0:
            name=f"eld3-{phase}.invalid"
            labels=b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\\0"
            q=struct.pack("!HHHHHH",sequence%65536,0x100,1,0,0,0)+labels+b"\\0\\1\\0\\1"
            udp.sendto(q,("10.64.0.1",53))
            with socket.socket() as tcp:
                tcp.settimeout(.1);tcp.connect(("10.64.0.1",53));tcp.sendall(struct.pack("!H",len(q))+q);tcp.recv(1024)
            with socket.socket() as tcp:
                tcp.settimeout(.1);tcp.connect(("1.1.1.1",7778));tcp.sendall(marker)
    except OSError: pass
    sequence+=1;time.sleep(.02)
"""


class DataplaneHarness(Harness):
    def __init__(self, image):
        super().__init__(image)
        self.prefix = "exitlane-d3-" + uuid.uuid4().hex[:12]
        self.network = self.prefix + "-normal"
        self.external = self.prefix + "-external"
        self.created_networks = []
        self.roles = {}
        self.receipts = {}
        self.observers = {}
        self.observer_interfaces = {}
        self.previous_polls = {}
        self.source_known = False
        self.pia_source_known = False
        self.artifacts = Path(tempfile.mkdtemp(prefix="exitlane-d3-"))
        self.artifacts.chmod(0o700)

    def preflight(self):
        """Refuse host route/resolver overlap before creating either owned bridge."""
        ranges = [
            ipaddress.ip_network(value)
            for value in ("192.0.0.0/28", "1.1.1.0/29", "fd88::/64", "fd99::/64")
        ]
        for endpoint in ("192.0.0.9", "192.0.0.10", "1.1.1.1"):
            if not ipaddress.ip_address(endpoint).is_global:
                raise RuntimeError(
                    "synthetic endpoints must satisfy production public-IP validation"
                )
        resolvers = []
        for path in (
            Path("/etc/resolv.conf"),
            Path("/run/systemd/resolve/resolv.conf"),
        ):
            if path.exists():
                for line in path.read_text().splitlines():
                    fields = line.split()
                    if len(fields) >= 2 and fields[0] == "nameserver":
                        address = ipaddress.ip_address(fields[1].split("%", 1)[0])
                        resolvers.append(address)
                        if any(address in network for network in ranges):
                            raise RuntimeError(
                                "synthetic bridge overlaps a configured host DNS resolver"
                            )
        if any(address.is_loopback for address in resolvers) and not any(
            not address.is_loopback for address in resolvers
        ):
            raise RuntimeError("host stub DNS upstream cannot be safely validated")
        destinations = []
        for family in ("-4", "-6"):
            routes = subprocess.run(
                ["ip", family, "-j", "route", "show", "table", "all"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            destinations.extend(
                item["dst"]
                for item in json.loads(routes.stdout)
                if item.get("dst") not in (None, "default", "0.0.0.0/0", "::/0")
            )
        identifiers = self.docker("network", "ls", "--quiet").stdout.split()
        if identifiers:
            for facts in json.loads(
                self.docker("network", "inspect", *identifiers).stdout
            ):
                config = facts.get("IPAM", {}).get("Config")
                if (
                    config is None
                    and facts.get("Driver") in ("host", "null")
                    and facts.get("Name") in ("host", "none")
                ):
                    continue
                if not isinstance(config, list):
                    raise TypeError("unable to validate existing Docker network IPAM")
                for item in config:
                    if not isinstance(item, dict) or not isinstance(
                        item.get("Subnet"), str
                    ):
                        raise TypeError(
                            "unable to validate existing Docker network subnet"
                        )
                    destinations.append(item["Subnet"])
        for destination in destinations:
            existing = ipaddress.ip_network(destination, strict=False)
            if any(
                existing.version == network.version and existing.overlaps(network)
                for network in ranges
            ):
                raise RuntimeError(
                    "synthetic bridge overlaps an existing host route or Docker subnet"
                )
        print("PASS: bounded bridge/resolver/route preflight", flush=True)

    def create_role(self, role, source=None, *, external=False, address=None):
        name = self.prefix + "-" + role
        arguments = [
            "create",
            "--name",
            name,
            "--network",
            self.external if external else self.network,
            "--dns",
            "192.0.0.9",
            "--init",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "--security-opt",
            "no-new-privileges:true",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--sysctl",
            "net.ipv6.conf.all.disable_ipv6=0",
            "--sysctl",
            "net.ipv6.conf.default.disable_ipv6=0",
            "--sysctl",
            "net.ipv6.conf.all.forwarding=1",
            "--tmpfs",
            "/run:rw,mode=0700",
            "--tmpfs",
            "/data:rw,mode=0700",
        ]
        ipv6 = {
            "client": "fd88::5",
            "relay": "fd88::1",
            "peer-a": "fd88::9",
            "peer-b": "fd88::10",
            "unsafe": "fd88::3",
            "appliance": "fd88::4",
            "target": "fd99::1",
        }[role]
        arguments.extend(["--ip6", ipv6])
        if address:
            arguments.extend(["--ip", address])
        arguments.append(self.image)
        arguments.extend(["python", "-u", "-c", "import time;time.sleep(900)"])
        self.docker(*arguments)
        self.resources.append(name)
        self.docker("start", name)
        self.execute(name, "ip", "route", "delete", "default", check=False)
        self.execute(name, "ip", "-6", "route", "delete", "default", check=False)
        ipv6_routes = json.loads(
            self.execute(name, "ip", "-6", "-j", "route", "show").stdout
        )
        assert not any(route.get("dst") == "default" for route in ipv6_routes)
        routes = json.loads(self.execute(name, "ip", "-j", "route", "show").stdout)
        assert not any(route.get("dst") == "default" for route in routes)
        if source:
            self.docker("exec", "--detach", name, "python", "-u", "-c", source)
        facts = json.loads(self.docker("inspect", name).stdout)[0]
        validate_capabilities(facts["HostConfig"]["CapAdd"])
        assert (
            facts["HostConfig"]["CapDrop"] == ["ALL"]
            and not facts["HostConfig"]["Privileged"]
        )
        assert (
            int(
                self.execute(
                    name,
                    "python",
                    "-c",
                    "from pathlib import Path; print(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')))",
                ).stdout.strip(),
                16,
            )
            == 1 << 12
        )
        self.roles[role] = name
        return name

    def ip(self, role, network=None):
        return json.loads(self.docker("inspect", self.roles[role]).stdout)[0][
            "NetworkSettings"
        ]["Networks"][network or self.network]["IPAddress"]

    def request(self, role, port, payload=None):
        source = f"""import json,sys,urllib.request,urllib.error
payload=json.load(sys.stdin) if {payload is not None!r} else None
body=json.dumps(payload).encode() if payload is not None else None
request=urllib.request.Request("http://127.0.0.1:{port}/",data=body,headers={{"Content-Type":"application/json"}})
try:
    print(urllib.request.urlopen(request,timeout=100).read(65536).decode())
except urllib.error.HTTPError as error:
    response=json.loads(error.read(4096));response['http_status']=error.code;print(json.dumps(response))
except (urllib.error.URLError,TimeoutError):
    print(json.dumps({{'ok':False,'error_code':'synthetic_http_unreachable','http_status':0}}))"""
        result = self.docker(
            "exec", "-i", self.roles[role], "python", "-c", source,
            data=json.dumps(payload) if payload is not None else None,
            timeout=120 if payload and payload.get("command") == "switch" else 30,
        )
        response = json.loads(result.stdout)
        if response.get("http_status") is not None or response.get("ok") is False:
            receipt = {
                key: response[key]
                for key in ("ok", "error_code", "http_status")
                if key in response
            }
            path = self.artifacts / "last-request-failure.json"
            path.write_text(json.dumps(receipt, sort_keys=True))
            path.chmod(0o600)
            print(
                "Synthetic operation failure:",
                json.dumps(receipt, sort_keys=True),
                flush=True,
            )
        return response

    def observer(self, role, interfaces):
        name = self.prefix + "-capture-" + role
        self.docker(
            "create",
            "--name",
            name,
            "--network",
            "container:" + self.roles[role],
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_RAW",
            "--security-opt",
            "no-new-privileges:true",
            "--tmpfs",
            "/run:rw,mode=0700",
            self.image,
            "python",
            "-u",
            "/qualification/capture.py",
            *interfaces,
        )
        self.resources.append(name)
        self.observers[role] = name
        self.observer_interfaces[role] = interfaces
        self.docker("start", name)
        self.wait(lambda: self.capture_ready(role), "capture ready " + role)

    def capture_ready(self, role):
        try:
            return self.request(role, 8991).get("ready") is True
        except (RuntimeError, ValueError):
            return False

    def observed(self, role):
        expected = {
            item["ifname"]: item["ifindex"]
            for item in json.loads(
                self.execute(self.roles[role], "ip", "-j", "link", "show").stdout
            )
            if item["ifname"] in self.observer_interfaces[role]
        }

        def current():
            data = self.request(role, 8991)
            return (
                data.get("ready") is True
                and data.get("active_interfaces") == expected
                and data.get("polls", 0) > self.previous_polls.get(role, -1)
            )

        self.wait(current, "fresh complete observer inventory " + role, timeout=5)
        data = self.request(role, 8991)
        assert data["ready"] and data["drops"] == 0 and not data.get("capture_errors")
        assert data["active_interfaces"] == expected
        assert data["polls"] > self.previous_polls.get(role, -1)
        self.previous_polls[role] = data["polls"]
        return data

    def phase(self, phase):
        self.python(
            self.roles["client"],
            'import sys;from pathlib import Path;Path("/run/d3-phase").write_text(sys.stdin.read())',
            data=phase,
        )
        # Only a source actually introduced by a provider generation is protected.
        if not self.source_known:
            return
        if self.pia_source_known:
            self.python(
                self.roles["appliance"],
                f"""import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_IP,15,1);s.bind(("10.65.0.2",0))
try:s.sendto(b"exitlane-d3-protected-{phase}-source:output-pia",("1.1.1.1",7777))
except OSError:pass""",
            )
        # Also exercise local provider-source OUTPUT after interface deletion.
        self.python(
            self.roles["appliance"],
            f"""import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_IP,15,1);s.bind(("10.64.0.2",0))
try:s.sendto(b"exitlane-d3-protected-{phase}-source:output",("1.1.1.1",7777))
except OSError:pass""",
        )

    def dns_response(self, address, protocol, phase, *, role="client", bind=None):
        source = f'''import socket,struct
labels=b"".join(bytes([len(x)])+x.encode() for x in {("synthetic-control.invalid" if phase.endswith("control") else "eld3-response-" + phase + ".invalid")!r}.split("."))+b"\\0"
q=struct.pack("!HHHHHH",31415,0x100,1,0,0,0)+labels+b"\\0\\1\\0\\1"
with socket.socket(socket.AF_INET,{"socket.SOCK_STREAM" if protocol == "tcp" else "socket.SOCK_DGRAM"}) as s:
    s.settimeout(2)
    if {bind is not None!r}:
        s.setsockopt(socket.SOL_IP,15,1);s.bind(({bind!r},0))
    if {protocol == "tcp"!r}:
        s.connect(("{address}",53));s.sendall(struct.pack("!H",len(q))+q)
        h=s.recv(2);assert len(h)==2;n=struct.unpack("!H",h)[0];response=b""
        while len(response)<n:
            piece=s.recv(n-len(response));assert piece;response+=piece
    else:
        s.sendto(q,("{address}",53));response=s.recv(2048)
assert len(response)>=12 and response[:2]==q[:2] and struct.unpack("!H",response[6:8])[0]>0
'''
        return self.python(self.roles[role], source, check=False).returncode == 0

    def snapshot(self, label):
        evidence = {
            "runtime": self.control("snapshot"),
            "target": self.request("target", 8989),
            "capture": self.request("appliance", 8991),
        }
        assert evidence["runtime"]["ok"], "synthetic runtime snapshot unavailable"
        for key, arguments in (
            ("nft", ("nft", "-j", "list", "ruleset")),
            ("rules", ("ip", "-4", "-j", "rule", "show")),
        ):
            evidence[key] = json.loads(
                self.execute(self.roles["appliance"], *arguments).stdout
            )
        path = self.artifacts / (label + ".json")
        path.write_text(json.dumps(evidence, sort_keys=True))
        path.chmod(0o600)

    def control(self, command, provider="mullvad", target="a", **extra):
        return self.request(
            "appliance",
            8990,
            {"command": command, "provider": provider, "target": target, **extra},
        )

    def peer_fault(self, label, protocol=None, *, remove=False):
        peer = self.roles["peer-" + label]
        if remove:
            self.execute(
                peer, "nft", "delete", "table", "inet", "d3_fault", check=False
            )

        else:
            expression = (
                f"{protocol} dport 53 drop" if protocol else 'iifname "wg-peer" drop'
            )
            self.execute(
                peer,
                "nft",
                "-f",
                "/dev/stdin",
                data=(
                    "table inet d3_fault {\nchain input {\ntype filter hook input priority -300; policy accept;\n"
                    + expression
                    + "\n}\n}\n"
                ),
            )

    def switch_with_peer_loss(self, *, source_loss=False):
        app = self.roles["appliance"]
        self.execute(self.roles["peer-b"], "ip", "link", "set", "wg-peer", "up")
        self.python(app, 'from pathlib import Path;Path("/run/d3-before-target").write_text("pia")')
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.control, "switch", "pia", "b")
            self.wait(
                lambda: self.execute(app, "test", "-f", "/run/d3-before-target-paused", check=False).returncode == 0,
                "target connect reached after proven source handoff",
                timeout=25,
            )
            self.execute(self.roles["peer-b"], "ip", "link", "set", "wg-peer", "down")
            if source_loss:
                self.execute(self.roles["peer-a"], "ip", "link", "set", "wg-peer", "down")
            self.phase("switch-failed-rollback-transition" if source_loss else "switch-target-failure-transition")
            self.python(app, 'from pathlib import Path;Path("/run/d3-before-target-release").touch()')
            result = pending.result(timeout=110)
            snapshot = self.control("snapshot")
            validate_rollback_receipt(result, snapshot, source_loss=source_loss)
            self.snapshot("failed-rollback-complete" if source_loss else "rollback-complete")

    def check(self, phase, *, delivery):
        if delivery:
            self.wait(
                lambda: self.request("target", 8989).get(phase + "-udp", 0) >= 10,
                "positive provider delivery " + phase,
                timeout=15,
            )
        else:
            # Continuous probes must be observed before accepting a zero target count.
            self.wait(
                lambda: (
                    self.request("client", 8991)["interfaces"]
                    .get("wg-client", {})
                    .get("markers", {})
                    .get(phase, 0)
                    >= 10
                ),
                "negative phase probe synchronization " + phase,
            )
        status = self.request("appliance", 8990)
        assert status["ok"]
        ingress = self.observed("appliance")
        self.wait(
            lambda: (
                self.request("appliance", 8991)["interfaces"]
                .get("wg-office", {})
                .get("markers", {})
                .get(phase, 0)
                >= 10
            ),
            "decrypted ingress probe evidence " + phase,
        )
        if delivery:
            assert self.request("target", 8989).get(phase + "-tcp", 0) > 0
            interface = status["interface"]
            assert (
                ingress["interfaces"]
                .get(interface, {})
                .get("markers", {})
                .get(phase, 0)
                > 0
            )
            dns = "10.65.0.1" if status["active_provider"] == "pia" else "10.64.0.1"
            for protocol in ("udp", "tcp"):
                assert self.dns_response(dns, protocol, phase), (
                    phase,
                    protocol,
                    "DNS response missing",
                )

        for role, interfaces in {
            "appliance": ["eth0"],
            "relay": ["eth0", "eth1"],
            "peer-a": ["eth0"],
            "peer-b": ["eth0"],
        }.items():
            evidence = self.observed(role)
            assert evidence["drops"] == 0 and not evidence.get("capture_errors"), (
                evidence
            )
            for interface in interfaces:
                # Local source probes may use a candidate WG path, but never
                # the ordinary uplink. Count them separately from client data.
                assert evidence["interfaces"].get(interface, {}).get("markers", {}).get(
                    phase + "-source", 0
                ) == 0, (phase, role, interface, "provider-source fallback")
                assert (
                    evidence["interfaces"]
                    .get(interface, {})
                    .get("markers", {})
                    .get(phase, 0)
                    == 0
                ), (phase, role, interface)
                assert evidence["interfaces"].get(interface, {}).get("dns", 0) == 0, (
                    phase,
                    role,
                    interface,
                    "plaintext DNS",
                )
            self.receipts[role] = evidence
        if not delivery:
            assert self.request("target", 8989).get(phase, 0) == 0, phase
        print("PASS:", phase, "provider-only" if delivery else "blocked", flush=True)

    def run(self):
        self.preflight()
        for network, subnet, gateway, ipv6_subnet, ipv6_gateway in (
            (self.network, "192.0.0.0/28", "192.0.0.1", "fd88::/64", "fd88::ffff"),
            (self.external, "1.1.1.0/29", "1.1.1.6", "fd99::/64", "fd99::ffff"),
        ):
            self.docker(
                "network",
                "create",
                *(
                    ["--internal"]
                    if network == self.external
                    else [
                        "--opt",
                        "com.docker.network.bridge.enable_ip_masquerade=false",
                    ]
                ),
                "--ipv6",
                "--subnet",
                ipv6_subnet,
                "--gateway",
                ipv6_gateway,
                "--subnet",
                subnet,
                "--gateway",
                gateway,
                network,
            )
            self.created_networks.append(network)
        self.create_role("client")
        self.create_role("target", TARGET, external=True, address="1.1.1.1")
        self.wait(
            lambda: (
                self.request("target", 8989).get("_listeners")
                == ["udp4", "udp6", "tcp4"]
            ),
            "complete target listener inventory",
        )
        self.create_role("relay")
        self.docker(
            "network", "connect", "--ip6", "fd99::2", self.external, self.roles["relay"]
        )
        for label, endpoint in (("a", "192.0.0.9"), ("b", "192.0.0.10")):
            self.create_role("peer-" + label, address=endpoint)
            self.docker(
                "network",
                "connect",
                "--ip6",
                "fd99::9" if label == "a" else "fd99::10",
                self.external,
                self.roles["peer-" + label],
            )
        for role in ("relay", "peer-a", "peer-b"):
            self.execute(
                self.roles[role],
                "ip",
                "route",
                "replace",
                "1.1.1.1/32",
                "via",
                self.ip("target", self.external),
                "dev",
                "eth1",
            )
        self.execute(
            self.roles["relay"],
            "nft",
            "-f",
            "/dev/stdin",
            data='table ip synthetic_relay_nat {\n chain postrouting {\n type nat hook postrouting priority srcnat; policy accept;\n oifname "eth1" masquerade\n }\n}\n',
        )
        self.execute(
            self.roles["relay"],
            "nft",
            "-f",
            "/dev/stdin",
            data='table ip6 synthetic_relay_nat6 {\n chain postrouting {\n type nat hook postrouting priority srcnat; policy accept;\n oifname "eth1" masquerade\n }\n}\n',
        )
        # Separate unsafe plaintext control calibrates bridge/uplink observers.
        self.create_role("unsafe")
        self.execute(
            self.roles["unsafe"],
            "ip",
            "route",
            "replace",
            "default",
            "via",
            self.ip("relay"),
            "dev",
            "eth0",
        )
        self.observer("relay", ["eth0", "eth1"])

        def calibration_delivered():
            self.python(
                self.roles["unsafe"],
                'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b"exitlane-d3-protected-calibration:1",("1.1.1.1",7777))',
            )
            return self.request("target", 8989).get("calibration", 0) > 0

        self.wait(calibration_delivered, "unsafe target calibration")
        self.wait(
            lambda: (
                self.request("relay", 8991)["interfaces"]["eth1"]["markers"].get(
                    "calibration", 0
                )
                > 0
            ),
            "uplink observer calibration",
        )
        private, public = self.keypair(self.roles["client"])
        ingress_private, ingress_public = self.keypair(self.roles["client"])
        provider_private, provider_public = self.keypair(self.roles["client"])
        self.provider_public = provider_public
        peers = {}
        for label, endpoint in (("a", "192.0.0.9"), ("b", "192.0.0.10")):
            peer = self.roles["peer-" + label]
            secret, peer_public = self.keypair(peer)
            peers[label] = {
                "endpoint": endpoint,
                "public_key": peer_public,
                "port": 51820,
            }
            self.execute(peer, "ip", "link", "add", "wg-peer", "type", "wireguard")
            self.execute(
                peer,
                "wg",
                "setconf",
                "wg-peer",
                "/dev/stdin",
                data=f"[Interface]\nPrivateKey = {secret}\nListenPort = 51820\n[Peer]\nPublicKey = {provider_public}\nAllowedIPs = 10.64.0.2/32,10.65.0.2/32\n",
            )
            self.execute(peer, "ip", "address", "add", "10.64.0.1/24", "dev", "wg-peer")
            self.execute(peer, "ip", "address", "add", "10.65.0.1/24", "dev", "wg-peer")
            self.execute(peer, "ip", "link", "set", "wg-peer", "up")
            self.execute(
                peer,
                "nft",
                "-f",
                "/dev/stdin",
                data='table ip synthetic_provider_nat {\n chain postrouting {\n type nat hook postrouting priority srcnat; policy accept;\n oifname "eth1" masquerade\n }\n}\n',
            )
            self.docker("exec", "--detach", peer, "python", "-u", "-c", DNS)
            self.observer("peer-" + label, ["eth0", "eth1", "wg-peer"])
        self.create_role(
            "appliance",
            'import runpy;runpy.run_path("/qualification/fixture.py",run_name="__main__")',
        )
        app = self.roles["appliance"]
        self.execute(
            app,
            "ip",
            "route",
            "replace",
            "default",
            "via",
            self.ip("relay"),
            "dev",
            "eth0",
        )
        boot = {
            "ingress": {
                "interface": "wg-office",
                "address": "10.77.0.1/24",
                "private_key": ingress_private,
                "public_key": public,
                "allowed_ips": "10.77.0.2/32",
                "listen_port": 51820,
            },
            "provider_private_key": provider_private,
            "provider_public_key": provider_public,
            "peers": peers,
        }
        self.wait(
            lambda: (
                self.execute(app, "test", "-p", "/run/d3-boot", check=False).returncode
                == 0
            ),
            "private boot FIFO",
        )
        self.python(
            app,
            'import sys;f=open("/run/d3-boot","w");f.write(sys.stdin.read());f.close()',
            data=json.dumps(boot),
        )
        self.wait(lambda: self.capture_http_ready(), "synthetic fixture ready")
        self.observer(
            "appliance", ["eth0", "wg-office", "wg-mullvad", "wg-pia", "wg-proton"]
        )
        client = self.roles["client"]
        self.execute(client, "ip", "link", "add", "wg-client", "type", "wireguard")
        self.execute(
            client,
            "wg",
            "setconf",
            "wg-client",
            "/dev/stdin",
            data=f"[Interface]\nPrivateKey = {private}\n[Peer]\nPublicKey = {ingress_public}\nEndpoint = {self.ip('appliance')}:51820\nAllowedIPs = 10.77.0.1/32,10.64.0.1/32,10.65.0.1/32,1.1.1.1/32\nPersistentKeepalive = 1\n",
        )
        self.execute(client, "ip", "address", "add", "10.77.0.2/32", "dev", "wg-client")
        self.execute(client, "ip", "link", "set", "wg-client", "up")
        for address in ("10.77.0.1", "10.64.0.1", "10.65.0.1", "1.1.1.1"):
            self.execute(
                client, "ip", "route", "replace", address + "/32", "dev", "wg-client"
            )
        self.observer("client", ["wg-client"])
        self.phase("no-provider")
        self.docker("exec", "--detach", client, "python", "-u", "-c", SENDER)
        self.check("no-provider", delivery=False)
        self.execute(
            self.roles["unsafe"],
            "ip",
            "route",
            "replace",
            "10.77.0.1/32",
            "via",
            self.ip("appliance"),
            "dev",
            "eth0",
        )
        for protocol in ("udp", "tcp"):
            assert self.dns_response(
                "10.77.0.1",
                protocol,
                "proxy-control",
                role="unsafe",
                bind=self.ip("unsafe"),
            )
            assert not self.dns_response("10.77.0.1", protocol, "proxy-ingress-blocked")
            assert self.dns_response(
                "127.0.0.11", protocol, "embedded-control", role="appliance"
            )
        # Synthetic IPv6 fallback exists, and ingress accepts these test packets;
        # production remains IPv4-only. The mandatory inet guard must block them.
        self.execute(
            client, "ip", "-6", "address", "add", "fd77::2/128", "dev", "wg-client"
        )
        for role in ("unsafe", "appliance"):
            self.execute(
                self.roles[role],
                "ip",
                "-6",
                "route",
                "replace",
                "fd99::1/128",
                "via",
                "fd88::1",
                "dev",
                "eth0",
            )
        self.execute(
            app,
            "wg",
            "set",
            "wg-office",
            "peer",
            public,
            "allowed-ips",
            "10.77.0.2/32,fd77::2/128",
        )
        self.execute(
            client,
            "wg",
            "set",
            "wg-client",
            "peer",
            ingress_public,
            "allowed-ips",
            "10.77.0.1/32,10.64.0.1/32,10.65.0.1/32,1.1.1.1/32,fd99::1/128",
        )
        self.execute(
            client, "ip", "-6", "route", "replace", "fd99::1/128", "dev", "wg-client"
        )

        def ipv6_sender(role, phase):
            return self.python(
                self.roles[role],
                f'import socket,time;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);[(s.sendto(b"exitlane-d3-protected-{phase}:6",("fd99::1",7777)),time.sleep(.03)) for _ in range(15)]',
            )

        ipv6_sender("unsafe", "ipv6-calibration")
        self.wait(
            lambda: self.request("target", 8989).get("ipv6-calibration", 0) > 0,
            "IPv6 fallback calibration",
        )
        ipv6_sender("client", "ipv6-blocked")
        self.wait(
            lambda: (
                self.request("appliance", 8991)["interfaces"]
                .get("wg-office", {})
                .get("markers", {})
                .get("ipv6-blocked", 0)
                >= 10
            ),
            "decrypted IPv6 ingress",
        )
        assert self.request("target", 8989).get("ipv6-blocked", 0) == 0
        assert (
            self.observed("appliance")["interfaces"]["eth0"]["markers"].get(
                "ipv6-blocked", 0
            )
            == 0
        )
        for provider in ("mullvad", "pia", "proton"):
            phase = "connect-" + provider
            self.phase(phase)
            if provider != "mullvad":
                assert self.request(
                    "appliance",
                    8990,
                    {"command": "switch", "provider": provider, "target": "a"},
                )["ok"]
            result = self.request(
                "appliance",
                8990,
                {
                    "command": "connect",
                    "provider": provider,
                    "target": "a",
                    "timeout": 5,
                },
            )
            assert result["ok"], result
            self.source_known = True
            self.pia_source_known |= provider == "pia"
            self.check(phase, delivery=True)
            source = "10.65.0.2" if provider == "pia" else "10.64.0.2"
            for protocol in ("udp", "tcp"):
                assert not self.dns_response(
                    "127.0.0.11",
                    protocol,
                    "embedded-source-blocked",
                    role="appliance",
                    bind=source,
                )
            phase = "disconnect-" + provider
            self.phase(phase + "-transition")
            result = self.request(
                "appliance",
                8990,
                {"command": "disconnect", "provider": provider, "timeout": 5},
            )
            assert result["ok"], result
            self.phase(phase)
            self.check(phase, delivery=False)
        self.phase("connect-source")
        assert self.request(
            "appliance",
            8990,
            {"command": "switch", "provider": "mullvad", "target": "a"},
        )["ok"]
        assert self.request(
            "appliance",
            8990,
            {"command": "connect", "provider": "mullvad", "target": "a"},
        )["ok"]
        self.check("connect-source", delivery=True)
        self.execute(
            self.roles["peer-b"],
            "wg",
            "set",
            "wg-peer",
            "peer",
            self.provider_public,
            "allowed-ips",
            "10.65.0.2/32",
        )
        self.phase("switch-success")
        assert self.request(
            "appliance", 8990, {"command": "switch", "provider": "pia", "target": "b"}
        )["ok"]
        self.check("switch-success", delivery=True)
        assert self.control("stale-commit", "pia")["ok"]
        self.phase("stale-generation")
        self.check("stale-generation", delivery=True)
        # Exact peer-source identity makes stale source NAT across the switch observable.
        self.execute(
            self.roles["peer-b"],
            "wg",
            "set",
            "wg-peer",
            "peer",
            self.provider_public,
            "allowed-ips",
            "10.64.0.2/32,10.65.0.2/32",
        )
        self.control("disconnect", "pia")
        assert self.control("switch", "mullvad")["ok"]
        peer_a = self.roles["peer-a"]
        self.execute(peer_a, "ip", "link", "set", "wg-peer", "down")
        self.phase("absent-handshake-attempt")
        assert not self.control("connect", timeout=3)["ok"]
        self.phase("absent-handshake")
        self.check("absent-handshake", delivery=False)
        self.execute(peer_a, "ip", "link", "set", "wg-peer", "up")
        # Keep WG handshake/DNS alive while independently removing provider forwarding.
        self.execute(peer_a, "ip", "route", "replace", "unreachable", "1.1.1.1/32")
        self.phase("unusable-dataplane-attempt")
        assert not self.control("connect", timeout=3)["ok"]
        self.phase("unusable-dataplane")
        self.check("unusable-dataplane", delivery=False)
        self.execute(
            peer_a,
            "ip",
            "route",
            "replace",
            "1.1.1.1/32",
            "via",
            self.ip("target", self.external),
            "dev",
            "eth1",
        )
        for protocol in ("udp", "tcp"):
            self.peer_fault("a", protocol)
            self.phase("dns-" + protocol + "-attempt")
            assert not self.control("connect", timeout=3)["ok"]
            self.phase("dns-" + protocol + "-failure")
            self.check("dns-" + protocol + "-failure", delivery=False)
            self.peer_fault("a", remove=True)
        self.execute(peer_a, "ip", "link", "set", "wg-peer", "down")
        self.phase("late-handshake-waiting")
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.control, "connect", timeout=15)
            self.wait(
                lambda: (
                    (peer := self.execute(
                        app, "wg", "show", "wg-mullvad", "latest-handshakes", check=False
                    )).returncode == 0
                    and len(peer.stdout.split()) == 2
                    and peer.stdout.split()[1] == "0"
                ),
                "late-handshake candidate created",
            )
            handshake = self.execute(
                app, "wg", "show", "wg-mullvad", "latest-handshakes"
            ).stdout.split()
            assert len(handshake) == 2 and handshake[1] == "0"
            self.check("late-handshake-waiting", delivery=False)
            self.phase("late-handshake-recovery")
            self.execute(peer_a, "ip", "link", "set", "wg-peer", "up")
            result = pending.result(timeout=30)
            assert result["ok"], result
        self.phase("late-handshake")
        self.check("late-handshake", delivery=True)
        # Exercise the *outer* actual app switching transaction after inner commit.
        self.python(
            app,
            'from pathlib import Path;Path("/run/d3-pause-target").write_text("pia")',
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.control, "switch", "pia", "b")
            self.wait(
                lambda: (
                    self.execute(
                        app, "test", "-f", "/run/d3-target-paused", check=False
                    ).returncode
                    == 0
                ),
                "target committed before outer switch completion",
                timeout=25,
            )
            self.snapshot("outer-pause-before-status")
            self.phase("outer-switch-paused")
            try:
                self.check("outer-switch-paused", delivery=False)
            finally:
                self.snapshot("outer-pause-after-status")
            assert self.execute(app, "test", "-f", "/run/d3-target-paused").returncode == 0
            assert not pending.done(), "outer switch ended before its blocked-traffic assertion"
            self.phase("outer-switch-recovery")
            self.python(
                app, 'from pathlib import Path;Path("/run/d3-release-target").touch()'
            )
            assert pending.result(timeout=30)["ok"]
        self.phase("outer-switch-complete")
        self.check("outer-switch-complete", delivery=True)
        self.control("disconnect", "pia")
        assert self.control("switch", "mullvad")["ok"]
        assert self.control("connect")["ok"]
        self.switch_with_peer_loss()
        self.phase("switch-rollback-success")
        self.check("switch-rollback-success", delivery=True)
        self.switch_with_peer_loss(source_loss=True)
        self.phase("switch-failed-rollback")
        self.check("switch-failed-rollback", delivery=False)
        for label in ("a", "b"):
            self.execute(
                self.roles["peer-" + label], "ip", "link", "set", "wg-peer", "up"
            )
        # Configured optional killswitch remains a working independent guard.
        self.python(
            app,
            "from exitlane import core;from exitlane.services import killswitch;core.set_setting(killswitch.SETTING_CONFIGURED,True)",
        )
        for provider in ("mullvad", "pia", "proton"):
            phase = "configured-killswitch-" + provider
            self.phase(phase + "-transition")
            if self.request("appliance", 8990)["active_provider"] != provider:
                result = self.control("switch", provider, "a")
                assert result["ok"], result
            result = self.control("connect", provider, "a")
            assert result["ok"], result
            self.phase(phase)
            self.check(phase, delivery=True)
            if provider != "proton":
                self.phase(phase + "-disconnect-transition")
                result = self.control("disconnect", provider)
                assert result["ok"], result
                self.phase(phase + "-disconnected")
                self.check(phase + "-disconnected", delivery=False)
        self.phase("interface-deletion-transition")
        interface = self.request("appliance", 8990)["interface"]
        self.execute(app, "ip", "link", "delete", interface)
        self.phase("interface-deletion")
        self.check("interface-deletion", delivery=False)
        # Drain observers after the last synchronized packet before final receipts.
        time.sleep(0.3)
        for role in self.observers:
            receipt = self.observed(role)
            assert receipt["drops"] == 0 and not receipt.get("capture_errors")
            self.receipts[role] = receipt
            self.retain_capture(role)
        for role, interfaces in {
            "appliance": ["eth0"],
            "relay": ["eth0", "eth1"],
        }.items():
            for interface in interfaces:
                assert all(
                    count == 0
                    for phase, count in self.receipts[role]["interfaces"]
                    .get(interface, {})
                    .get("markers", {})
                    .items()
                    if phase not in {"calibration", "ipv6-calibration"}
                )
        self.receipts["target"] = self.request("target", 8989)
        receipt_file = self.artifacts / "receipt.json"
        receipt_file.write_text(json.dumps(self.receipts, sort_keys=True))
        receipt_file.chmod(0o600)
        print("Packet receipts:", self.artifacts, flush=True)
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "source_scope": "D3 synthetic only",
                    "captures": self.receipts,
                },
                sort_keys=True,
            )
        )

    def capture_http_ready(self):
        try:
            return self.request("appliance", 8990).get("ok") is True
        except (RuntimeError, ValueError):
            return False

    def retain_capture(self, role):
        path = self.artifacts / (role + ".pcap")
        result = self.docker(
            "cp", self.observers[role] + ":/run/d3-capture.pcap", str(path), check=False
        )
        if result.returncode:
            result = self.python(
                self.observers[role],
                "import base64;from pathlib import Path;p=Path('/run/d3-capture.pcap');assert p.stat().st_size<=16777216;print(base64.b64encode(p.read_bytes()).decode())",
            )
            path.write_bytes(base64.b64decode(result.stdout.strip(), validate=True))
        path.chmod(0o600)

    def cleanup(self):
        # Preserve bounded packet evidence even when qualification fails early.
        for role in self.observers:
            try:
                self.retain_capture(role)
            except (RuntimeError, ValueError):
                print("Capture unavailable:", role, flush=True)
            try:
                receipt = self.request(role, 8991)
                path = self.artifacts / (role + "-partial.json")
                path.write_text(json.dumps(receipt, sort_keys=True))
                path.chmod(0o600)
            except (RuntimeError, ValueError):
                pass
        if "appliance" in self.roles:
            result = self.execute(
                self.roles["appliance"], "cat", "/run/fixture-status.json", check=False
            )
            if result.returncode == 0:
                receipt = json.loads(result.stdout)
                path = self.artifacts / "fixture-status.json"
                path.write_text(json.dumps(receipt, sort_keys=True))
                path.chmod(0o600)
                print(
                    "Fixture startup receipt:",
                    json.dumps(receipt, sort_keys=True),
                    flush=True,
                )
            result = self.execute(
                self.roles["appliance"],
                "cat",
                "/run/management-status.json",
                check=False,
            )
            if result.returncode == 0:
                receipt = json.loads(result.stdout)
                path = self.artifacts / "management-status.json"
                path.write_text(json.dumps(receipt, sort_keys=True))
                path.chmod(0o600)
                print(
                    "Management routing receipt:",
                    json.dumps(receipt, sort_keys=True),
                    flush=True,
                )
            for label, arguments in (
                ("nft", ("nft", "-j", "list", "ruleset")),
                ("rules", ("ip", "-4", "-j", "rule", "show")),
                ("routes6", ("ip", "-6", "-j", "route", "show", "table", "all")),
                ("rules6", ("ip", "-6", "-j", "rule", "show")),
                ("routes", ("ip", "-4", "-j", "route", "show", "table", "all")),
            ):
                result = self.execute(self.roles["appliance"], *arguments, check=False)
                if result.returncode == 0:
                    path = self.artifacts / ("appliance-" + label + ".json")
                    path.write_text(result.stdout)
                    path.chmod(0o600)
        if "target" in self.roles:
            try:
                path = self.artifacts / "target-partial.json"
                path.write_text(
                    json.dumps(self.request("target", 8989), sort_keys=True)
                )
                path.chmod(0o600)
            except (RuntimeError, ValueError):
                print("Target receipt unavailable", flush=True)
        print("Packet artifacts retained:", self.artifacts, flush=True)
        for name in reversed(self.resources):
            self.docker("rm", "--force", name, check=False)
        for network in reversed(self.created_networks):
            self.docker("network", "rm", network, check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="exitlane-dataplane:test")
    harness = DataplaneHarness(parser.parse_args().image)
    try:
        harness.run()
    finally:
        harness.cleanup()
