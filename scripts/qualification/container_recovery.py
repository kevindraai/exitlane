#!/usr/bin/env python3
"""Owned-volume D4 proof; no Docker host restart, publication or host-filesystem mount.

Reuses lifecycle Docker helpers and D3 packet capture/calibration primitives.
Each restarted appliance gets a fresh private namespace and the same owned volume.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from container_dataplane import TARGET, DataplaneHarness
from container_lifecycle import validate_capabilities

CHECKPOINTS = (
    "prepared",
    "snapshot_ready",
    "publishing",
    "published_database",
    "published_master_key",
    "published_manifest",
    "published_wireguard",
    "published_provider_egress",
    "installed",
    "validated",
    "committed",
    "rollback_required",
)
FIXTURE = Path(__file__).with_name("container_recovery_fixture.py")


def validate_receipt(before, after, *, marker=None, revoked=False):
    assert after["schema"] == 1 and not after["journal_present"]
    assert {item[0] for item in after["provider_digests"]} == {
        "mullvad",
        "pia",
        "proton",
    }
    assert len(after["intents"]) == 3
    if marker is not None:
        assert after["marker"] == marker
    if before is not None:
        for name in (
            "marker",
            "key_digest",
            "provider_digests",
            "intents",
            "server_public",
        ):
            assert before[name] == after[name], "durable recovery identity mismatch"
    if revoked:
        assert after["sessions"] == 0


class RecoveryHarness(DataplaneHarness):
    def __init__(self, image):
        super().__init__(image)
        self.prefix = "exitlane-d4-" + uuid.uuid4().hex[:12]
        self.network = self.prefix + "-network"
        self.volume = self.prefix + "-state"
        self.volume_created = False
        self.fixture_source = FIXTURE.read_text()
        self.boot = None
        self.client_private = None
        self.server_public = None
        self.phase_name = "startup"
        self.capture_epoch = 0

    def create_role(self, role, *, volume=False):
        name = self.prefix + "-" + role
        args = [
            "create",
            "--name",
            name,
            "--network",
            self.network,
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
            "--tmpfs",
            "/run:rw,mode=0700",
        ]
        args += (
            ["--mount", f"type=volume,source={self.volume},target=/data"]
            if volume
            else ["--tmpfs", "/data:rw,mode=0700"]
        )
        args += [self.image, "python", "-c", "import time;time.sleep(1800)"]
        self.docker(*args)
        self.resources.append(name)
        self.roles[role] = name
        self.docker("start", name)
        facts = json.loads(self.docker("inspect", name).stdout)[0]
        validate_capabilities(facts["HostConfig"]["CapAdd"])
        assert (
            facts["HostConfig"]["CapDrop"] == ["ALL"]
            and not facts["HostConfig"]["Privileged"]
        )
        assert facts["HostConfig"]["NetworkMode"] == self.network
        effective = self.python(
            name,
            "from pathlib import Path;print(next(x.split()[1] for x in Path('/proc/self/status').read_text().splitlines() if x.startswith('CapEff:')))",
        ).stdout.strip()
        assert int(effective, 16) == 1 << 12
        self.execute(name, "ip", "route", "delete", "default", check=False)
        assert not any(
            r.get("dst") == "default"
            for r in json.loads(self.execute(name, "ip", "-j", "route").stdout)
        )
        if volume:
            assert [
                m["Type"] for m in facts["Mounts"] if m["Destination"] == "/data"
            ] == ["volume"]
        return name

    def install_fixture(self, app):
        self.python(
            app,
            "import sys,os;from pathlib import Path;p=Path('/run/recovery_fixture.py');p.write_text(sys.stdin.read());p.chmod(0o600)",
            data=self.fixture_source,
        )

    def fixture(self, mode, payload=None, *, check=True, timeout=60):
        result = self.docker(
            "exec",
            "-i",
            self.roles["appliance"],
            "python",
            "/run/recovery_fixture.py",
            mode,
            data=json.dumps(payload or {}),
            check=check,
            timeout=timeout,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise RuntimeError("synthetic recovery response missing") from None

    def ready(self):
        app = self.roles["appliance"]
        failure = self.execute(app, "cat", "/run/d4-failure.json", check=False)
        if failure.returncode == 0:
            raise RuntimeError(
                "synthetic fixture startup failure: "
                + json.loads(failure.stdout)["error"]
            )
        return (
            self.execute(app, "test", "-f", "/run/d4-ready", check=False).returncode
            == 0
        )

    def start_appliance(self, *, checkpoint=None):
        app = self.create_role("appliance", volume=True)
        self.install_fixture(app)
        if checkpoint:
            self.python(
                app,
                "import sys;from pathlib import Path;Path('/run/d4-kill-phase').write_text(sys.stdin.read())",
                data=checkpoint,
            )
        self.docker(
            "exec", "--detach", app, "python", "-u", "/run/recovery_fixture.py", "serve"
        )
        self.wait(
            lambda: (
                self.execute(app, "test", "-p", "/run/d4-boot", check=False).returncode
                == 0
            ),
            "root boot FIFO",
        )
        self.python(
            app,
            "import sys;f=open('/run/d4-boot','w');f.write(sys.stdin.read());f.close()",
            data=json.dumps(self.boot),
        )
        if checkpoint:
            self.wait(
                lambda: (
                    self.execute(
                        app, "test", "-f", "/run/d4-checkpoint", check=False
                    ).returncode
                    == 0
                ),
                "initialization checkpoint",
            )
            return
        self.wait(self.ready, "guarded recovery startup", timeout=30)
        self.observer("appliance", ["eth0", "wg-office"])
        self.client_configuration(self.fixture("inspect"))

    def client_configuration(self, receipt):
        client = self.roles["client"]
        app_ip = self.ip("appliance")
        self.server_public = receipt["server_public"]
        payload = (
            f"[Interface]\nPrivateKey = {self.client_private}\n[Peer]\nPublicKey = {self.server_public}\n"
            f"Endpoint = {app_ip}:51820\nAllowedIPs = 10.77.0.1/32,{self.ip('target')}/32\nPersistentKeepalive = 1\n"
        )
        if self.execute(
            client, "ip", "link", "show", "wg-client", check=False
        ).returncode:
            self.execute(client, "ip", "link", "add", "wg-client", "type", "wireguard")
            self.execute(
                client, "ip", "address", "add", "10.77.0.2/32", "dev", "wg-client"
            )
        self.execute(client, "wg", "setconf", "wg-client", "/dev/stdin", data=payload)
        self.execute(client, "ip", "link", "set", "wg-client", "up")
        for dst in ("10.77.0.1", self.ip("target")):
            self.execute(
                client, "ip", "route", "replace", dst + "/32", "dev", "wg-client"
            )
        echo = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.3);s.sendto(b'd4-encrypted-ingress-proof',('10.77.0.1',5666));assert s.recv(1024)==b'd4-encrypted-ingress-proof'"
        self.wait(
            lambda: self.python(client, echo, check=False).returncode == 0,
            "encrypted ingress positive control",
        )
        self.wait(
            lambda: self.http(client, app_ip).returncode == 0, "management child health"
        )
        if "worker_ticks" in receipt:
            baseline = receipt["worker_ticks"]
            self.wait(
                lambda: self.fixture("inspect")["worker_ticks"] > baseline,
                "leased SQLite writer resumed",
            )

    def phase(self, name):
        self.phase_name = name
        self.python(
            self.roles["client"],
            "import sys;from pathlib import Path;Path('/run/d4-phase').write_text(sys.stdin.read())",
            data=name,
        )

    def capture_blocked(self, name):
        time.sleep(0.15)
        observed = self.observed("appliance")
        emitted = self.observed("client")
        assert emitted["interfaces"]["wg-client"]["markers"].get(name, 0) > 0, (
            "client probe missing"
        )
        assert observed["interfaces"]["eth0"]["markers"].get(name, 0) == 0, (
            "plaintext protected fallback"
        )
        target = self.request("target", 8989)
        assert target.get(name, 0) == 0, "protected target fallback"
        path = self.artifacts / (name + ".json")
        path.write_text(
            json.dumps({"capture": observed, "target": target}, sort_keys=True)
        )
        path.chmod(0o600)

    def destroy_appliance(self):
        if "appliance" in self.observers:
            self.retain_capture("appliance")
            self.capture_epoch += 1
            (self.artifacts / "appliance.pcap").rename(
                self.artifacts / f"appliance-{self.capture_epoch}.pcap"
            )
        observer = self.observers.pop("appliance", None)
        if observer:
            self.docker("rm", "--force", observer, check=False)
        self.previous_polls.pop("appliance", None)
        self.docker("rm", "--force", self.roles["appliance"])

    def ticks(self):
        result = self.python(
            self.roles["appliance"],
            "import sqlite3,json;c=sqlite3.connect('file:/data/state/exitlane.db?mode=ro',uri=True);row=c.execute(\"SELECT value FROM settings WHERE key='synthetic.worker_ticks'\").fetchone();print(json.loads(row[0]) if row else 0)",
        )
        return int(result.stdout)

    def checkpoint_restore(self, phase, old):
        self.phase("crash-" + phase)
        app = self.roles["appliance"]
        self.python(
            app,
            "import sys;from pathlib import Path;Path('/run/d4-kill-phase').write_text(sys.stdin.read())",
            data=phase,
        )
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(
                self.fixture,
                "restore",
                {"filename": "new.elb", "fail_health": phase == "rollback_required"},
                check=False,
            )
            self.wait(
                lambda: (
                    self.execute(
                        app, "test", "-f", "/run/d4-checkpoint", check=False
                    ).returncode
                    == 0
                ),
                "durable restore checkpoint",
                timeout=30,
            )
            ticks_before = self.ticks()
            self.capture_blocked("crash-" + phase)
            assert self.ticks() == ticks_before, (
                "writer advanced while coordinator exclusively paused"
            )

            self.destroy_appliance()
            try:
                pending.result(timeout=10)
            except RuntimeError:
                pass  # Owned exec was intentionally killed at the observed checkpoint.
        self.start_appliance()
        receipt = self.fixture("inspect")
        if phase == "committed":
            validate_receipt(None, receipt, marker="new", revoked=True)
        else:
            validate_receipt(old, receipt)
        self.fixture("restore", {"filename": "old.elb"})
        self.client_configuration(self.fixture("inspect"))
        print("PASS durable checkpoint " + phase, flush=True)

    def run(self):
        self.docker("network", "create", "--internal", self.network)
        self.created_networks.append(self.network)
        self.docker("volume", "create", self.volume)
        self.volume_created = True
        client = self.create_role("client")
        target = self.create_role("target")
        self.docker("exec", "--detach", target, "python", "-u", "-c", TARGET)
        private, public = self.keypair(client)
        self.client_private = private
        server_private, _server_public = self.keypair(client)
        self.boot = {
            "ingress": {
                "interface": "wg-office",
                "address": "10.77.0.1/24",
                "private_key": server_private,
                "public_key": public,
                "allowed_ips": "10.77.0.2/32",
                "listen_port": 51820,
            }
        }
        for initial_phase in ("init_preparing", "init_ready"):
            self.start_appliance(checkpoint=initial_phase)
            self.destroy_appliance()
            self.start_appliance()
            validate_receipt(None, self.fixture("inspect"), marker="old")
            self.destroy_appliance()
            self.docker("volume", "rm", self.volume)
            self.docker("volume", "create", self.volume)
            print("PASS initialization checkpoint " + initial_phase, flush=True)
        self.start_appliance()
        self.observer("client", ["wg-client"])
        initial_ticks = self.fixture("inspect")["worker_ticks"]
        self.wait(
            lambda: self.fixture("inspect")["worker_ticks"] > initial_ticks,
            "actual leased SQLite writer",
        )
        old = self.fixture("inspect")
        validate_receipt(None, old, marker="old")
        self.fixture("backup", {"filename": "old.elb"})
        new_private, _ = self.keypair(client)
        newboot = json.loads(json.dumps(self.boot))
        newboot["ingress"]["private_key"] = new_private
        self.fixture("source", newboot)
        sender = f"""import socket,time
from pathlib import Path
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for seq in range(100000):
    try:phase=Path('/run/d4-phase').read_text().strip();s.sendto(('exitlane-d3-protected-'+phase+':'+str(seq)).encode(),('{self.ip("target")}',7777))
    except OSError:pass
    time.sleep(.01)
"""
        self.python(
            self.roles["appliance"],
            f"import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'exitlane-d3-protected-calibration:control',('{self.ip('target')}',7777))",
        )
        self.wait(
            lambda: self.request("target", 8989).get("calibration", 0) > 0,
            "capture positive calibration",
        )
        assert (
            self.observed("appliance")["interfaces"]["eth0"]["markers"].get(
                "calibration", 0
            )
            > 0
        )
        self.phase("steady-state")
        self.docker("exec", "--detach", client, "python", "-u", "-c", sender)
        self.capture_blocked("steady-state")
        assert (
            self.observed("appliance")["interfaces"]["wg-office"]["markers"].get(
                "steady-state", 0
            )
            > 0
        )
        self.python(
            self.roles["appliance"],
            "from pathlib import Path;Path('/run/d4-writer-pause').write_text('pause')",
        )
        self.wait(
            lambda: (
                self.execute(
                    self.roles["appliance"],
                    "test",
                    "-f",
                    "/run/d4-writer-paused",
                    check=False,
                ).returncode
                == 0
            ),
            "owned writer paused in SQLite transaction",
        )
        self.destroy_appliance()
        self.start_appliance()
        validate_receipt(old, self.fixture("inspect"))
        print("PASS volume recreation and all provider identities", flush=True)
        self.phase("invalid-archive")
        self.python(
            self.roles["appliance"],
            "from pathlib import Path;p=Path('/data/backups/invalid.elb');p.write_bytes(b'synthetic-invalid-archive');p.chmod(0o600)",
        )
        result = self.fixture("restore", {"filename": "invalid.elb"})
        assert result["ok"] is False and result["network_mutations"] == 0
        validate_receipt(old, self.fixture("inspect"))
        self.capture_blocked("invalid-archive")
        self.phase("wrong-key-archive")
        result = self.fixture("restore", {"filename": "wrong-key.elb"})
        assert result["ok"] is False and result["network_mutations"] == 0
        validate_receipt(old, self.fixture("inspect"))
        self.capture_blocked("wrong-key-archive")
        self.phase("restore")
        result = self.fixture("restore", {"filename": "new.elb"})
        assert result["ok"] is True
        new = self.fixture("inspect")
        validate_receipt(None, new, marker="new", revoked=True)
        assert new["key_digest"] != old["key_digest"]
        self.client_configuration(new)
        self.capture_blocked("restore")
        assert self.fixture("restore", {"filename": "old.elb"})["ok"] is True
        self.client_configuration(self.fixture("inspect"))
        self.phase("failed-health-rollback")
        result = self.fixture("restore", {"filename": "new.elb", "fail_health": True})
        assert result["ok"] is False and result["error"] == "restore_failed_rolled_back"
        validate_receipt(old, self.fixture("inspect"))
        self.client_configuration(self.fixture("inspect"))
        self.capture_blocked("failed-health-rollback")
        with ThreadPoolExecutor(max_workers=1) as pool:
            holder = pool.submit(self.fixture, "lease-hold")
            self.wait(
                lambda: (
                    self.execute(
                        self.roles["appliance"],
                        "test",
                        "-f",
                        "/run/d4-held",
                        check=False,
                    ).returncode
                    == 0
                ),
                "exclusive lease acquired",
            )
            started = time.monotonic()
            assert self.fixture("backup", {"filename": "old.elb"})["ok"] is True
            assert time.monotonic() - started >= 0.5
            assert holder.result()["ok"] is True
        self.python(
            self.roles["appliance"],
            "import os,signal;from pathlib import Path;pid=int(Path('/run/d4-worker.pid').read_text());os.kill(pid,signal.SIGKILL)",
        )
        assert self.fixture("restore", {"filename": "old.elb"})["ok"] is True
        self.client_configuration(self.fixture("inspect"))
        print(
            "PASS crashed writer parent and owned descendant-group reaping", flush=True
        )
        print(
            "PASS guarded restore rollback session revocation and real IPC serialization",
            flush=True,
        )
        self.phase("failed-rollback")
        result = self.fixture("restore", {"filename": "new.elb", "fail_health": 2})
        assert result["ok"] is False and result["error"] == "recovery_required"
        status = self.fixture("status")
        assert status["available"] is False and status["recovery_required"] is True
        assert status["worker_running"] is False
        assert (
            self.execute(
                self.roles["appliance"], "ip", "link", "show", "wg-office", check=False
            ).returncode
            != 0
        )
        assert self.fixture("inspect", check=False)["ok"] is False
        self.capture_blocked("failed-rollback")
        self.destroy_appliance()
        self.start_appliance()
        validate_receipt(old, self.fixture("inspect"))
        print(
            "PASS failed rollback retained journal guard ingress-down and writer denial",
            flush=True,
        )
        for phase in CHECKPOINTS:
            self.checkpoint_restore(phase, old)
        print(
            "PASS D4 owned-volume qualification (Docker support remains gated)",
            flush=True,
        )

    def cleanup(self):
        if "appliance" in self.roles:
            for filename in (
                "d4-failure.json",
                "d4-stage",
                "d4-owner-loss.json",
                "d4-worker-stderr",
            ):
                command = (
                    ("tail", "-c", "8192")
                    if filename == "d4-worker-stderr"
                    else ("cat",)
                )
                result = self.execute(
                    self.roles["appliance"], *command, "/run/" + filename, check=False
                )
                if result.returncode == 0:
                    path = self.artifacts / filename
                    path.write_text(result.stdout)
                    path.chmod(0o600)
                    print(
                        "Fixture diagnostic " + filename + ": " + result.stdout.strip(),
                        flush=True,
                    )
        if "appliance" in self.roles:
            facts = self.python(
                self.roles["appliance"],
                "import json;from pathlib import Path;root=Path('/data/state');print(json.dumps([{'name':p.name,'size':p.lstat().st_size,'mode':oct(p.lstat().st_mode & 0o777),'uid':p.lstat().st_uid,'links':p.lstat().st_nlink} for p in root.iterdir() if p.name.startswith('exitlane.db')]))",
                check=False,
            )
            if facts.returncode == 0:
                path = self.artifacts / "sqlite-file-facts.json"
                path.write_text(facts.stdout)
                path.chmod(0o600)
                print("SQLite file facts: " + facts.stdout.strip(), flush=True)
        super().cleanup()
        if self.volume_created:
            self.docker("volume", "rm", self.volume, check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="exitlane-dataplane:test")
    args = parser.parse_args()
    harness = RecoveryHarness(args.image)
    try:
        harness.run()
    finally:
        harness.cleanup()


if __name__ == "__main__":
    main()
