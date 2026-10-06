#!/usr/bin/env python3
"""Synthetic D4 fixture. Fixed local control and owned state only; never production."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import signal
import sqlite3
import sys
import traceback
import urllib.request
from dataclasses import asdict
from pathlib import Path

from exitlane import core, lifecycle
from exitlane.container_control import (
    ERROR_CODES,
    ControlError,
    MutationAuthority,
    MutationOwner,
    UnixControlClient,
    UnixControlServer,
)
from exitlane.container_maintenance import MaintenanceGuard
from exitlane.container_recovery import (
    ContainerRecoveryCoordinator,
    IngressIdentity,
    RecoveryHooks,
)
from exitlane.container_runtime import (
    ContainerSupervisor,
    ContainerWireGuardLifecycle,
    IngressConfig,
)
from exitlane.container_state import ContainerLayout, ContainerState
from exitlane.providers.mullvad import Relay
from exitlane.providers.pia_api import PiaKeyResponse, PiaServer
from exitlane.providers.proton_profile import parse_profile
from exitlane.providers.wireguard_keys import _public_key_for_private
from exitlane.services import auth_security, provider_secrets

ROOT = Path("/data")
PASSPHRASE = "synthetic-recovery-only"
WRITER = """
import json,sqlite3,sys,time,os,signal
from pathlib import Path
for line in sys.stdin:
    assert line.strip() == 'tick'
    with sqlite3.connect('/data/state/exitlane.db',timeout=1) as c:
        c.execute('PRAGMA cache_size=1')
        c.execute('BEGIN IMMEDIATE')
        row=c.execute("SELECT value FROM settings WHERE key='synthetic.worker_ticks'").fetchone()
        count=json.loads(row[0]) if row else 0
        c.execute("INSERT INTO settings(key,value) VALUES('synthetic.worker_ticks',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(count+1),))
        if Path('/run/d4-writer-pause').exists():
            c.execute('SELECT COUNT(*) FROM users').fetchone()
            Path('/run/d4-writer-paused').write_text('paused')
            os.kill(os.getpid(),signal.SIGSTOP)
    print('ack',flush=True)
# Deliberately survive parent EOF, without further unauthorized writes.
time.sleep(1800)
"""
WORKER = rf"""
import http.server,sqlite3,socket,threading,time,subprocess,sys
writer=subprocess.Popen([sys.executable,'-u','-c',{WRITER!r}],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
def echo():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        while True:
            try:s.bind(('10.77.0.1',5666));break
            except OSError:time.sleep(.05)
        while True:
            value,peer=s.recvfrom(1024);s.sendto(value,peer)
threading.Thread(target=echo,daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with sqlite3.connect('file:/data/state/exitlane.db?mode=ro',uri=True) as c:
            assert c.execute('PRAGMA integrity_check').fetchone()==('ok',)
        self.send_response(200);self.end_headers();self.wfile.write(b'synthetic-management')
    def log_message(self,*a):pass
threading.Thread(target=lambda:http.server.HTTPServer(('0.0.0.0',8989),Handler).serve_forever(),daemon=True).start()
for line in sys.stdin:
    assert line.strip() == 'tick'
    writer.stdin.write('tick\n');writer.stdin.flush()
    assert writer.stdout.readline().strip() == 'ack'
    print('ack',flush=True)
"""


def stage(name):
    Path("/run/d4-stage").write_text(name)


def seed(state, ingress, marker, client_private_key):
    """Only used under authority on a new volume or isolated source staging."""
    old_db, old_path = core.DB, auth_security.master_key_path
    core.DB = state.layout.database
    auth_security.master_key_path = lambda: state.layout.master_key
    try:
        core.set_settings(
            {
                "synthetic.marker": marker,
                "wireguard_configured": True,
                "wireguard_interface": "wg-office",
                "wireguard_client_name": "router",
                "wireguard_subnet": "10.77.0.0/24",
                "vpn.provider_id": "mullvad",
            }
        )
        private = base64.b64encode(bytes(range(32))).decode()
        public = _public_key_for_private(private)
        peer = base64.b64encode(bytes(range(1, 33))).decode()
        provider_secrets.save(
            "mullvad",
            {
                "version": 1,
                "account_number": "0000000000000000",
                "private_key": private,
                "public_key": public,
                "ipv4_address": "10.64.0.2/32",
                "active": {
                    "generation": marker + "-mullvad",
                    "relay": asdict(
                        Relay(
                            "synthetic",
                            "NL",
                            "Synthetic",
                            "ams",
                            "Synthetic",
                            "192.0.0.9",
                            peer,
                        )
                    ),
                },
            },
        )
        provider_secrets.save(
            "pia",
            {
                "version": 1,
                "username": "p0000000",
                "password": "synthetic-fixture-only",
                "pending": {
                    "generation": marker + "-pia",
                    "private_key": private,
                    "public_key": public,
                    "address": "10.65.0.2/32",
                    "server": asdict(
                        PiaServer(
                            "synthetic",
                            "Synthetic",
                            "NL",
                            "peer",
                            "192.0.0.9",
                            "192.0.0.9",
                        )
                    ),
                    "response": asdict(
                        PiaKeyResponse("10.65.0.2/32", peer, 51820, "10.65.0.1")
                    ),
                },
            },
        )
        profile = parse_profile(
            f"[Interface]\nPrivateKey = {private}\nAddress = 10.66.0.2/32\nDNS = 10.66.0.1\n[Peer]\nPublicKey = {peer}\nEndpoint = 192.0.0.9:51820\nAllowedIPs = 0.0.0.0/0\n"
        )
        provider_secrets.save(
            "proton",
            {
                "version": 1,
                "profiles": {"synthetic": {"config": asdict(profile)}},
                "pending": {
                    "generation": marker + "-proton",
                    "profile_id": "synthetic",
                    "endpoint_address": "192.0.0.9",
                    "address": "10.66.0.2/32",
                },
            },
        )
        text = f"[Interface]\nPrivateKey = {ingress.private_key}\nAddress = {ingress.address}\nListenPort = {ingress.listen_port}\n[Peer]\nPublicKey = {ingress.public_key}\nAllowedIPs = {ingress.allowed_ips}\n"
        path = state.layout.wireguard / "wg-office.conf"
        path.write_text(text)
        path.chmod(0o600)
        client = state.layout.wireguard / "router.conf"
        client.write_text(
            f"[Interface]\nPrivateKey = {client_private_key}\n"
            "Address = 10.77.0.2/32\nDNS = 1.1.1.1\n\n"
            f"[Peer]\nPublicKey = {_public_key_for_private(ingress.private_key)}\n"
            "Endpoint = 192.0.2.5:51820\nAllowedIPs = 0.0.0.0/0\n"
            "PersistentKeepalive = 25\n"
        )
        client.chmod(0o600)
        with sqlite3.connect(core.DB) as c:
            c.execute("INSERT INTO users(id,username) VALUES(1,'synthetic')")
            c.execute(
                "INSERT INTO sessions(token_hash,user_id,expires_at,public_id) VALUES('synthetic-session',1,9999999999,'synthetic')"
            )
        state.validate()
    finally:
        core.DB, auth_security.master_key_path = old_db, old_path


def inspect():
    state = ContainerState(ContainerLayout(ROOT))
    inventory = state.validate()
    with sqlite3.connect(state.layout.database) as c:
        marker = json.loads(
            c.execute(
                "SELECT value FROM settings WHERE key='synthetic.marker'"
            ).fetchone()[0]
        )
        sessions = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        tickrow = c.execute(
            "SELECT value FROM settings WHERE key='synthetic.worker_ticks'"
        ).fetchone()
        ticks = json.loads(tickrow[0]) if tickrow else 0
        secrets = [
            (p, hashlib.sha256(value).hexdigest())
            for p, value in c.execute(
                "SELECT provider_id,encrypted_payload FROM provider_secrets ORDER BY provider_id"
            )
        ]
    ingress = IngressConfig.from_file(state.layout.wireguard / "wg-office.conf")
    return {
        "marker": marker,
        "key_digest": hashlib.sha256(state.layout.master_key.read_bytes()).hexdigest(),
        "provider_digests": secrets,
        "intents": [(i.provider_id, i.status, i.generation) for i in inventory.intents],
        "sessions": sessions,
        "worker_ticks": ticks,
        "server_public": _public_key_for_private(ingress.private_key),
        "schema": inventory.schema,
        "journal_present": (state.layout.recovery / "transaction.json").exists(),
    }


def checkpoint(phase):
    wanted = Path("/run/d4-kill-phase")
    if wanted.exists() and wanted.read_text().strip() == phase:
        Path("/run/d4-checkpoint").write_text(
            json.dumps({"phase": phase, "pid": os.getpid()})
        )
        os.kill(os.getpid(), signal.SIGSTOP)


class Fixture:
    def __init__(self, boot):
        self.boot = boot
        self.state = ContainerState(ContainerLayout(ROOT))
        self.network = ContainerWireGuardLifecycle(IngressConfig(**boot["ingress"]))
        self.maintenance = MaintenanceGuard()
        self.worker = None
        self.supervisor = ContainerSupervisor(
            self.network, self.start_worker, process_group=True, stop_timeout=2
        )
        self.fail_health = 0
        self.calls = 0
        self.authority = MutationAuthority(self.abandon)
        self.coordinator = ContainerRecoveryCoordinator(
            self.state,
            RecoveryHooks(
                self.guard,
                self.quiesce,
                self.reset,
                self.reconcile,
                self.health,
                self.reopen,
            ),
            phase_observer=checkpoint,
            require_exclusive=lambda: self.authority.owner is not None,
        )
        self.server = UnixControlServer(
            self.authority,
            callbacks={
                "backup": self.backup,
                "restore": self.restore,
                "status": self.status,
            },
        )

    async def ticks(self):
        while self.authority.available:
            await asyncio.sleep(0.05)
            try:
                await self.tick_once()
            except (
                BrokenPipeError,
                ConnectionResetError,
                AssertionError,
                ControlError,
            ):
                # Authority already guarded and reaped the lost owner before returning.
                if not self.authority.available:
                    return

    async def tick_once(self):
        worker = self.worker
        if not worker or worker.returncode is not None or self.supervisor.maintenance:
            return
        async with self.authority.exclusive(
            MutationOwner(worker.pid, "synthetic-worker"), timeout=5
        ):
            if (
                self.worker is not worker
                or worker.returncode is not None
                or self.supervisor.maintenance
            ):
                return
            worker.stdin.write(b"tick\n")
            await asyncio.wait_for(worker.stdin.drain(), 1)
            assert await asyncio.wait_for(worker.stdout.readline(), 1) == b"ack\n"

    async def abandon(self, owner, reason):
        Path("/run/d4-owner-loss.json").write_text(
            json.dumps(
                {
                    "reason": reason,
                    "worker_returncode": self.worker.returncode
                    if self.worker
                    else None,
                }
            )
        )
        await self.guard((IngressIdentity("wg-office", "10.77.0.0/24"),))
        await self.quiesce()
        return True

    async def guard(self, identities):
        stage("guard")
        self.calls += 1
        stage("maintenance-arm")
        await self.maintenance.arm(identities)
        stage("permanent-arm")
        await self.network.arm_guard()
        stage("ingress-stop")
        await self.network.deactivate()

    async def start_worker(self):
        diagnostics = Path("/run/d4-worker-stderr")
        diagnostics.touch(mode=0o600, exist_ok=True)
        stderr = await asyncio.to_thread(diagnostics.open, "ab", buffering=0)
        worker = await asyncio.create_subprocess_exec(
            sys.executable,
            "-u",
            "-c",
            WORKER,
            start_new_session=True,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=stderr,
        )
        stderr.close()
        assert os.getpgid(worker.pid) == worker.pid
        Path("/run/d4-worker.pid").write_text(str(worker.pid))
        self.supervisor.worker = worker
        self.supervisor.worker_group = worker.pid
        return worker

    async def quiesce(self):
        stage("quiesce")
        await self.supervisor.quiesce()
        assert not self.worker or self.worker.returncode is not None
        assert self.supervisor.worker_group is None

    async def reset(self):
        stage("reset")
        await self.network.observe_guard()

    async def reconcile(self, inventory):
        stage("reconcile")
        await self.maintenance.observed(self.maintenance.identities)
        self.state.rebuild_projections(
            inventory, guard_observed=lambda: self.maintenance.active
        )
        path = self.state.layout.wireguard / "wg-office.conf"
        if path.exists():
            self.network.config = IngressConfig.from_file(path)
        await self.network.arm_guard()

    async def health(self):
        stage("health")
        self.state.validate()
        await self.network.observe_guard()
        if not self.worker or self.worker.returncode is not None:
            self.worker = await self.start_worker()
        deadline = asyncio.get_running_loop().time() + 5
        while True:
            try:

                def check():
                    with urllib.request.urlopen(
                        "http://127.0.0.1:8989/", timeout=0.2
                    ) as response:
                        return response.status == 200

                if await asyncio.to_thread(check):
                    break
            except OSError:
                pass
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(0.05)
        if self.fail_health:
            self.fail_health -= 1
            return False
        return True

    async def reopen(self):
        stage("reopen")
        if (self.state.layout.wireguard / "wg-office.conf").exists():
            await self.network.activate()
        if not self.worker or self.worker.returncode is not None:
            self.worker = await self.start_worker()
        self.supervisor.resume()
        await self.maintenance.release()

    async def backup(self, payload):
        if set(payload) != {"filename"} or payload["filename"] not in {
            "old.elb",
            "new.elb",
        }:
            raise ValueError
        await self.coordinator.backup(
            self.state.layout.backups / payload["filename"], PASSPHRASE
        )
        return {"ok": True}

    async def restore(self, payload):
        if set(payload) - {"filename", "fail_health"} or payload.get(
            "filename"
        ) not in {"old.elb", "new.elb", "invalid.elb", "wrong-key.elb"}:
            raise ValueError
        health_count = payload.get("fail_health", False)
        self.fail_health = 1 if health_count is True else 2 if health_count == 2 else 0
        before = self.calls
        try:
            await self.coordinator.restore(
                self.state.layout.backups / payload["filename"],
                PASSPHRASE,
                confirmation="RESTORE EXITLANE",
            )
            return {"ok": True}
        except Exception as error:  # noqa: BLE001 - bounded synthetic error codes, no secret repr
            if getattr(error, "code", None) == "recovery_required":
                self.authority.require_recovery()
            return {
                "ok": False,
                "error": getattr(error, "code", "synthetic_restore_failed"),
                "network_mutations": self.calls - before,
            }

    async def status(self, payload):
        return {
            "state": "recovery_required"
            if self.coordinator.journal.exists() or not self.authority.available
            else "ready",
            "available": self.authority.available,
            "recovery_required": self.coordinator.journal.exists(),
            "worker_running": bool(self.worker and self.worker.returncode is None),
            "dataplane_ready": False,
        }

    async def run(self):
        stage("startup")
        ROOT.chmod(0o700)
        async with self.authority.exclusive(MutationOwner(os.getpid(), "startup")):
            await self.coordinator.startup()
            if not core.setting("synthetic.marker"):
                await self.guard((IngressIdentity("wg-office", "10.77.0.0/24"),))
                await self.quiesce()
                stage("seed")
                seed(self.state, self.network.config, "old", self.boot["client_private_key"])
                await self.reconcile(self.state.validate())
                await self.reopen()
        await self.server.start()
        self.tick_task = asyncio.create_task(self.ticks())
        Path("/run/d4-ready").write_text("ready")
        await asyncio.Event().wait()


async def operation(command, payload):
    client = UnixControlClient()
    if command == "inspect":
        async with client.mutation(timeout=5):
            return inspect()
    if command == "lease-hold":
        async with client.mutation(timeout=5):
            Path("/run/d4-held").write_text("held")
            await asyncio.sleep(1)
        return {"ok": True}
    return await client.request(command, payload, timeout=30)


if __name__ == "__main__":
    try:
        mode = sys.argv[1]
        if mode == "serve":
            path = Path("/run/d4-boot")
            os.mkfifo(path, 0o600)
            with path.open() as source:
                boot = json.load(source)
            path.unlink()
            asyncio.run(Fixture(boot).run())
        elif mode == "source":
            boot = json.load(sys.stdin)
            staging = ROOT / "recovery/source"
            state = ContainerState(
                ContainerState(ContainerLayout(ROOT)).stage_empty(staging)
            )
            ingress = IngressConfig(**boot["ingress"])
            seed(state, ingress, "new", boot["client_private_key"])

            async def build():
                async def noop(*args):
                    pass

                async def health():
                    return True

                authority = MutationAuthority(lambda *args: health())
                coordinator = ContainerRecoveryCoordinator(
                    state,
                    RecoveryHooks(noop, noop, noop, noop, health, noop),
                    require_exclusive=lambda: authority.owner is not None,
                )
                async with authority.exclusive(MutationOwner(os.getpid(), "source")):
                    await coordinator.backup(
                        state.layout.backups / "new.elb", PASSPHRASE
                    )

            asyncio.run(build())
            os.rename(staging / "backups/new.elb", ROOT / "backups/new.elb")
            bad = ROOT / "recovery/wrong-archive"
            bad.mkdir(mode=0o700)
            manifest = lifecycle._validated_payload(
                lifecycle._decrypt(ROOT / "backups/new.elb", PASSPHRASE), bad
            )
            entry = next(
                item for item in manifest["files"] if item["type"] == "master_key"
            )
            keyfile = bad / entry["name"]
            keyfile.write_bytes(b"x" * 32)
            keyfile.chmod(0o600)
            entry["sha256"] = hashlib.sha256(b"x" * 32).hexdigest()
            lifecycle.encrypt_staged_backup(
                bad, manifest, ROOT / "backups/wrong-key.elb", PASSPHRASE
            )
            print(json.dumps({"ok": True}))
        else:
            payload = json.load(sys.stdin)
            print(json.dumps(asyncio.run(operation(mode, payload)), sort_keys=True))
    except Exception as error:  # noqa: BLE001 - bounded synthetic error codes, no secret repr
        failure = {
            "ok": False,
            "error": getattr(error, "code", "synthetic_recovery_failed"),
            "error_type": type(error).__name__,
            "frames": [
                [Path(f.filename).name, f.name, f.lineno]
                for f in traceback.extract_tb(error.__traceback__)[-8:]
            ],
        }
        causes = []
        current = error
        for _ in range(4):
            if current is None:
                break
            code = getattr(current, "code", None)
            if isinstance(current, ControlError) and str(current) in ERROR_CODES:
                code = str(current)
            causes.append(
                {
                    "type": type(current).__name__,
                    "code": code,
                    "sqlite_code": getattr(current, "sqlite_errorcode", None),
                    "sqlite_name": getattr(current, "sqlite_errorname", None),
                }
            )
            current = current.__context__
        failure["causes"] = causes
        Path("/run/d4-failure.json").write_text(json.dumps(failure))
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": getattr(error, "code", "synthetic_recovery_failed"),
                }
            ),
            flush=True,
        )
        sys.exit(2)
