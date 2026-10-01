"""Experimental container supervisor. No Docker host control or provider registration.

The parent owns ingress interfaces and the exclusive authority. A live application
worker alone owns direct-provider policy; maintenance protection precedes every
parent intervention. The worker receives one startup grant over an inherited FD.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import signal
import socket
import stat
import sys
import urllib.request
from pathlib import Path


class EntrypointError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _http_health():
    try:
        request = urllib.request.Request("http://127.0.0.1:8787/api/health")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=1) as response:
            value = json.loads(response.read(4097))
            return response.status == 200 and isinstance(value, dict) and value.get("ok") is True
    except (OSError, ValueError):
        return False


def _validate_preflight(facts):
    expected = {
        "uid": 0,
        "capabilities": 1 << 12,
        "no_new_privileges": 1,
        "ipv4_forwarding": "1",
        "ipv6_forwarding": "0",
        "ping_group_range": "0 0",
        "tun": True,
        "tools": True,
        "root_readonly": True,
        "data_mount": True,
        "run_private": True,
        "tmp_private": True,
        "runtime": "container",
    }
    if facts != expected:
        raise EntrypointError("container_preflight_failed")


def preflight():
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    tun = Path("/dev/net/tun").stat()
    mountpoints = [
        line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()
    ]

    def private_directory(path):
        details = Path(path).lstat()
        return (
            stat.S_ISDIR(details.st_mode) and details.st_uid == 0 and details.st_mode & 0o077 == 0
        )

    _validate_preflight(
        {
            "uid": os.geteuid(),
            "capabilities": int(status.get("CapEff", "0"), 16),
            "no_new_privileges": int(status.get("NoNewPrivs", "0")),
            "ipv4_forwarding": Path("/proc/sys/net/ipv4/ip_forward").read_text().strip(),
            "ipv6_forwarding": Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip(),
            "ping_group_range": " ".join(
                Path("/proc/sys/net/ipv4/ping_group_range").read_text().split()
            ),
            "tun": stat.S_ISCHR(tun.st_mode)
            and os.major(tun.st_rdev) == 10
            and os.minor(tun.st_rdev) == 200,
            "tools": all(
                shutil.which(tool) for tool in ("ip", "wg", "wg-quick", "nft", "ping", "bash")
            ),
            "root_readonly": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
            "data_mount": "/data" in mountpoints,
            "run_private": private_directory("/run"),
            "tmp_private": private_directory("/tmp"),
            "runtime": os.environ.get("EXITLANE_RUNTIME"),
        }
    )


class ContainerController:
    """Parent-only ingress ownership; no live provider candidate/proof cache."""

    def __init__(self, state, maintenance, *, runner=None, operation_valid=lambda: True):
        from exitlane import core

        self.state = state
        self.maintenance = maintenance
        self.runner = runner or core.command
        self.network = None
        self.operation_valid = operation_valid

    def identity(self, config):
        from exitlane.container_recovery import IngressIdentity

        return IngressIdentity(
            config.interface, str(ipaddress.IPv4Interface(config.address).network)
        )

    async def checked(self, *argv):
        from exitlane.container_runtime import ContainerLifecycleError

        rc, output, _ = await self.runner(*argv, timeout=5)
        if rc:
            raise ContainerLifecycleError("container_network_command_failed")
        return output

    async def observe_policy(self, *, config=None):
        """Stateless exact recognition; observing never grants a forwarding verdict."""
        from exitlane.container_runtime import TABLE, ContainerWireGuardLifecycle
        from exitlane.services.provider_wireguard import RULE_PRIORITY, TABLE_ID

        config = config or (self.network.config if self.network else None)
        if config is None:
            await self.maintenance.observed(self.maintenance.identities)
            return
        observer = ContainerWireGuardLifecycle(config, runner=self.runner)
        data = json.loads(await self.checked("nft", "-j", "list", "table", "inet", TABLE))
        observer.validate_previous_policy(data)
        for family in (4, 6):
            routes = json.loads(
                await self.checked(
                    "ip", f"-{family}", "-j", "route", "show", "table", str(TABLE_ID)
                )
            )
            rules = json.loads(await self.checked("ip", f"-{family}", "-j", "rule", "show"))
            if not any(
                item.get("type") == "unreachable" and item.get("dst") == "default"
                for item in routes
            ):
                raise EntrypointError("container_guard_unproven")
            if not any(
                item.get("iif") == config.interface
                and item.get("priority") == RULE_PRIORITY
                and str(item.get("table")) == str(TABLE_ID)
                for item in rules
            ):
                raise EntrypointError("container_guard_unproven")

    async def arm_maintenance(self, identities):
        if self.network:
            identities = tuple(dict.fromkeys((*identities, self.identity(self.network.config))))
        await self.maintenance.arm(identities)

    async def deactivate(self):
        if self.network:
            await self.network.deactivate()

    async def reset_policy(self):
        # Every application process has been reaped before this method.
        if self.network:
            await self.network.arm_guard()
        else:
            await self.maintenance.observed(self.maintenance.identities)

    async def reconcile(self, inventory):
        from exitlane.container_recovery import ingress_identities
        from exitlane.container_runtime import ContainerWireGuardLifecycle, IngressConfig

        await self.maintenance.observed(self.maintenance.identities)
        self.state.rebuild_projections(inventory, guard_observed=lambda: self.maintenance.active)
        identities = ingress_identities(self.state.layout.database)
        if not identities:
            self.network = None
            return
        if len(identities) != 1:
            raise EntrypointError("container_ingress_config_invalid")
        config = IngressConfig.from_file(
            self.state.layout.wireguard / f"{identities[0].interface}.conf"
        )
        if self.network and self.identity(self.network.config) != self.identity(config):
            # The old guard was recognized and revoked before resetting writers.
            # A different ingress requires replacing only our own proven table,
            # under the independent old/new maintenance union.
            from exitlane.container_runtime import TABLE

            await self.observe_policy()
            await self.checked("nft", "delete", "table", "inet", TABLE)
        history = self.network.source_addresses if self.network else ()
        self.network = ContainerWireGuardLifecycle(config, runner=self.runner)
        self.network.source_addresses = history
        await self.network.activate()  # Before child policy/proof exists.
        await self.observe_policy()

    async def ingress(self, payload):
        from exitlane.container_runtime import INTERFACE, ContainerWireGuardLifecycle, IngressConfig

        if not self.operation_valid():
            raise EntrypointError("container_ingress_lease_revoked")
        if (
            set(payload) != {"action", "interface"}
            or payload["action"] not in {"activate", "observe"}
            or not isinstance(payload["interface"], str)
            or INTERFACE.fullmatch(payload["interface"]) is None
        ):
            raise EntrypointError("container_ingress_config_invalid")
        config = IngressConfig.from_file(
            self.state.layout.wireguard / f"{payload['interface']}.conf"
        )
        if self.network and self.network.config.interface != config.interface:
            raise EntrypointError("container_ingress_config_invalid")
        if payload["action"] == "activate":
            previous = self.network
            await self.arm_maintenance((self.identity(config),))
            await self.deactivate()
            if not self.operation_valid():
                raise EntrypointError("container_ingress_lease_revoked")
            self.network = ContainerWireGuardLifecycle(config, runner=self.runner)
            if previous is None:
                await self.network.activate()  # First ingress initializes blocked policy.
            else:
                # Existing exact guard covers iif across a possible subnet change.
                await self.network.activate_already_guarded(
                    lambda: self.observe_policy(config=previous.config)
                )
            if not self.operation_valid():
                raise EntrypointError("container_ingress_lease_revoked")
            return {"active": True}
        await self.observe_policy(config=config)
        if not self.network or await self.network.observe_owned_ingress() is not True:
            raise EntrypointError("container_interface_ownership_unproven")
        if not self.operation_valid():
            raise EntrypointError("container_ingress_lease_revoked")
        if self.maintenance.active:
            await self.maintenance.release()
        return {"active": True}


class ContainerEntrypoint:
    def __init__(self):
        from exitlane.container_control import MutationAuthority, UnixControlServer
        from exitlane.container_maintenance import MaintenanceGuard
        from exitlane.container_recovery import ContainerRecoveryCoordinator, RecoveryHooks
        from exitlane.container_runtime import ContainerSupervisor
        from exitlane.container_service import ContainerRecoveryService
        from exitlane.container_state import ContainerLayout, ContainerState

        self.state = ContainerState(ContainerLayout(Path("/data")))
        self.maintenance = MaintenanceGuard()
        self.controller = ContainerController(
            self.state, self.maintenance,
            operation_valid=lambda: self.authority.owner is not None
            and self.authority.owner.label == "acquire" and not self.authority.revoking,
        )
        # ContainerSupervisor is used solely for bounded owned process-group
        # cleanup. This entrypoint owns startup/recovery and does not run its D2 loop.
        self.supervisor = ContainerSupervisor(
            self.controller, self.start_worker, process_group=True
        )
        self.authority = MutationAuthority(self.abandon)
        self.coordinator = ContainerRecoveryCoordinator(
            self.state,
            RecoveryHooks(
                self.guard, self.quiesce, self.reset, self.reconcile, self.health, self.reopen
            ),
            require_exclusive=lambda: self.authority.owner is not None,
        )
        self.ready = False
        self.service = ContainerRecoveryService(
            self.coordinator,
            self.authority,
            worker_running=lambda: bool(
                self.supervisor.worker and self.supervisor.worker.returncode is None
            ),
        )
        self.server = UnixControlServer(
            self.authority,
            callbacks={**self.service.callbacks, "status": self.status},
            ingress_callback=self.controller.ingress,
            worker_authorized=lambda pid: bool(
                self.supervisor.worker
                and self.supervisor.worker.pid == pid
                and self.supervisor.worker.returncode is None
            ),
        )
        self.stopping = asyncio.Event()

    async def status(self, payload):
        result = await self.service.status(payload)
        if result["state"] == "ready" and not self.ready:
            result["state"] = "blocked"
        return result

    async def guard(self, identities):
        self.ready = False
        await self.controller.arm_maintenance(identities)

    async def quiesce(self):
        # Do not use D2 quiesce's policy mutation before reaping a live D5 owner.
        self.supervisor.maintenance = True
        await self.supervisor.stop_worker()
        await self.controller.deactivate()

    async def reset(self):
        await self.controller.reset_policy()
        # Recognize only interfaces matching validated persisted generations;
        # fixed names alone are never ownership evidence. Ambiguity exits this
        # namespace rather than adopting or deleting an unrelated interface.
        from exitlane.providers.wireguard_keys import _public_key_for_private

        configs = None
        for name in ("wg-mullvad", "wg-pia", "wg-proton"):
            rc, output, _ = await self.controller.runner(
                "ip", "-j", "-d", "link", "show", "dev", name, timeout=5
            )
            if rc == 1:
                continue
            if rc:
                raise EntrypointError("container_guard_unproven")
            if configs is None:
                # Fresh initialization and interrupted publication can precede
                # a coherent published pair. An empty namespace has nothing to
                # remove; a surviving interface still requires full validation.
                inventory = self.state.validate()
                configs = [item.config for item in inventory.intents if item.config is not None]
            links = json.loads(output)
            if (
                not isinstance(links, list)
                or len(links) != 1
                or links[0].get("ifname") != name
                or links[0].get("linkinfo", {}).get("info_kind") != "wireguard"
                or type(links[0].get("ifindex")) is not int
            ):
                raise EntrypointError("container_provider_recovery_required")
            index = links[0]["ifindex"]
            public = (await self.controller.checked("wg", "show", name, "public-key")).strip()
            peers = (await self.controller.checked("wg", "show", name, "peers")).splitlines()
            endpoints = (
                await self.controller.checked("wg", "show", name, "endpoints")
            ).splitlines()
            addresses = json.loads(
                await self.controller.checked("ip", "-4", "-j", "address", "show", "dev", name)
            )
            actual = [
                (item.get("local"), item.get("prefixlen"))
                for link in addresses
                for item in link.get("addr_info", [])
                if item.get("family") == "inet"
            ]
            matched = False
            for config in configs:
                expected = ipaddress.IPv4Interface(config.address)
                if (
                    config.interface == name
                    and _public_key_for_private(config.private_key) == public
                    and peers == [config.peer_public_key]
                    and endpoints
                    == [
                        f"{config.peer_public_key}\t{config.endpoint_address}:{config.endpoint_port}"
                    ]
                    and actual == [(str(expected.ip), expected.network.prefixlen)]
                ):
                    matched = True
                    break
            if not matched:
                raise EntrypointError("container_provider_recovery_required")
            current = json.loads(
                await self.controller.checked("ip", "-j", "link", "show", "dev", name)
            )
            if len(current) != 1 or current[0].get("ifindex") != index:
                raise EntrypointError("container_interface_ownership_changed")
            await self.controller.checked("ip", "link", "delete", "dev", name)

    async def reconcile(self, inventory):
        await self.controller.reconcile(inventory)

    async def start_worker(self):
        from exitlane.container_control import _read, _write

        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent.setblocking(False)
        child.set_inheritable(True)
        environment = dict(os.environ)
        environment["EXITLANE_STARTUP_FD"] = str(child.fileno())
        try:
            worker = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "exitlane.container_entrypoint",
                "worker",
                start_new_session=True,
                pass_fds=(child.fileno(),),
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
            )
            child.close()
            self.supervisor.worker = worker
            self.supervisor.worker_group = worker.pid
            if os.getpgid(worker.pid) != worker.pid:
                raise EntrypointError("container_worker_process_group_invalid")
            reader, writer = await asyncio.open_connection(sock=parent)
            try:
                await _write(writer, {"command": "startup-grant", "version": 1})
                if await _read(reader, 30) != {"command": "initialized", "version": 1}:
                    raise EntrypointError("container_worker_startup_failed")
            finally:
                writer.close()
                await writer.wait_closed()
            return worker
        except BaseException:
            await self.supervisor.stop_worker()
            raise
        finally:
            parent.close()
            child.close()

    async def health(self):
        self.state.validate()
        if not self.supervisor.worker or self.supervisor.worker.returncode is not None:
            await self.start_worker()
        deadline = asyncio.get_running_loop().time() + 10
        while asyncio.get_running_loop().time() < deadline:
            if self.supervisor.worker.returncode is not None:
                return False
            if await asyncio.to_thread(_http_health):
                await self.controller.observe_policy()
                if self.controller.network:
                    await self.controller.network.observe_owned_ingress()
                return True
            await asyncio.sleep(0.1)
        return False

    async def reopen(self):
        await self.controller.observe_policy()
        if self.controller.network:
            await self.controller.network.observe_owned_ingress()
            await self.maintenance.release()
        # Empty first-run keeps its forward-drop table until validated ingress.
        self.supervisor.maintenance = False
        self.ready = True

    async def abandon(self, owner, reason):
        from exitlane.container_recovery import ingress_identities

        try:
            await self.guard(ingress_identities(self.state.layout.database))
            await self.quiesce()
            await self.reset()
            return True
        except Exception:  # noqa: BLE001 - never disclose child/provider material
            self.stopping.set()
            return False

    async def run(self):
        from exitlane.container_control import MutationOwner

        root = self.state.layout.root
        if root.exists():
            facts = root.lstat()
            if stat.S_ISDIR(facts.st_mode) and facts.st_uid == 0 and not any(root.iterdir()):
                root.chmod(0o700)
        await self.server.start()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self.stopping.set)
        try:
            async with self.authority.exclusive(MutationOwner(os.getpid(), "startup")):
                await self.coordinator.startup()
            attempts = 0
            while not self.stopping.is_set():
                worker = self.supervisor.worker
                wait = asyncio.create_task(worker.wait())
                stop = asyncio.create_task(self.stopping.wait())
                try:
                    await asyncio.wait((wait, stop), return_when=asyncio.FIRST_COMPLETED)
                    if self.stopping.is_set():
                        break
                    # Restore may have replaced this worker under the same authority.
                    async with self.authority.exclusive(MutationOwner(os.getpid(), "restart")):
                        if self.supervisor.worker is not worker:
                            continue
                        if attempts >= 2:
                            raise EntrypointError("container_worker_restart_exhausted")
                        attempts += 1
                        await self.coordinator.startup()
                finally:
                    for task in (wait, stop):
                        task.cancel()
                    await asyncio.gather(wait, stop, return_exceptions=True)
            return 0
        finally:
            self.ready = False
            await self.server.stop()
            try:
                await self.controller.arm_maintenance(self.maintenance.identities)
            finally:
                await self.supervisor.stop_worker()
                await self.controller.deactivate()
                for sig in (signal.SIGTERM, signal.SIGINT):
                    loop.remove_signal_handler(sig)


async def _health():
    from exitlane.container_control import UnixControlClient

    try:
        result = await UnixControlClient().request("status", {}, timeout=2)
        return (
            result.get("state") == "ready"
            and result.get("worker_running") is True
            and await asyncio.to_thread(_http_health)
        )
    except Exception:  # noqa: BLE001 - health is a bounded exit status, never diagnostics
        return False


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"serve", "worker", "health"}:
        return 2
    if sys.argv[1] == "health":
        return 0 if asyncio.run(_health()) else 1
    if sys.argv[1] == "worker":
        import uvicorn

        from exitlane.main import app

        uvicorn.run(app, host="0.0.0.0", port=8787, proxy_headers=False, access_log=False)
        return 0
    try:
        preflight()
        return asyncio.run(ContainerEntrypoint().run())
    except Exception:  # noqa: BLE001 - detailed child exceptions can contain provider secrets
        print(
            "ExitLane container startup/recovery failed; protected traffic remains blocked.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
