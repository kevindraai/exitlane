"""Explicit runtime composition; native Debian remains the only implemented runtime.

Container coordination will acquire an outer lifecycle lease before provider claims
and network locks. Existing native backup/restore locking does not cover ordinary
application mutations. This module does not introduce a global native lease.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path


class RuntimeCapabilityUnavailable(RuntimeError):
    code = "runtime_capability_unavailable"

    def __init__(self, capability: str):
        super().__init__(self.code)
        self.capability = capability


def validate_runtime_selection() -> str:
    selected = os.getenv("EXITLANE_RUNTIME", "native")
    if selected not in {"native", "container"}:
        raise RuntimeError("runtime_unavailable")
    return selected


@dataclass(frozen=True)
class RuntimeCapabilities:
    system_actions: tuple[str, ...] = ("restart", "reboot", "shutdown")
    providers: tuple[str, ...] = ("nordvpn", "mullvad", "pia", "proton")
    ingress: bool = True
    restore: bool = True
    timezone_configuration: bool = True
    host_timezone: bool = True
    host_metrics: bool = True
    diagnostics: bool = True
    host_diagnostics: bool = True
    package_installation: bool = True
    speedtest: bool = True
    native_upgrade: bool = True
    direct_egress: bool = True
    runtime_name: str = "native"
    supported: bool = True
    metric_scope: str = "host"

    def require(self, capability: str) -> None:
        if not getattr(self, capability, False):
            raise RuntimeCapabilityUnavailable(capability)

    def require_provider(self, provider_id: str) -> None:
        if provider_id not in self.providers:
            raise RuntimeCapabilityUnavailable("provider")

    def require_action(self, action: str) -> None:
        if action not in self.system_actions:
            raise RuntimeCapabilityUnavailable("system_action")

    def projection(self) -> dict:
        return {
            "runtime": self.runtime_name,
            "supported": self.supported,
            "metric_scope": self.metric_scope,
            "system_actions": list(self.system_actions),
            "providers": list(self.providers),
            **{
                name: getattr(self, name)
                for name in (
                    "ingress",
                    "restore",
                    "timezone_configuration",
                    "host_timezone",
                    "host_metrics",
                    "diagnostics",
                    "host_diagnostics",
                    "package_installation",
                    "speedtest",
                    "native_upgrade",
                    "direct_egress",
                )
            },
        }


@dataclass(frozen=True)
class RuntimePaths:
    # Preserve historical independent native defaults. Unifying these is a migration.
    config: Path
    application_data: Path
    service_data: Path
    logs: Path
    system_wireguard: Path = Path("/etc/wireguard")

    @classmethod
    def native(cls):
        return cls(
            Path(os.getenv("EXITLANE_CONFIG_DIR", "/etc/exitlane")),
            Path(os.getenv("EXITLANE_DATA_DIR", "/etc/exitlane")),
            Path(os.getenv("EXITLANE_DATA_DIR", "/var/lib/exitlane")),
            Path(os.getenv("EXITLANE_LOG_DIR", "/var/log/exitlane")),
        )

    @classmethod
    def container(cls, root: Path = Path("/data")):
        """Fixed durable paths; this does not enable container composition."""
        from exitlane.container_paths import ContainerLayout

        layout = ContainerLayout(root)
        return cls(
            layout.config, layout.state, layout.state, layout.root / "logs", layout.wireguard
        )


SYSTEM_ACTION_COMMANDS = {
    "restart": ("/usr/bin/systemctl", "restart", "exitlane.service"),
    "reboot": ("/usr/bin/systemctl", "reboot"),
    "shutdown": ("/usr/bin/systemctl", "poweroff"),
}


class NativeSystemdRuntime:
    coordinated_mutations = False

    def __init__(self, capabilities: RuntimeCapabilities | None = None):
        self.capabilities = capabilities or RuntimeCapabilities()
        self.paths = RuntimePaths.native()

    @asynccontextmanager
    async def mutation(self):
        # Native retains its existing transaction/network locks and concurrency.
        yield

    @asynccontextmanager
    async def startup_mutation(self):
        # Native startup retains existing initializer and systemd ordering.
        yield

    async def launch_system_action(self, action: str, *, launcher=asyncio.create_subprocess_exec):
        self.capabilities.require_action(action)
        return await launcher(
            *SYSTEM_ACTION_COMMANDS[action],
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )

    async def system_status(self, data: Path, *, observer):
        self.capabilities.require("host_metrics")
        return await observer(data)

    def read_timezone(self, *, reader):
        self.capabilities.require("host_timezone")
        return reader()

    async def set_timezone(self, timezone: str, *, setter):
        self.capabilities.require("timezone_configuration")
        self.capabilities.require("host_timezone")
        return await setter(timezone)

    async def diagnostics(self, *, observer):
        self.capabilities.require("diagnostics")
        self.capabilities.require("host_diagnostics")
        return await observer()

    async def observe_ingress(self, interface: str, *, runner):
        self.capabilities.require("ingress")
        rc, _, _ = await runner(
            "systemctl", "is-active", "--quiet", f"wg-quick@{interface}.service"
        )
        return rc == 0

    async def activate_ingress(
        self, interface: str, *, source_directory, system_directory, runner
    ) -> None:
        self.capabilities.require("ingress")
        source_config = source_directory / f"{interface}.conf"
        system_config = system_directory / f"{interface}.conf"
        service_name = f"wg-quick@{interface}.service"

        if not source_config.exists():
            raise RuntimeError(f"WireGuard-configuratie ontbreekt: {source_config}")

        system_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        source_config.chmod(0o600)

        if system_config.is_symlink():
            if system_config.resolve() != source_config.resolve():
                system_config.unlink()
                system_config.symlink_to(source_config)
        elif system_config.exists():
            raise RuntimeError(f"{system_config} bestaat al en is geen symlink.")
        else:
            system_config.symlink_to(source_config)

        enable_rc, _, enable_error = await runner(
            "systemctl",
            "enable",
            service_name,
        )

        if enable_rc != 0:
            raise RuntimeError(enable_error or "De WireGuard-service kon niet worden ingeschakeld.")

        service_rc, _, _ = await runner(
            "systemctl",
            "is-active",
            "--quiet",
            service_name,
        )

        if service_rc != 0:
            link_rc, _, _ = await runner(
                "ip",
                "link",
                "show",
                "dev",
                interface,
            )

            if link_rc == 0:
                await runner(
                    "wg-quick",
                    "down",
                    str(source_config),
                )

        restart_rc, _, restart_error = await runner(
            "systemctl",
            "restart",
            service_name,
        )

        if restart_rc != 0:
            raise RuntimeError(restart_error or "De WireGuard-service kon niet worden gestart.")

        active_rc, _, active_error = await runner(
            "systemctl",
            "is-active",
            "--quiet",
            service_name,
        )

        if active_rc != 0:
            raise RuntimeError(active_error or "De WireGuard-service is niet actief geworden.")

    def restore_ingress(self, *, start: bool, core, lifecycle, killswitch) -> None:
        self.capabilities.require("restore")
        if not core.setting("wireguard_configured", False):
            return
        ingress, _ = killswitch.configuration()
        interface = ingress[0]
        unit = f"wg-quick@{interface}.service"
        if start:
            source = core.WG_DIR / f"{interface}.conf"
            lifecycle._safe_regular_file(source)
            system_directory = self.paths.system_wireguard
            system_directory.mkdir(mode=0o700, exist_ok=True)
            target = system_directory / source.name
            if target.is_symlink():
                if target.resolve() != source.resolve():
                    raise lifecycle.LifecycleError("restore_ingress_config_conflict")
            elif target.exists():
                raise lifecycle.LifecycleError("restore_ingress_config_conflict")
            else:
                target.symlink_to(source)
            commands = (("enable", unit), ("restart", unit))
        else:
            commands = (("disable", "--now", unit),)
        for arguments in commands:
            rc, _, _ = asyncio.run(
                core.command(
                    "/usr/bin/systemctl",
                    *arguments,
                    timeout=30,
                    environment={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
                )
            )
            if rc:
                raise lifecycle.LifecycleError("restore_ingress_service_failed")

    async def service_action(self, action: str, *, runner):
        self.capabilities.require("restore")
        if action not in {"start", "stop"}:
            raise RuntimeCapabilityUnavailable("service_action")
        return await runner(
            "/usr/bin/systemctl",
            action,
            "exitlane.service",
            timeout=30,
            environment={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )

    def restore(self, source, passphrase, *, restore_transaction: Callable, **callbacks):
        self.capabilities.require("restore")
        return restore_transaction(source, passphrase, **callbacks)


class ContainerRuntime:
    """Bounded container adapter; support remains gated by host qualification."""

    coordinated_mutations = True

    def __init__(self):
        from exitlane.container_control import UnixControlClient
        from exitlane.runtime_mutation import ContainerMutationBoundary

        self.paths = RuntimePaths.container()
        for name, expected in (
            ("EXITLANE_DATA_DIR", self.paths.application_data),
            ("EXITLANE_CONFIG_DIR", self.paths.config),
            ("EXITLANE_MASTER_KEY_FILE", self.paths.config / "secret.key"),
            ("EXITLANE_LOG_DIR", self.paths.logs),
        ):
            if name in os.environ and Path(os.environ[name]) != expected:
                raise RuntimeError("container_path_override_invalid")
        self.capabilities = RuntimeCapabilities(
            system_actions=(),
            providers=("mullvad", "pia", "proton"),
            timezone_configuration=False,
            host_timezone=False,
            host_metrics=False,
            host_diagnostics=False,
            package_installation=False,
            speedtest=False,
            native_upgrade=False,
            direct_egress=False,
            runtime_name="container",
            supported=False,
            metric_scope="container",
        )
        self.client = UnixControlClient()
        self.boundary = ContainerMutationBoundary(self.client)
        self.network = None

    async def legacy_provider_conflict(self):
        from exitlane import core

        rc, _, _ = await core.command("nft", "list", "table", "inet", "mullvad", timeout=3)
        return rc == 0

    def mutation(self):
        return self.boundary.mutation()

    def startup_mutation(self):
        return self.boundary.startup_mutation()

    async def launch_system_action(self, action, **_kwargs):
        self.capabilities.require_action(action)

    async def system_status(self, data, *, observer):
        from exitlane.container_observation import system_status

        return await system_status(data)

    def read_timezone(self, **_kwargs):
        # The read-only image uses UTC; this is not Docker host timezone state.
        return "UTC"

    async def set_timezone(self, _timezone, **_kwargs):
        self.capabilities.require("timezone_configuration")

    async def diagnostics(self, *, observer):
        from exitlane.container_observation import diagnostics

        return await diagnostics(self.network)

    async def observe_ingress(self, _interface, *, runner):
        result = await self.client.request(
            "ingress", {"action": "observe", "interface": _interface}
        )
        return result.get("active") is True

    async def activate_ingress(self, _interface, **_kwargs):
        await self.client.request("ingress", {"action": "activate", "interface": _interface})
        await self.configure_providers(_interface)
        await self.client.request("ingress", {"action": "observe", "interface": _interface})

    async def configure_providers(self, interface_override=None):
        from exitlane import core
        from exitlane.container_egress import ContainerWireGuardEgress
        from exitlane.container_runtime import ContainerWireGuardLifecycle, IngressConfig
        from exitlane.providers import catalog

        if interface_override is None and not core.setting("wireguard_configured", False):
            return
        interface = interface_override or core.setting("wireguard_interface")
        config = IngressConfig.from_file(core.WG_DIR / f"{interface}.conf")
        # The worker owns policy only; parent exclusively creates/deletes ingress.
        if self.network is not None:
            if (
                self.network.config.interface != config.interface
                or self.network.config.address != config.address
            ):
                raise RuntimeError("container_ingress_identity_change_unsupported")
            self.network.config = config
            await self.network.observe_guard()
            return
        self.network = ContainerWireGuardLifecycle(config)
        await self.network.arm_guard()
        await self.network.observe_guard()
        for provider in catalog.provider_registry.direct_egress_providers():
            provider.wireguard = ContainerWireGuardEgress(self.network)

    async def resume_provider(self):
        from exitlane import core
        from exitlane.container_paths import ContainerLayout
        from exitlane.container_state import ContainerState
        from exitlane.providers import catalog
        from exitlane.services import killswitch

        if self.network is None:
            return
        inventory = ContainerState(ContainerLayout(Path("/data"))).validate()
        # The parent still owns its independent maintenance guard and startup
        # lease. Shared transition state may outlive a restored database; first
        # prove the permanent container policy before touching that shared table.
        await self.network.observe_guard()

        async def remain_blocked():
            if core.setting(killswitch.SETTING_CONFIGURED, False) or core.setting(
                killswitch.SETTING_TRANSITION, False
            ):
                await killswitch.reconcile(killswitch.TunnelFacts(False))

        selected = inventory.selected_provider
        if selected is None or any(item.status != "active" for item in inventory.intents):
            # A different provider's pending generation also prevents completion
            # of the shared transaction. Never promote or register it at startup.
            await remain_blocked()
            return
        intent = next((item for item in inventory.intents if item.provider_id == selected), None)
        if intent is None or intent.config is None:
            await remain_blocked()
            return
        provider = catalog.provider_registry.get(selected)
        config = intent.config
        await provider.wireguard.start(config, (self.network.config.interface,))
        facts = await provider.wireguard.probe(config)
        if facts.get("ready") is not True:
            await remain_blocked()
            return
        await provider.wireguard.committed(config)
        await self.network.observe_guard()
        # Reuse the shared transaction service only after this exact persisted
        # active generation has fresh D3 proof. Enabled settings produce current
        # protected rules; disabled settings remove a stale temporary table.
        # Failure prevents the worker's initialized ACK and maintenance release.
        await killswitch.complete_provider_transition(
            killswitch.TunnelFacts(
                True,
                interface=config.interface,
                supports_ipv4=True,
                supports_ipv6=False,
                protected_egress=True,
            )
        )

    def restore(self, *_args, **_kwargs):
        raise RuntimeCapabilityUnavailable("native_restore")

    async def service_action(self, _action, **_kwargs):
        raise RuntimeCapabilityUnavailable("host_service")


validate_runtime_selection()
runtime = NativeSystemdRuntime() if validate_runtime_selection() == "native" else ContainerRuntime()
