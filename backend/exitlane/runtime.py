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
    if selected != "native":
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
            "runtime": "native",
            "supported": True,
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
        from exitlane.container_state import ContainerLayout

        layout = ContainerLayout(root)
        return cls(layout.config, layout.state, layout.state, layout.root / "logs", layout.wireguard)


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


validate_runtime_selection()
runtime = NativeSystemdRuntime()
