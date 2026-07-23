from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Awaitable, Callable

from exitlane import core

TABLE_FAMILY = "inet"
TABLE_NAME = "exitlane_killswitch"
SETTING_CONFIGURED = "network.exitlane_killswitch.configured"
SETTING_INGRESS = "network.exitlane_killswitch.routed_ingress_interfaces"
SETTING_LOCAL_ALLOWLIST = "network.exitlane_killswitch.local_allowlist"
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
SAFE_REASONS = {
    "disabled",
    "tunnel_available",
    "tunnel_unavailable",
    "tunnel_interface_unknown",
    "provider_unavailable",
    "firewall_unavailable",
    "firewall_apply_failed",
    "firewall_rules_missing",
    "invalid_configuration",
}


class KillswitchError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code if code in SAFE_REASONS else "firewall_apply_failed"


@dataclass(frozen=True)
class TunnelFacts:
    available: bool
    interface: str | None = None
    supports_ipv4: bool = False
    supports_ipv6: bool = False
    protected_egress: bool = False
    reason: str = "tunnel_unavailable"


@dataclass(frozen=True)
class KillswitchStatus:
    configured: bool
    effective: bool
    state: str
    reason: str
    tunnel_available: bool
    tunnel_interface_known: bool
    firewall_rules_installed: bool
    ipv4_protected: bool
    ipv6_protected: bool
    protected_sources: tuple[str, ...]
    local_allowlist: tuple[str, ...]
    last_transition: str | None

    def as_dict(self) -> dict:
        return asdict(self)


Runner = Callable[..., Awaitable[tuple[int, str, str]]]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _interface(value: str) -> str:
    if not isinstance(value, str) or not INTERFACE_RE.fullmatch(value):
        raise KillswitchError("invalid_configuration")
    return value


def validate_allowlist(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError) as error:
            raise KillswitchError("invalid_configuration") from error
        if network.prefixlen == 0:
            raise KillswitchError("invalid_configuration")
        result.append(str(network))
    return tuple(dict.fromkeys(result))


def configuration() -> tuple[tuple[str, ...], tuple[str, ...]]:
    wireguard = _interface(core.setting("wireguard.interface", "wg0"))
    routed = core.setting(SETTING_INGRESS, [])
    if not isinstance(routed, list):
        raise KillswitchError("invalid_configuration")
    ingress = tuple(dict.fromkeys((wireguard, *(_interface(item) for item in routed))))
    allowed = core.setting(SETTING_LOCAL_ALLOWLIST, [])
    if not isinstance(allowed, list):
        raise KillswitchError("invalid_configuration")
    return ingress, validate_allowlist(allowed)


def generate_ruleset(
    facts: TunnelFacts, *, ingress: tuple[str, ...], local_allowlist: tuple[str, ...]
) -> str:
    sources = ", ".join(f'"{item}"' for item in ingress)
    v4_local = ", ".join(item for item in local_allowlist if ":" not in item)
    v6_local = ", ".join(item for item in local_allowlist if ":" in item)
    lines = [
        f"destroy table {TABLE_FAMILY} {TABLE_NAME}",
        f"table {TABLE_FAMILY} {TABLE_NAME} {{",
        f"  set protected_ingress {{ type ifname; elements = {{ {sources} }} }}",
    ]
    if v4_local:
        lines.append(
            f"  set local_v4 {{ type ipv4_addr; flags interval; elements = {{ {v4_local} }} }}"
        )
    if v6_local:
        lines.append(
            f"  set local_v6 {{ type ipv6_addr; flags interval; elements = {{ {v6_local} }} }}"
        )
    lines.extend(
        [
            "  chain forward {",
            "    type filter hook forward priority -150; policy accept;",
            '    ct state established,related accept comment "ExitLane return traffic"',
        ]
    )
    if v4_local:
        lines.append(
            '    iifname @protected_ingress ip daddr @local_v4 accept comment "ExitLane local IPv4"'
        )
    if v6_local:
        lines.append(
            '    iifname @protected_ingress ip6 daddr @local_v6 accept comment "ExitLane local IPv6"'
        )
    if facts.available and facts.protected_egress and facts.interface:
        interface = _interface(facts.interface)
        if facts.supports_ipv4:
            lines.append(
                f'    iifname @protected_ingress meta nfproto ipv4 oifname "{interface}" accept comment "ExitLane protected IPv4"'
            )
        if facts.supports_ipv6:
            lines.append(
                f'    iifname @protected_ingress meta nfproto ipv6 oifname "{interface}" accept comment "ExitLane protected IPv6"'
            )
    lines.extend(
        [
            '    iifname @protected_ingress udp dport 53 drop comment "ExitLane DNS leak guard"',
            '    iifname @protected_ingress tcp dport 53 drop comment "ExitLane DNS leak guard"',
            '    iifname @protected_ingress drop comment "ExitLane fail closed"',
            "  }",
        ]
    )
    if facts.available and facts.protected_egress and facts.interface and facts.supports_ipv4:
        lines.extend(
            [
                "  chain postrouting {",
                "    type nat hook postrouting priority srcnat; policy accept;",
                f'    iifname @protected_ingress oifname "{_interface(facts.interface)}" masquerade comment "ExitLane client NAT"',
                "  }",
            ]
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


class NftBackend:
    def __init__(self, runner: Runner = core.command):
        self.runner = runner

    async def installed(self) -> bool:
        rc, _, _ = await self.runner("nft", "list", "table", TABLE_FAMILY, TABLE_NAME, timeout=10)
        return rc == 0

    async def snapshot(self) -> str | None:
        rc, output, _ = await self.runner(
            "nft", "list", "table", TABLE_FAMILY, TABLE_NAME, timeout=10
        )
        return output + "\n" if rc == 0 else None

    async def _load(self, ruleset: str, *, check: bool) -> None:
        core.DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=".killswitch-", dir=core.DATA, delete=False
        ) as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(ruleset)
            path = Path(handle.name)
        try:
            arguments = ("nft", "-c", "-f", str(path)) if check else ("nft", "-f", str(path))
            rc, _, _ = await self.runner(*arguments, timeout=15)
            if rc != 0:
                raise KillswitchError("firewall_apply_failed")
        finally:
            path.unlink(missing_ok=True)

    async def apply(self, ruleset: str) -> None:
        previous = await self.snapshot()
        await self._load(ruleset, check=True)
        try:
            await self._load(ruleset, check=False)
        except KillswitchError:
            if previous is not None:
                rollback = f"destroy table {TABLE_FAMILY} {TABLE_NAME}\n{previous}"
                try:
                    await self._load(rollback, check=False)
                except KillswitchError:
                    pass
            raise

    async def remove(self) -> None:
        if await self.installed():
            await self._load(f"destroy table {TABLE_FAMILY} {TABLE_NAME}\n", check=False)


def _transition(value: str | None = None) -> str | None:
    key = "network.exitlane_killswitch.last_transition"
    if value is not None:
        core.set_setting(key, value)
        return value
    return core.setting(key, None)


async def status(facts: TunnelFacts, backend: NftBackend | None = None) -> KillswitchStatus:
    configured = bool(core.setting(SETTING_CONFIGURED, False))
    ingress, local = configuration()
    installed = await (backend or NftBackend()).installed()
    protected = bool(
        configured
        and installed
        and facts.available
        and facts.protected_egress
        and facts.interface
        and facts.supports_ipv4
    )
    if not configured:
        state, reason, effective = "disabled", "disabled", False
    elif not installed:
        state, reason, effective = "error", "firewall_rules_missing", False
    elif protected:
        state, reason, effective = "enabled_protected", "tunnel_available", True
    elif facts.reason == "tunnel_interface_unknown":
        state, reason, effective = "enabled_degraded", "tunnel_interface_unknown", True
    else:
        state, reason, effective = "enabled_waiting_for_tunnel", facts.reason, True
    return KillswitchStatus(
        configured,
        effective,
        state,
        reason if reason in SAFE_REASONS else "tunnel_unavailable",
        facts.available,
        facts.interface is not None,
        installed,
        protected,
        bool(protected and facts.supports_ipv6),
        ingress,
        local,
        _transition(),
    )


async def enable(facts: TunnelFacts, backend: NftBackend | None = None) -> KillswitchStatus:
    ingress, local = configuration()
    firewall = backend or NftBackend()
    await firewall.apply(generate_ruleset(facts, ingress=ingress, local_allowlist=local))
    if not await firewall.installed():
        raise KillswitchError("firewall_rules_missing")
    core.set_setting(SETTING_CONFIGURED, True)
    _transition(_now())
    return await status(facts, firewall)


async def reconcile(facts: TunnelFacts, backend: NftBackend | None = None) -> KillswitchStatus:
    firewall = backend or NftBackend()
    if not core.setting(SETTING_CONFIGURED, False):
        return await status(facts, firewall)
    ingress, local = configuration()
    await firewall.apply(generate_ruleset(facts, ingress=ingress, local_allowlist=local))
    _transition(_now())
    return await status(facts, firewall)


async def disable(backend: NftBackend | None = None) -> KillswitchStatus:
    firewall = backend or NftBackend()
    await firewall.remove()
    core.set_setting(SETTING_CONFIGURED, False)
    _transition(_now())
    return await status(TunnelFacts(False), firewall)
