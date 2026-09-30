"""Experimental, synthetic-only container networking lifecycle.

This is deliberately not selected by the application's runtime composition yet.
D2 keeps protected client forwarding blocked; provider commit belongs to D3.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import signal
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from exitlane import core, lifecycle
from exitlane.services.provider_wireguard import RULE_PRIORITY, TABLE_ID, ProviderWireGuard

TABLE = "exitlane_container_guard"
INTERFACE = re.compile(r"[A-Za-z0-9-]{1,15}\Z")


class ContainerLifecycleError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(value: bool, code: str = "container_ingress_config_invalid") -> None:
    if not value:
        raise ContainerLifecycleError(code)


def key(value: str) -> str:
    require(isinstance(value, str))
    try:
        require(len(value) == 44 and len(base64.b64decode(value, validate=True)) == 32)
    except ValueError:
        raise ContainerLifecycleError("container_ingress_config_invalid") from None
    return value


@dataclass(frozen=True)
class IngressConfig:
    interface: str
    address: str
    private_key: str = field(repr=False)
    public_key: str = field(repr=False)
    allowed_ips: str
    listen_port: int
    keepalive: int = 25

    def validated(self) -> IngressConfig:
        require(
            all(
                isinstance(value, str)
                for value in (
                    self.interface,
                    self.address,
                    self.private_key,
                    self.public_key,
                    self.allowed_ips,
                )
            )
        )
        require(bool(INTERFACE.fullmatch(self.interface)))
        require(self.interface not in {"eth0", "lo", "wg-mullvad", "wg-pia", "wg-proton"})
        try:
            address = ipaddress.IPv4Interface(self.address)
            allowed = ipaddress.IPv4Network(self.allowed_ips, strict=True)
            require(address.network.prefixlen <= 31 and allowed.prefixlen == 32)
            require(
                allowed.network_address in address.network and allowed.network_address != address.ip
            )
            require(
                not address.ip.is_loopback
                and not address.ip.is_multicast
                and not address.ip.is_unspecified
            )
        except (ValueError, TypeError):
            raise ContainerLifecycleError("container_ingress_config_invalid") from None
        key(self.private_key)
        key(self.public_key)
        require(type(self.listen_port) is int and 1 <= self.listen_port <= 65535)
        require(type(self.keepalive) is int and 0 <= self.keepalive <= 65535)
        return self

    def wireguard_payload(self) -> str:
        self.validated()
        return (
            f"[Interface]\nPrivateKey = {self.private_key}\nListenPort = {self.listen_port}\n"
            f"[Peer]\nPublicKey = {self.public_key}\nAllowedIPs = {self.allowed_ips}\n"
            f"PersistentKeepalive = {self.keepalive}\n"
        )

    @classmethod
    def from_file(cls, path: Path) -> IngressConfig:
        descriptor = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            facts = os.fstat(descriptor)
            require(stat.S_ISREG(facts.st_mode) and facts.st_size <= 65536)
            require(facts.st_uid == os.geteuid() and facts.st_mode & 0o077 == 0)
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                content = source.read(65537)

            # Validate the exact in-memory bytes, avoiding a second file read.
            class Snapshot:
                stem = path.stem
                suffix = path.suffix

                def read_bytes(self):
                    return content

            lifecycle._validated_wireguard_hooks(Snapshot())
            values: dict[str, dict[str, str]] = {"Interface": {}, "Peer": {}}
            section = ""
            seen_sections = set()
            peer_count = 0
            for raw in content.decode("ascii").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line in ("[Interface]", "[Peer]"):
                    section = line[1:-1]
                    require(section not in seen_sections)
                    require(section == "Interface" or "Interface" in seen_sections)
                    seen_sections.add(section)
                    peer_count += int(section == "Peer")
                    require(peer_count <= 1)
                    continue
                require(bool(section) and "=" in line)
                name, value = (item.strip() for item in line.split("=", 1))
                if name in ("PostUp", "PostDown", "PreUp", "PreDown"):
                    # Only the shared native validator's exact generated hooks
                    # are accepted; they are never interpreted or executed.
                    require(section == "Interface")
                    continue
                allowed = (
                    {"Address", "PrivateKey", "ListenPort"}
                    if section == "Interface"
                    else {"PublicKey", "AllowedIPs", "PersistentKeepalive"}
                )
                require(name in allowed and name not in values[section])
                values[section][name] = value
            i, p = values["Interface"], values["Peer"]
            return cls(
                path.stem,
                i["Address"],
                i["PrivateKey"],
                p["PublicKey"],
                p["AllowedIPs"],
                int(i["ListenPort"]),
                int(p.get("PersistentKeepalive", "25")),
            ).validated()
        except (OSError, UnicodeError, ValueError, KeyError, lifecycle.LifecycleError):
            raise ContainerLifecycleError("container_ingress_config_invalid") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)


class ContainerWireGuardLifecycle:
    def __init__(self, config: IngressConfig, *, runner=core.command, provider_guard=None):
        self.config = config.validated()
        self.runner = runner
        self.provider_guard = provider_guard or ProviderWireGuard(runner)
        self.active = False
        self.owned_ifindex: int | None = None
        self.uncertain_creation = False

    async def checked(self, *arguments: str, input_text: str | None = None, timeout: float = 10):
        rc, output, _ = await self.runner(*arguments, input_text=input_text, timeout=timeout)
        if rc:
            raise ContainerLifecycleError("container_network_command_failed")
        return output

    def expressions(self) -> tuple[list[dict], list[dict]]:
        interface = [
            {
                "match": {
                    "op": "==",
                    "left": {"meta": {"key": "iifname"}},
                    "right": self.config.interface,
                }
            },
            {"drop": None},
        ]
        network = ipaddress.IPv4Interface(self.config.address).network
        source = [
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                    "right": {
                        "prefix": {"addr": str(network.network_address), "len": network.prefixlen}
                    },
                }
            },
            {"drop": None},
        ]
        return interface, source

    def validate_nft_guard(self, data: dict) -> None:
        require(
            isinstance(data, dict) and isinstance(data.get("nftables"), list),
            "container_guard_unproven",
        )
        objects = data["nftables"]
        require(
            all(
                isinstance(item, dict)
                and len(item) == 1
                and next(iter(item)) in {"metainfo", "table", "chain", "rule"}
                for item in objects
            ),
            "container_guard_unproven",
        )
        require(
            all(
                item["table"].get("family") == "inet" and item["table"].get("name") == TABLE
                for item in objects
                if "table" in item
            ),
            "container_guard_unproven",
        )
        chains = [item["chain"] for item in objects if "chain" in item]
        rules = [item["rule"] for item in objects if "rule" in item]
        require(
            len(chains) == 1
            and chains[0].get("family") == "inet"
            and chains[0].get("table") == TABLE
            and chains[0].get("name") == "forward"
            and chains[0].get("type") == "filter"
            and chains[0].get("hook") == "forward"
            and chains[0].get("prio") == -200
            and chains[0].get("policy") == "accept",
            "container_guard_unproven",
        )
        require(
            len(rules) == 2
            and all(
                rule.get("family") == "inet"
                and rule.get("table") == TABLE
                and rule.get("chain") == "forward"
                for rule in rules
            ),
            "container_guard_unproven",
        )
        require(
            [rule["expr"] for rule in rules] == list(self.expressions()),
            "container_guard_unproven",
        )

    async def observe_guard(self) -> None:
        try:
            data = json.loads(await self.checked("nft", "-j", "list", "table", "inet", TABLE))
            self.validate_nft_guard(data)
            for family in (4, 6):
                routes = json.loads(
                    await self.checked(
                        "ip", f"-{family}", "-j", "route", "show", "table", str(TABLE_ID)
                    )
                )
                rules = json.loads(await self.checked("ip", f"-{family}", "-j", "rule", "show"))
                require(
                    any(
                        route.get("type") == "unreachable" and route.get("dst") == "default"
                        for route in routes
                    ),
                    "container_guard_unproven",
                )
                require(
                    any(
                        rule.get("iif") == self.config.interface
                        and rule.get("priority") == RULE_PRIORITY
                        and str(rule.get("table")) == str(TABLE_ID)
                        for rule in rules
                    ),
                    "container_guard_unproven",
                )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ContainerLifecycleError("container_guard_unproven") from None

    async def arm_guard(self) -> None:
        try:
            tables = json.loads(await self.checked("nft", "-j", "list", "tables"))["nftables"]
            exists = any(
                item.get("table", {}).get("family") == "inet"
                and item.get("table", {}).get("name") == TABLE
                for item in tables
            )
            if exists:
                self.validate_nft_guard(
                    json.loads(await self.checked("nft", "-j", "list", "table", "inet", TABLE))
                )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ContainerLifecycleError("container_guard_resource_conflict") from None
        await self.provider_guard.arm((self.config.interface,))
        network = str(ipaddress.IPv4Interface(self.config.address).network)
        payload = (
            f"destroy table inet {TABLE}\ntable inet {TABLE} {{\n"
            "chain forward { type filter hook forward priority -200; policy accept;\n"
            f'iifname "{self.config.interface}" drop\nip saddr {network} drop\n'
            "}\n}\n"
        )
        await self.checked("nft", "-c", "-f", "/dev/stdin", input_text=payload)
        await self.checked("nft", "-f", "/dev/stdin", input_text=payload)
        await self.observe_guard()

    async def activate(self) -> None:
        require(not self.uncertain_creation, "container_interface_creation_uncertain")
        rc, _, _ = await self.runner("ip", "link", "show", "dev", self.config.interface, timeout=5)
        require(rc != 0, "container_interface_collision")
        require(rc == 1, "container_interface_probe_failed")
        forwarding = await self.checked("cat", "/proc/sys/net/ipv4/ip_forward")
        require(forwarding.strip() == "1", "container_forwarding_unavailable")
        await self.arm_guard()
        try:
            self.uncertain_creation = True
            await self.checked(
                "ip", "link", "add", "dev", self.config.interface, "type", "wireguard"
            )
            self.owned_ifindex = await self.interface_index()
            self.uncertain_creation = False
            self.active = True
            await self.checked(
                "wg",
                "setconf",
                self.config.interface,
                "/dev/stdin",
                input_text=self.config.wireguard_payload(),
            )
            await self.checked(
                "ip", "-4", "address", "add", self.config.address, "dev", self.config.interface
            )
            await self.checked("ip", "link", "set", "dev", self.config.interface, "up")
            await self.observe_guard()
        except BaseException:
            if self.uncertain_creation:
                # The kernel may have created an interface even when the command
                # timed out/cancelled. No ownership proof means no name-based
                # cleanup or retry; the supervisor must exit the namespace.
                raise ContainerLifecycleError("container_interface_creation_uncertain") from None
            await self.deactivate()
            raise

    async def interface_index(self) -> int:
        try:
            facts = json.loads(
                await self.checked("ip", "-j", "link", "show", "dev", self.config.interface)
            )
            require(
                isinstance(facts, list)
                and len(facts) == 1
                and facts[0].get("ifname") == self.config.interface,
                "container_interface_ownership_unproven",
            )
            index = facts[0].get("ifindex")
            require(type(index) is int and index > 0, "container_interface_ownership_unproven")
            return index
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ContainerLifecycleError("container_interface_ownership_unproven") from None

    async def deactivate(self) -> None:
        if self.active:
            require(
                await self.interface_index() == self.owned_ifindex,
                "container_interface_ownership_changed",
            )
            await self.checked("ip", "link", "delete", "dev", self.config.interface)
            self.active = False
            self.owned_ifindex = None

    async def observe(self) -> bool:
        await self.observe_guard()
        rc, _, _ = await self.runner("ip", "link", "show", "dev", self.config.interface, timeout=5)
        if self.active and rc == 0:
            require(
                await self.interface_index() == self.owned_ifindex,
                "container_interface_ownership_changed",
            )
            return True
        return False


class ContainerSupervisor:
    """One bounded worker under init; lifecycle lease/restore IPC belongs to D4."""

    def __init__(
        self,
        network: ContainerWireGuardLifecycle,
        worker_factory: Callable[[], Awaitable],
        *,
        restart_budget: int = 2,
        stop_timeout: float = 5,
    ):
        require(
            type(restart_budget) is int and 0 <= restart_budget <= 10,
            "container_supervisor_invalid",
        )
        require(0 < stop_timeout <= 30, "container_supervisor_invalid")
        self.network = network
        self.worker_factory = worker_factory
        self.restart_budget = restart_budget
        self.stop_timeout = stop_timeout
        self.stopping = asyncio.Event()
        self.worker = None

    def request_stop(self) -> None:
        self.stopping.set()

    async def stop_worker(self) -> None:
        if self.worker and self.worker.returncode is None:
            self.worker.terminate()
            try:
                await asyncio.wait_for(self.worker.wait(), self.stop_timeout)
            except TimeoutError:
                self.worker.kill()
                await asyncio.wait_for(self.worker.wait(), self.stop_timeout)

    async def run(self, *, install_signals: bool = True) -> int:
        loop = asyncio.get_running_loop()
        installed = []
        if install_signals:
            for item in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(item, self.request_stop)
                installed.append(item)
        try:
            for attempt in range(self.restart_budget + 1):
                if self.stopping.is_set():
                    return 0
                await self.network.activate()
                self.worker = await asyncio.wait_for(self.worker_factory(), 10)
                wait = asyncio.create_task(self.worker.wait())
                stop = asyncio.create_task(self.stopping.wait())
                try:
                    await asyncio.wait((wait, stop), return_when=asyncio.FIRST_COMPLETED)
                    await self.network.deactivate()
                    await self.network.observe_guard()
                    await self.stop_worker()
                    if self.stopping.is_set():
                        return 0
                    if attempt == self.restart_budget:
                        return 1
                finally:
                    for task in (wait, stop):
                        task.cancel()
                    await asyncio.gather(wait, stop, return_exceptions=True)
            return 1
        finally:
            try:
                await self.network.deactivate()
            finally:
                await self.stop_worker()
                for item in installed:
                    loop.remove_signal_handler(item)
