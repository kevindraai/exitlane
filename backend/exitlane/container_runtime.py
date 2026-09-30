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
import time
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
        self.policy_interface: str | None = None
        self.provider_interfaces = ("wg-mullvad", "wg-pia", "wg-proton")
        self.mutation_lock = asyncio.Lock()
        self.policy_lock = asyncio.Lock()
        self.policy_epoch = 0
        self.policy_candidate = None
        self.policy_proof = None
        self.policy_committed = None
        self.source_addresses: tuple[str, ...] = ()
        self.probe_interface: str | None = None

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

    def forward_expressions(self, interface: str | None = None) -> list[list[dict]]:
        blocks = list(self.expressions())
        if interface is None:
            return blocks
        return [
            [
                blocks[0][0],
                {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}},
                {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": interface}},
                {"accept": None},
            ],
            *blocks,
        ]

    def input_expressions(self) -> list[list[dict]]:
        return [
            [
                selector,
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": protocol, "field": "dport"}},
                        "right": 53,
                    }
                },
                {"drop": None},
            ]
            for selector in (self.expressions()[0][0], self.expressions()[1][0])
            for protocol in ("udp", "tcp")
        ]

    def nat_expressions(self, interface: str) -> list[list[dict]]:
        return [
            [
                self.expressions()[0][0],
                {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}},
                {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": interface}},
                {"masquerade": None},
            ]
        ]

    def output_expressions(self, *, sources=None, probe_interface=...) -> list[list[dict]]:
        sources = self.source_addresses if sources is None else sources
        interface = self.probe_interface if probe_interface is ... else probe_interface
        rules = []
        for address in sources:
            selector = {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": address}}
            if interface is not None:
                rules.append([selector, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": interface}}, {"accept": None}])
            rules.append([selector, {"drop": None}])
        return rules

    def validate_nft_guard(self, data: dict, *, policy_interface=..., sources=None, probe_interface=...) -> None:
        interface = self.policy_interface if policy_interface is ... else policy_interface
        source_inventory = self.source_addresses if sources is None else sources
        probe = self.probe_interface if probe_interface is ... else probe_interface
        require(
            interface is None or interface in self.provider_interfaces, "container_guard_unproven"
        )
        require(probe is None or probe in self.provider_interfaces, "container_guard_unproven")
        require(interface is None or (interface == probe and bool(source_inventory)), "container_guard_unproven")
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
        expected = {
            "forward": ("filter", -200, self.forward_expressions(interface)),
            "input": ("filter", -200, self.input_expressions()),
            "output": ("filter", 0, self.output_expressions(sources=sources, probe_interface=probe_interface)),
        }
        if interface is not None:
            expected["postrouting"] = ("nat", 100, self.nat_expressions(interface))
        require(len(chains) == len(expected), "container_guard_unproven")
        require(
            len(rules) == sum(len(value[2]) for value in expected.values()),
            "container_guard_unproven",
        )
        for name, (kind, priority, expressions) in expected.items():
            matched = [chain for chain in chains if chain.get("name") == name]
            require(len(matched) == 1, "container_guard_unproven")
            chain = matched[0]
            require(
                chain.get("family") == "inet"
                and chain.get("table") == TABLE
                and chain.get("type") == kind
                and chain.get("hook") == name
                and chain.get("prio") == priority
                and chain.get("policy") == "accept",
                "container_guard_unproven",
            )
            chain_rules = [rule for rule in rules if rule.get("chain") == name]
            require(
                all(
                    rule.get("family") == "inet" and rule.get("table") == TABLE
                    for rule in chain_rules
                ),
                "container_guard_unproven",
            )
            require(
                [rule.get("expr") for rule in chain_rules] == expressions,
                "container_guard_unproven",
            )

    def validate_previous_policy(self, data: dict) -> None:
        # Startup may revoke a structurally exact previously committed policy.
        # Recognition grants no forwarding permission and never adopts foreign
        # chains/rules, even in our reserved table.
        # Infer only literal historical /32 addresses; the complete exact shape
        # is then verified, including all rules, selectors, verdicts and chains.
        sources = set()
        try:
            for item in data["nftables"]:
                rule = item.get("rule", {})
                if rule.get("chain") != "output":
                    continue
                selector = rule["expr"][0]["match"]
                require(selector["op"] == "==" and selector["left"] == {"payload": {"protocol": "ip", "field": "saddr"}}, "container_guard_resource_conflict")
                address = selector["right"]
                parsed = ipaddress.IPv4Address(address)
                require(isinstance(address, str) and str(parsed) == address and not (parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_reserved or parsed.is_link_local or parsed in ipaddress.IPv4Network("0.0.0.0/8")), "container_guard_resource_conflict")
                sources.add(address)
            require(len(sources) <= 64, "container_guard_resource_conflict")
        except (ValueError, KeyError, TypeError, AttributeError, IndexError):
            raise ContainerLifecycleError("container_guard_resource_conflict") from None
        sources = tuple(sorted(sources))
        for interface in (None, *self.provider_interfaces):
            for probe in (None, *self.provider_interfaces):
                try:
                    self.validate_nft_guard(data, policy_interface=interface, sources=sources, probe_interface=probe)
                    self.source_addresses = sources
                    return
                except ContainerLifecycleError:
                    pass
        raise ContainerLifecycleError("container_guard_resource_conflict")

    def guard_payload(self, interface: str | None, *, sources=None, probe_interface=...) -> str:
        sources = self.source_addresses if sources is None else sources
        probe = self.probe_interface if probe_interface is ... else probe_interface
        subnet = str(ipaddress.IPv4Interface(self.config.address).network)
        protected = (f'iifname "{self.config.interface}"', f"ip saddr {subnet}")
        lines = [
            f"destroy table inet {TABLE}",
            f"table inet {TABLE} {{",
            "chain forward { type filter hook forward priority -200; policy accept;",
        ]
        if interface:
            lines.append(f'{protected[0]} meta nfproto ipv4 oifname "{interface}" accept')
        lines += [f"{selector} drop" for selector in protected]
        lines += ["}", "chain input { type filter hook input priority -200; policy accept;"]
        lines += [
            f"{selector} {protocol} dport 53 drop"
            for selector in protected
            for protocol in ("udp", "tcp")
        ]
        lines += ["}"]
        lines += ["chain output { type filter hook output priority 0; policy accept;"]
        for address in sources:
            if probe is not None:
                lines.append(f'ip saddr {address} oifname "{probe}" accept')
            lines.append(f"ip saddr {address} drop")
        lines += ["}"]
        if interface:
            lines += [
                "chain postrouting { type nat hook postrouting priority srcnat; policy accept;",
                f'{protected[0]} meta nfproto ipv4 oifname "{interface}" masquerade',
                "}",
            ]
        return "\n".join([*lines, "}", ""])

    async def register_source(self, config) -> None:
        # Called under the policy lock, before address assignment or probing.
        try:
            address = str(ipaddress.IPv4Interface(config.address).ip)
            parsed = ipaddress.IPv4Address(address)
            require(config.interface in self.provider_interfaces and not (parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_reserved or parsed.is_link_local or parsed in ipaddress.IPv4Network("0.0.0.0/8")), "container_provider_invalid")
            sources = tuple(sorted(set(self.source_addresses) | {address}))
            require(len(sources) <= 64, "container_provider_source_budget_exhausted")
        except (ValueError, TypeError, AttributeError):
            raise ContainerLifecycleError("container_provider_invalid") from None
        await self._rewrite_policy(None, sources=sources, probe=config.interface)

    async def restrict_provider(self, config=None, *, keep_probe=False) -> None:
        # Caller holds policy_lock; D4 will add the outer lifecycle lease.
        # Never acquire provider transaction locks while holding this lock.
        if config is not None:
            proof = self.policy_proof
            require(
                self.policy_candidate == config
                and proof is not None
                and proof[:2] == (self.policy_epoch, config)
                and time.monotonic() - proof[2] <= 5,
                "container_provider_commit_unproven",
            )
        interface = config.interface if config is not None else None
        if config is None:
            self.policy_committed = None
        require(
            interface is None or interface in self.provider_interfaces, "container_provider_invalid"
        )
        probe = interface if config is not None else self.probe_interface if keep_probe else None
        await self._rewrite_policy(interface, sources=self.source_addresses, probe=probe)

    async def _rewrite_policy(self, interface, *, sources, probe) -> None:
        existing = json.loads(await self.checked("nft", "-j", "list", "table", "inet", TABLE))
        self.validate_nft_guard(existing)
        payload = self.guard_payload(interface, sources=sources, probe_interface=probe)
        await self.checked("nft", "-c", "-f", "/dev/stdin", input_text=payload)
        # Retain the union even when an apply is cancelled after kernel mutation.
        self.source_addresses = sources
        self.probe_interface = probe
        try:
            await self.checked("nft", "-f", "/dev/stdin", input_text=payload)
            self.policy_interface = interface
            await self.observe_guard()
        except BaseException:

            async def recover_block():
                self.policy_interface = None
                self.policy_committed = None
                self.probe_interface = None
                try:
                    await self.checked(
                        "nft", "-f", "/dev/stdin", input_text=self.guard_payload(None)
                    )
                    await self.observe_guard()
                except (ContainerLifecycleError, ValueError, KeyError, TypeError, AttributeError):
                    await self.deactivate()

            cleanup = asyncio.create_task(recover_block())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
            raise

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
        async with self.policy_lock:
            try:
                tables = json.loads(await self.checked("nft", "-j", "list", "tables"))["nftables"]
                exists = any(
                    item.get("table", {}).get("family") == "inet"
                    and item.get("table", {}).get("name") == TABLE
                    for item in tables
                )
                if exists:
                    self.validate_previous_policy(
                        json.loads(await self.checked("nft", "-j", "list", "table", "inet", TABLE))
                    )
            except (ValueError, KeyError, TypeError, AttributeError):
                raise ContainerLifecycleError("container_guard_resource_conflict") from None
            await self.provider_guard.arm((self.config.interface,))
            self.probe_interface = None
            payload = self.guard_payload(None)
            await self.checked("nft", "-c", "-f", "/dev/stdin", input_text=payload)
            await self.checked("nft", "-f", "/dev/stdin", input_text=payload)
            self.policy_interface = None
            self.policy_candidate = self.policy_proof = self.policy_committed = None
            self.policy_epoch += 1
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
