from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import struct
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from exitlane import core

INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
PROVIDER_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
TABLE_ID = 51820
SOURCE_RULE_PRIORITY = 0
RULE_PRIORITY = 20000
PROBE_RULE_PRIORITY = 19999
ROUTE_PROTOCOL = 196
UNREACHABLE_METRIC = 42760
PROBE_ADDRESS = "1.1.1.1"
HANDSHAKE_MAX_AGE_SECONDS = 180

Runner = Callable[..., Awaitable[tuple[int, str, str]]]
DnsProbe = Callable[[str, str, float], Awaitable[bool]]


class ProviderWireGuardError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _source_address(value: str) -> str:
    if not isinstance(value, str):
        raise ProviderWireGuardError("provider_egress_configuration_invalid")
    try:
        source = ipaddress.ip_interface(value)
    except (TypeError, ValueError) as error:
        raise ProviderWireGuardError("provider_egress_configuration_invalid") from error
    if (
        source.version != 4
        or source.network.prefixlen != 32
        or source.ip.is_unspecified
        or source.ip.is_multicast
        or source.ip.is_loopback
        or source.ip.is_link_local
    ):
        raise ProviderWireGuardError("provider_egress_configuration_invalid")
    return str(source)


def _wireguard_key(value: str) -> str:
    if not isinstance(value, str) or len(value) != 44:
        raise ProviderWireGuardError("provider_egress_configuration_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ProviderWireGuardError("provider_egress_configuration_invalid") from error
    if len(decoded) != 32:
        raise ProviderWireGuardError("provider_egress_configuration_invalid")
    return value


@dataclass(frozen=True)
class EgressConfig:
    provider_id: str
    generation: str
    interface: str
    private_key: str
    address: str
    peer_public_key: str
    endpoint_address: str
    dns_address: str
    endpoint_port: int = 51820
    mtu: int = 1380

    def validated(self) -> EgressConfig:
        if PROVIDER_PATTERN.fullmatch(self.provider_id) is None:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        if not self.generation or len(self.generation) > 64 or not self.generation.isascii():
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        if INTERFACE_PATTERN.fullmatch(self.interface) is None:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        _wireguard_key(self.private_key)
        _wireguard_key(self.peer_public_key)
        try:
            assigned = ipaddress.ip_interface(self.address)
            endpoint = ipaddress.ip_address(self.endpoint_address)
            dns = ipaddress.ip_address(self.dns_address)
        except ValueError as error:
            raise ProviderWireGuardError("provider_egress_configuration_invalid") from error
        if assigned.version != 4 or assigned.network.prefixlen != 32:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        if endpoint.version != 4 or not endpoint.is_global or dns.version != 4:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        if not 1 <= self.endpoint_port <= 65535 or not 1280 <= self.mtu <= 1420:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        return self


def _dns_query(interface: str, address: str, timeout: float) -> bool:
    transaction = os.urandom(2)
    labels = b"".join(bytes((len(label),)) + label for label in b"mullvad.net".split(b"."))
    packet = transaction + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(timeout)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
            client.sendto(packet, (address, 53))
            response = client.recv(4096)
    except OSError:
        return False
    if len(response) < 12 or response[:2] != transaction:
        return False
    flags, questions, answers = struct.unpack("!HHH", response[2:8])
    return bool(flags & 0x8000) and flags & 0x000F == 0 and questions == 1 and answers > 0


async def _default_dns_probe(interface: str, address: str, timeout: float) -> bool:
    return await asyncio.to_thread(_dns_query, interface, address, timeout)


class ProviderWireGuard:
    """Own one provider-egress interface without touching WireGuard ingress."""

    def __init__(
        self,
        runner: Runner = core.command,
        *,
        root: Path | None = None,
        dns_probe: DnsProbe = _default_dns_probe,
    ):
        self.runner = runner
        self.root = root or (core.DATA / "provider-egress")
        self.dns_probe = dns_probe

    def _path(self, interface: str) -> Path:
        if INTERFACE_PATTERN.fullmatch(interface) is None:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        root = self.root.resolve(strict=False)
        path = (root / f"{interface}.conf").resolve(strict=False)
        if path.parent != root:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        return path

    @staticmethod
    def render(config: EgressConfig) -> str:
        item = config.validated()
        return (
            "[Interface]\n"
            f"# ExitLane provider={item.provider_id} generation={item.generation}\n"
            f"PrivateKey = {item.private_key}\n"
            f"Address = {item.address}\n"
            f"MTU = {item.mtu}\n"
            "Table = off\n\n"
            "[Peer]\n"
            f"PublicKey = {item.peer_public_key}\n"
            f"Endpoint = {item.endpoint_address}:{item.endpoint_port}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "PersistentKeepalive = 25\n"
        )

    def _atomic_write(self, path: Path, content: str) -> None:
        if self.root.is_symlink():
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        if path.is_symlink():
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=self.root)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    async def _run(self, *arguments: str, timeout: float = 10) -> str:
        rc, output, _error = await self.runner(*arguments, timeout=timeout)
        if rc != 0:
            raise ProviderWireGuardError("provider_egress_apply_failed")
        return output

    async def _json(self, *arguments: str) -> list[dict]:
        output = await self._run("ip", "-j", *arguments, timeout=5)
        try:
            value = json.loads(output)
        except (TypeError, ValueError) as error:
            raise ProviderWireGuardError("provider_egress_apply_failed") from error
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise ProviderWireGuardError("provider_egress_apply_failed")
        return value

    @staticmethod
    def _owned_route(route: dict, egress_interface: str | None) -> bool:
        protocol = str(route.get("protocol"))
        destination = route.get("dst", "default")
        metric = route.get("metric")
        route_type = route.get("type", "unicast")
        return (
            protocol == str(ROUTE_PROTOCOL)
            and destination == "default"
            and (
                (route_type == "unreachable" and metric == UNREACHABLE_METRIC)
                or (
                    route_type == "unicast"
                    and metric == 10
                    and egress_interface is not None
                    and route.get("dev") == egress_interface
                )
            )
        )

    async def _check_table_ownership(self, family: int, egress_interface: str | None) -> None:
        arguments = ("ip", "-j", f"-{family}", "route", "show", "table", str(TABLE_ID))
        rc, output, error = await self.runner(*arguments, timeout=5)
        if rc != 0:
            missing_table = f"Error: ipv{family}: FIB table does not exist."
            if output.strip() in {"", "[]"} and error.strip().splitlines() in (
                [missing_table],
                [missing_table, "Dump terminated"],
            ):
                return
            raise ProviderWireGuardError("provider_egress_apply_failed")
        try:
            routes = json.loads(output)
        except (TypeError, ValueError) as error:
            raise ProviderWireGuardError("provider_egress_apply_failed") from error
        if not isinstance(routes, list) or not all(isinstance(route, dict) for route in routes):
            raise ProviderWireGuardError("provider_egress_apply_failed")
        if any(not self._owned_route(route, egress_interface) for route in routes):
            raise ProviderWireGuardError("provider_egress_resource_conflict")

    async def _ensure_rule(
        self, direction: str, interface: str, priority: int, family: int
    ) -> None:
        if direction not in {"iif", "oif"} or INTERFACE_PATTERN.fullmatch(interface) is None:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        rules = await self._json(f"-{family}", "rule", "show")
        if any(self._owned_rule(rule, (priority, direction, interface)) for rule in rules):
            return
        await self._run(
            "ip",
            f"-{family}",
            "rule",
            "add",
            "priority",
            str(priority),
            direction,
            interface,
            "table",
            str(TABLE_ID),
            "protocol",
            str(ROUTE_PROTOCOL),
        )

    @staticmethod
    def _owned_rule(rule: dict, expected: tuple[int, str, str]) -> bool:
        priority, direction, interface = expected
        allowed_keys = {
            "priority",
            "src",
            direction,
            f"{direction}_detached",
            "table",
            "protocol",
        }
        return (
            set(rule) <= allowed_keys
            and str(rule.get("priority")) == str(priority)
            and rule.get("src", "all") == "all"
            and rule.get(direction) == interface
            and rule.get(f"{direction}_detached") in {None, False}
            and str(rule.get("table")) == str(TABLE_ID)
            and str(rule.get("protocol")) == str(ROUTE_PROTOCOL)
        )

    @staticmethod
    def _owned_source_rule(rule: dict) -> bool:
        if (
            not set(rule) <= {"priority", "src", "table", "protocol"}
            or str(rule.get("priority")) != str(SOURCE_RULE_PRIORITY)
            or str(rule.get("table")) != str(TABLE_ID)
            or str(rule.get("protocol")) != str(ROUTE_PROTOCOL)
            or not isinstance(rule.get("src"), str)
        ):
            return False
        try:
            source = _source_address(rule["src"])
        except ProviderWireGuardError:
            return False
        return rule["src"] in {source, source.removesuffix("/32")}

    @staticmethod
    def _local_rule(rule: dict) -> bool:
        return (
            set(rule) <= {"priority", "src", "table", "protocol"}
            and str(rule.get("priority")) == "0"
            and rule.get("src") == "all"
            and str(rule.get("table")) in {"local", "255"}
            and str(rule.get("protocol", "kernel")) in {"kernel", "2"}
        )

    def _check_source_rule_order(self, rules: list[dict], *, required: bool) -> None:
        zero = [rule for rule in rules if str(rule.get("priority")) == "0"]
        if not zero and not required:
            return
        if (
            not zero
            or not self._local_rule(zero[0])
            or any(not self._owned_source_rule(rule) for rule in zero[1:])
        ):
            raise ProviderWireGuardError("provider_egress_resource_conflict")

    async def _check_source_assignment(self, source: str, interface: str | None) -> None:
        address = source.removesuffix("/32")
        for link in await self._json("-4", "address", "show"):
            if link.get("ifname") == interface:
                continue
            entries = link.get("addr_info", [])
            if not isinstance(entries, list) or not all(isinstance(item, dict) for item in entries):
                raise ProviderWireGuardError("provider_egress_apply_failed")
            if any(item.get("local") == address for item in entries):
                raise ProviderWireGuardError("provider_egress_resource_conflict")

    async def _ensure_source_rule(self, source: str) -> None:
        rules = await self._json("-4", "rule", "show")
        self._check_source_rule_order(rules, required=True)
        if not any(
            self._owned_source_rule(rule) and _source_address(rule["src"]) == source
            for rule in rules
        ):
            await self._run(
                "ip",
                "-4",
                "rule",
                "add",
                "priority",
                str(SOURCE_RULE_PRIORITY),
                "from",
                source,
                "table",
                str(TABLE_ID),
                "protocol",
                str(ROUTE_PROTOCOL),
            )
        # Equal-priority insertion must preserve the built-in local lookup first.
        # Never rewrite/flush priority zero to repair a conflicting host policy.
        rules = await self._json("-4", "rule", "show")
        self._check_source_rule_order(rules, required=True)
        if not any(
            self._owned_source_rule(rule) and _source_address(rule["src"]) == source
            for rule in rules
        ):
            raise ProviderWireGuardError("provider_egress_source_guard_failed")

    async def _preflight(
        self,
        ingress_interfaces: tuple[str, ...],
        egress_interface: str | None,
        source_address: str | None = None,
    ) -> None:
        if source_address is not None:
            await self._check_source_assignment(source_address, egress_interface)
        expected = {(RULE_PRIORITY, "iif", item) for item in ingress_interfaces}
        if egress_interface is not None:
            expected.add((PROBE_RULE_PRIORITY, "oif", egress_interface))
        for family in (4, 6):
            await self._check_table_ownership(family, egress_interface)
            rules = await self._json(f"-{family}", "rule", "show")
            if family == 4:
                self._check_source_rule_order(rules, required=source_address is not None)
            for rule in rules:
                try:
                    priority = int(rule.get("priority"))
                except (TypeError, ValueError):
                    continue
                if priority not in {RULE_PRIORITY, PROBE_RULE_PRIORITY}:
                    continue
                owned = any(self._owned_rule(rule, item) for item in expected) and not (
                    family == 6 and priority == PROBE_RULE_PRIORITY
                )
                if not owned:
                    raise ProviderWireGuardError("provider_egress_resource_conflict")

    async def _apply_guard(
        self,
        ingress_interfaces: tuple[str, ...],
        egress_interface: str | None,
        source_address: str | None = None,
    ) -> None:
        for family in (4, 6):
            await self._run(
                "ip",
                f"-{family}",
                "route",
                "replace",
                "unreachable",
                "default",
                "table",
                str(TABLE_ID),
                "metric",
                str(UNREACHABLE_METRIC),
                "proto",
                str(ROUTE_PROTOCOL),
            )
        if source_address is not None:
            await self._ensure_source_rule(source_address)
        for ingress_interface in ingress_interfaces:
            for family in (4, 6):
                await self._ensure_rule("iif", ingress_interface, RULE_PRIORITY, family)
        if egress_interface is not None:
            await self._ensure_rule("oif", egress_interface, PROBE_RULE_PRIORITY, 4)

    async def _delete_rule(
        self, direction: str, interface: str, priority: int, family: int
    ) -> None:
        for _attempt in range(8):
            rc, _, _ = await self.runner(
                "ip",
                f"-{family}",
                "rule",
                "del",
                "priority",
                str(priority),
                direction,
                interface,
                "table",
                str(TABLE_ID),
                "protocol",
                str(ROUTE_PROTOCOL),
                timeout=5,
            )
            if rc != 0:
                return
        raise ProviderWireGuardError("provider_egress_apply_failed")

    async def arm_source(self, egress_interface: str, source_address: str) -> None:
        """Protect delayed host replies without altering another provider's ingress."""
        source = _source_address(source_address)
        if INTERFACE_PATTERN.fullmatch(egress_interface) is None:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        await self._check_source_assignment(source, egress_interface)
        await self._check_table_ownership(4, egress_interface)
        self._check_source_rule_order(await self._json("-4", "rule", "show"), required=True)
        await self._run(
            "ip",
            "-4",
            "route",
            "replace",
            "unreachable",
            "default",
            "table",
            str(TABLE_ID),
            "metric",
            str(UNREACHABLE_METRIC),
            "proto",
            str(ROUTE_PROTOCOL),
        )
        await self._ensure_source_rule(source)

    async def arm(
        self,
        ingress_interfaces: Iterable[str],
        egress_interface: str | None = None,
        *,
        source_address: str | None = None,
    ) -> None:
        source = _source_address(source_address) if source_address is not None else None
        ingress = tuple(dict.fromkeys(ingress_interfaces))
        if any(INTERFACE_PATTERN.fullmatch(item) is None for item in ingress):
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        if egress_interface is not None and INTERFACE_PATTERN.fullmatch(egress_interface) is None:
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        await self._preflight(ingress, egress_interface, source)
        await self._apply_guard(ingress, egress_interface, source)

    async def disarm(
        self, ingress_interfaces: Iterable[str], egress_interface: str | None = None
    ) -> None:
        for ingress in tuple(dict.fromkeys(ingress_interfaces)):
            for family in (4, 6):
                await self._delete_rule("iif", ingress, RULE_PRIORITY, family)
        if egress_interface is not None:
            await self._delete_rule("oif", egress_interface, PROBE_RULE_PRIORITY, 4)
        # Late kernel replies can outlive disconnect/sign-out or a restored DB.
        # Retain exact source guards and unreachable defaults until reboot.
        for family in (4, 6):
            await self._run(
                "ip",
                f"-{family}",
                "route",
                "replace",
                "unreachable",
                "default",
                "table",
                str(TABLE_ID),
                "metric",
                str(UNREACHABLE_METRIC),
                "proto",
                str(ROUTE_PROTOCOL),
            )
        if egress_interface is not None:
            await self.runner(
                "ip",
                "-4",
                "route",
                "del",
                "default",
                "dev",
                egress_interface,
                "table",
                str(TABLE_ID),
                "metric",
                "10",
                "proto",
                str(ROUTE_PROTOCOL),
                timeout=5,
            )

    async def interface_exists(self, interface: str) -> bool:
        if INTERFACE_PATTERN.fullmatch(interface) is None:
            return False
        rc, _, _ = await self.runner("ip", "link", "show", "dev", interface, timeout=5)
        return rc == 0

    async def stop_interface(self, interface: str) -> None:
        path = self._path(interface)
        if await self.interface_exists(interface):
            rc, _, _ = await self.runner("wg-quick", "down", str(path), timeout=15)
            if rc != 0 and await self.interface_exists(interface):
                raise ProviderWireGuardError("provider_egress_teardown_failed")
        await self.runner(
            "ip",
            "-4",
            "route",
            "del",
            "default",
            "dev",
            interface,
            "table",
            str(TABLE_ID),
            "metric",
            "10",
            "proto",
            str(ROUTE_PROTOCOL),
            timeout=5,
        )

    def remove_config(self, interface: str) -> None:
        self._path(interface).unlink(missing_ok=True)

    async def _rollback_start(self, interface: str, path: Path, previous: str | None) -> None:
        try:
            await self.stop_interface(interface)
        finally:
            if previous is None:
                path.unlink(missing_ok=True)
            else:
                self._atomic_write(path, previous)

    async def start(self, config: EgressConfig, ingress_interfaces: Iterable[str]) -> None:
        item = config.validated()
        path = self._path(item.interface)
        ingress = tuple(dict.fromkeys(ingress_interfaces))
        if item.interface in ingress or any(
            INTERFACE_PATTERN.fullmatch(value) is None for value in ingress
        ):
            raise ProviderWireGuardError("provider_egress_configuration_invalid")
        source = _source_address(item.address)
        await self._preflight(ingress, item.interface, source)
        try:
            previous = path.read_text(encoding="utf-8") if path.exists() else None
        except OSError as error:
            raise ProviderWireGuardError("provider_egress_apply_failed") from error
        try:
            await self._apply_guard(ingress, item.interface, source)
            await self.stop_interface(item.interface)
            self._atomic_write(path, self.render(item))
            await self._run("wg-quick", "up", str(path), timeout=20)
            await self._run(
                "ip",
                "-4",
                "route",
                "replace",
                "default",
                "dev",
                item.interface,
                "table",
                str(TABLE_ID),
                "metric",
                "10",
                "proto",
                str(ROUTE_PROTOCOL),
            )
            await self.verify_route(item.interface, ingress)
        except asyncio.CancelledError:
            cleanup = asyncio.create_task(self._rollback_start(item.interface, path, previous))
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
            raise
        except (OSError, ProviderWireGuardError) as error:
            await self._rollback_start(item.interface, path, previous)
            if isinstance(error, OSError):
                raise ProviderWireGuardError("provider_egress_apply_failed") from error
            raise

    async def verify_route(self, interface: str, ingress_interfaces: Iterable[str]) -> None:
        for ingress in tuple(dict.fromkeys(ingress_interfaces)):
            source = await self._ingress_source(ingress)
            output = await self._run(
                "ip",
                "-4",
                "route",
                "get",
                PROBE_ADDRESS,
                "from",
                source,
                "iif",
                ingress,
                timeout=5,
            )
            words = output.split()
            if (
                "dev" not in words
                or words[words.index("dev") + 1] != interface
                or "table" not in words
                or words[words.index("table") + 1] != str(TABLE_ID)
            ):
                raise ProviderWireGuardError("provider_egress_route_unavailable")

    async def _ingress_source(self, interface: str) -> str:
        addresses = await self._json("-4", "address", "show", "dev", interface)
        for device in addresses:
            entries = device.get("addr_info")
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("family") != "inet":
                    continue
                local = entry.get("local")
                prefixlen = entry.get("prefixlen")
                try:
                    own = ipaddress.ip_address(local)
                    network = ipaddress.ip_network(f"{local}/{int(prefixlen)}", strict=False)
                except (TypeError, ValueError):
                    continue
                for candidate in network.hosts():
                    if candidate != own:
                        return str(candidate)
        raise ProviderWireGuardError("provider_egress_route_unavailable")

    async def probe(self, config: EgressConfig, *, timeout: float = 8) -> dict:
        item = config.validated()
        rc, _, _ = await self.runner(
            "ping",
            "-n",
            "-I",
            item.interface,
            "-c",
            "1",
            "-W",
            str(max(1, int(timeout))),
            PROBE_ADDRESS,
            timeout=timeout + 1,
        )
        dns_ready = await self.dns_probe(item.interface, item.dns_address, timeout)
        handshake = await self._handshake(item)
        peer_matches = await self._peer_matches(item)
        return {
            "ready": rc == 0 and dns_ready and handshake > 0 and peer_matches,
            "handshake": handshake,
            "dataplane": rc == 0,
            "dns": dns_ready,
            "peer_matches": peer_matches,
        }

    async def _handshake(self, config: EgressConfig) -> int:
        peer_output = await self._run(
            "wg", "show", config.interface, "latest-handshakes", timeout=5
        )
        handshakes: dict[str, int] = {}
        for line in peer_output.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                handshakes[parts[0]] = int(parts[1])
        return handshakes.get(config.peer_public_key, 0)

    async def _peer_matches(self, config: EgressConfig) -> bool:
        output = await self._run("wg", "show", config.interface, "endpoints", timeout=5)
        expected = f"{config.endpoint_address}:{config.endpoint_port}"
        return any(
            line.split() == [config.peer_public_key, expected] for line in output.splitlines()
        )

    async def observe(self, config: EgressConfig) -> dict:
        """Observe the exact configured peer without generating dataplane traffic."""
        item = config.validated()
        if not await self.interface_exists(item.interface):
            return {"connected": False, "ready": False, "handshake": 0}
        try:
            handshake = await self._handshake(item)
            peer_matches = await self._peer_matches(item)
        except ProviderWireGuardError:
            return {"connected": False, "ready": False, "handshake": 0}
        now = int(time.time())
        fresh = (
            peer_matches
            and 0 < handshake <= now + 5
            and now - handshake <= HANDSHAKE_MAX_AGE_SECONDS
        )
        return {"connected": fresh, "ready": fresh, "handshake": handshake}

    async def status(self, config: EgressConfig) -> dict:
        return await self.observe(config)
