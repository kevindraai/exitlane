from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Protocol

from exitlane import core

SETTING_KEY = "network.management_prefixes"
IP_BINARY = "/usr/sbin/ip"
RULE_PROTOCOL = 196
PRIORITY_BASE = 10000
PRIORITY_MIN = 1
ROUTE_METRIC = 42760
PROVIDER_TABLES_SETTING = "network.management_provider_tables"
MAX_PREFIXES = 64
STANDARD_ROUTE_TABLES = frozenset({"local", "main", "default", "255", "254", "253"})
BROAD_PRIVATE_NETWORKS = {
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
}
WIREGUARD_CONFIGURED_SETTING = "wireguard_configured"
WIREGUARD_SUBNET_SETTING = "wireguard_subnet"
WIREGUARD_INTERFACE_SETTING = "wireguard_interface"
WIREGUARD_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,15}$")
FAIL_CLOSED_ROUTE_TYPES = frozenset({"blackhole", "prohibit", "unreachable"})

logger = logging.getLogger("exitlane.security")


class Runner(Protocol):
    async def __call__(
        self,
        *arguments: str,
        timeout: int = 10,
        input_text: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, str, str]: ...


class ProviderTableStore(Protocol):
    def load(self) -> dict[int, tuple[str, ...]]: ...

    def save(self, tables: dict[int, tuple[str, ...]]) -> None: ...


class MemoryProviderTableStore:
    def __init__(self):
        self.tables: dict[int, tuple[str, ...]] = {4: (), 6: ()}

    def load(self) -> dict[int, tuple[str, ...]]:
        return dict(self.tables)

    def save(self, tables: dict[int, tuple[str, ...]]) -> None:
        self.tables = dict(tables)


class CoreProviderTableStore:
    @staticmethod
    def _normalized(value: object) -> dict[int, tuple[str, ...]]:
        if not isinstance(value, dict):
            return {4: (), 6: ()}
        result: dict[int, tuple[str, ...]] = {}
        for family in (4, 6):
            raw = value.get(str(family), value.get(family, []))
            entries = raw if isinstance(raw, list) else []
            result[family] = tuple(
                dict.fromkeys(
                    table
                    for entry in entries
                    if (table := ManagementRoutingBackend._numeric_provider_table(entry))
                )
            )
        return result

    def load(self) -> dict[int, tuple[str, ...]]:
        return self._normalized(core.setting(PROVIDER_TABLES_SETTING, {}))

    def save(self, tables: dict[int, tuple[str, ...]]) -> None:
        normalized = {str(family): list(dict.fromkeys(tables.get(family, ()))) for family in (4, 6)}
        current = {str(family): list(self.load().get(family, ())) for family in (4, 6)}
        if normalized != current:
            core.set_setting(PROVIDER_TABLES_SETTING, normalized)


class ManagementRoutingError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        field: str | None = None,
        line: int | None = None,
        value: str | None = None,
    ):
        super().__init__(code)
        self.code = code
        self.field = field
        self.line = line
        self.value = value


Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class DirectManagementPath:
    network: Network
    device: str
    local_addresses: tuple[Address, ...]


@dataclass(frozen=True)
class ProtectedDestination:
    """A configured local destination that must never follow provider egress."""

    network: Network
    expected_device: str
    source: str


@dataclass(frozen=True)
class ReconcileResult:
    prefixes: tuple[str, ...]
    added: int
    removed: int

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": True,
            "prefixes": list(self.prefixes),
            "added": self.added,
            "removed": self.removed,
        }


def _network_sort_key(network: Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def parse_management_prefixes(
    values: str | list[str] | tuple[str, ...],
    *,
    confirm_broad: bool = False,
) -> tuple[Network, ...]:
    raw_entries = (
        values.replace(",", "\n").splitlines()
        if isinstance(values, str)
        else [str(part) for part in values]
    )
    entries = [(line, value.strip()) for line, value in enumerate(raw_entries, start=1)]
    entries = [(line, value) for line, value in entries if value]
    if len(entries) > MAX_PREFIXES:
        raise ManagementRoutingError("too_many_management_prefixes", field="management_prefixes")
    networks: list[Network] = []
    for line, value in entries:
        if value == "*" or any(character in value for character in " \\;&|$`()"):
            raise ManagementRoutingError(
                "invalid_management_prefix",
                field="management_prefixes",
                line=line,
                value=value[:128],
            )
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise ManagementRoutingError(
                "invalid_management_prefix",
                field="management_prefixes",
                line=line,
                value=value[:128],
            ) from error
        if network.prefixlen == 0:
            raise ManagementRoutingError(
                "management_prefix_too_broad",
                field="management_prefixes",
                line=line,
                value=value[:128],
            )
        if network.is_multicast or network.is_unspecified:
            raise ManagementRoutingError(
                "invalid_management_prefix",
                field="management_prefixes",
                line=line,
                value=value[:128],
            )
        networks.append(network)
    normalized = tuple(dict.fromkeys(sorted(networks, key=_network_sort_key)))
    if any(network in BROAD_PRIVATE_NETWORKS for network in normalized) and not confirm_broad:
        raise ManagementRoutingError(
            "broad_management_prefix_confirmation_required",
            field="management_prefixes",
        )
    return normalized


def configured_prefixes() -> tuple[Network, ...]:
    value = core.setting(SETTING_KEY, [])
    if not isinstance(value, (str, list, tuple)):
        raise ManagementRoutingError("invalid_management_prefix", field="management_prefixes")
    # Persisted values have already passed broad-range confirmation at write time.
    return parse_management_prefixes(value, confirm_broad=True)


def configured_protected_destinations() -> tuple[ProtectedDestination, ...]:
    """Return concrete non-provider destinations from canonical application state."""
    if not core.setting(WIREGUARD_CONFIGURED_SETTING, False):
        return ()
    subnet = core.setting(WIREGUARD_SUBNET_SETTING)
    interface = core.setting(WIREGUARD_INTERFACE_SETTING)
    if not isinstance(subnet, str) or not isinstance(interface, str):
        raise ManagementRoutingError("protected_destination_configuration_invalid")
    try:
        network = ipaddress.ip_network(subnet, strict=True)
    except ValueError as error:
        raise ManagementRoutingError("protected_destination_configuration_invalid") from error
    if (
        network.version != 4
        or network.prefixlen == 0
        or not WIREGUARD_INTERFACE_PATTERN.fullmatch(interface)
    ):
        raise ManagementRoutingError("protected_destination_configuration_invalid")
    return (
        ProtectedDestination(
            network=network,
            expected_device=interface,
            source="wireguard_ingress",
        ),
    )


def destination_is_protected(prefixes: tuple[Network, ...], destination: str) -> bool:
    try:
        address = ipaddress.ip_address(destination)
    except ValueError:
        return False
    return any(address.version == prefix.version and address in prefix for prefix in prefixes)


class ManagementRoutingBackend:
    def __init__(
        self,
        runner: Runner = core.command,
        provider_table_store: ProviderTableStore | None = None,
    ):
        self.runner = runner
        self.provider_table_store = provider_table_store or MemoryProviderTableStore()

    async def _json(self, *arguments: str, error_code: str) -> list[dict]:
        rc, output, _error = await self.runner(IP_BINARY, *arguments, timeout=10)
        if rc != 0:
            raise ManagementRoutingError(error_code)
        try:
            value = json.loads(output or "[]")
        except (TypeError, json.JSONDecodeError) as error:
            raise ManagementRoutingError(error_code) from error
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ManagementRoutingError(error_code)
        return value

    async def _direct_management_paths(self) -> tuple[DirectManagementPath, ...]:
        paths: list[DirectManagementPath] = []
        for family, address_family in ((4, "inet"), (6, "inet6")):
            routes = await self._json(
                "-j",
                f"-{family}",
                "route",
                "show",
                "table",
                "main",
                "default",
                error_code="management_route_discovery_failed",
            )
            devices = sorted(
                {
                    str(route["dev"])
                    for route in routes
                    if route.get("dst") == "default" and route.get("dev")
                }
            )
            for device in devices:
                device_networks: dict[Network, list[Address]] = {}
                addresses = await self._json(
                    "-j",
                    f"-{family}",
                    "addr",
                    "show",
                    "dev",
                    device,
                    "scope",
                    "global",
                    error_code="management_route_discovery_failed",
                )
                for interface in addresses:
                    for address in interface.get("addr_info", []):
                        if not isinstance(address, dict) or address.get("family") != address_family:
                            continue
                        local = address.get("local")
                        prefixlen = address.get("prefixlen")
                        if not isinstance(local, str) or not isinstance(prefixlen, int):
                            continue
                        try:
                            interface_address = ipaddress.ip_interface(f"{local}/{prefixlen}")
                        except ValueError:
                            continue
                        network = interface_address.network
                        if not network.is_loopback and not network.is_link_local:
                            device_networks.setdefault(network, []).append(interface_address.ip)
                paths.extend(
                    DirectManagementPath(
                        network,
                        device,
                        tuple(sorted(local_addresses, key=int)),
                    )
                    for network, local_addresses in device_networks.items()
                )
        return tuple(
            sorted(
                dict.fromkeys(paths),
                key=lambda path: (*_network_sort_key(path.network), path.device),
            )
        )

    async def direct_management_prefixes(self) -> tuple[Network, ...]:
        return tuple(dict.fromkeys(path.network for path in await self._direct_management_paths()))

    async def _rules(self, family: int) -> list[dict]:
        return await self._json(
            "-j",
            f"-{family}",
            "rule",
            "show",
            error_code="management_rule_inspection_failed",
        )

    @staticmethod
    def _rule_network(rule: dict) -> Network | None:
        if not rule.get("dst"):
            return None
        try:
            destination = str(rule["dst"])
            if "/" not in destination and rule.get("dstlen") is not None:
                destination = f"{destination}/{int(rule['dstlen'])}"
            return ipaddress.ip_network(destination, strict=False)
        except (TypeError, ValueError):
            return None

    def _owned_rules(self, family: int, rules: list[dict]) -> list[tuple[int, Network]]:
        owned: list[tuple[int, Network]] = []
        for rule in rules:
            try:
                priority = int(rule.get("priority"))
                protocol = int(rule.get("protocol"))
            except (TypeError, ValueError):
                continue
            table = rule.get("table")
            # Protocol 196 plus a main-table destination rule is ExitLane's
            # ownership signature. Previous implementations could place such a
            # rule at priority 0 or outside the current allocation range, so
            # ownership discovery must not hide those stale rules.
            if (
                priority < 0
                or protocol != RULE_PROTOCOL
                or table
                not in {
                    "main",
                    254,
                    "254",
                }
            ):
                continue
            network = self._rule_network(rule)
            if network is not None and network.version == family:
                owned.append((priority, network))
        return owned

    @staticmethod
    def _numeric_provider_table(value: object) -> str | None:
        normalized = str(value)
        if not normalized.isdigit():
            return None
        table = int(normalized)
        if table <= 0 or table > 0xFFFFFFFF or normalized in STANDARD_ROUTE_TABLES:
            return None
        return normalized

    def _provider_policy_tables_before(
        self, rules: list[dict], management_priority: int
    ) -> set[str]:
        tables: set[str] = set()
        for rule in rules:
            try:
                priority = int(rule.get("priority"))
                protocol = int(rule.get("protocol", -1))
            except (TypeError, ValueError):
                continue
            if priority < 0 or priority > management_priority or protocol == RULE_PROTOCOL:
                continue
            table = self._numeric_provider_table(rule.get("table"))
            if table is not None:
                tables.add(table)
        return tables

    def _provider_policy_tables(self, rules: list[dict]) -> set[str]:
        tables: set[str] = set()
        for rule in rules:
            try:
                protocol = int(rule.get("protocol", -1))
            except (TypeError, ValueError):
                continue
            table = rule.get("table")
            if protocol != RULE_PROTOCOL and table is not None:
                normalized = str(table)
                if normalized not in STANDARD_ROUTE_TABLES:
                    tables.add(normalized)
        return tables

    async def _mutate(self, action: str, priority: int, network: Network) -> None:
        rc, _output, _error = await self.runner(
            IP_BINARY,
            f"-{network.version}",
            "rule",
            action,
            "priority",
            str(priority),
            "to",
            str(network),
            "lookup",
            "main",
            "protocol",
            str(RULE_PROTOCOL),
            timeout=10,
        )
        if rc != 0:
            raise ManagementRoutingError("management_rule_apply_failed")

    async def _main_routes(self, family: int) -> list[dict]:
        return await self._json(
            "-j",
            f"-{family}",
            "route",
            "show",
            "table",
            "main",
            error_code="management_route_discovery_failed",
        )

    async def _table_routes(self, family: int, table: str) -> list[dict]:
        return await self._json(
            "-j",
            f"-{family}",
            "route",
            "show",
            "table",
            table,
            error_code="management_provider_route_inspection_failed",
        )

    async def _all_routes(self, family: int) -> list[dict]:
        return await self._json(
            "-j",
            f"-{family}",
            "route",
            "show",
            "table",
            "all",
            error_code="management_provider_route_inspection_failed",
        )

    @staticmethod
    def _route_network(route: dict) -> Network | None:
        destination = route.get("dst")
        if not destination or destination == "default":
            return None
        try:
            return ipaddress.ip_network(str(destination), strict=False)
        except ValueError:
            return None

    @staticmethod
    def _route_protocol(route: dict) -> int | None:
        try:
            return int(route.get("protocol"))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _route_type(route: dict) -> str:
        return str(route.get("type", "unicast"))

    def _owned_routes(self, family: int, routes: list[dict]) -> dict[Network, tuple]:
        owned = {}
        for route in routes:
            network = self._route_network(route)
            if (
                network is None
                or network.version != family
                or self._route_protocol(route) != RULE_PROTOCOL
                or route.get("metric") != ROUTE_METRIC
            ):
                continue
            owned[network] = (route.get("gateway"), route.get("dev"))
        return owned

    @staticmethod
    def _route_table(route: dict, *, default: str = "main") -> str:
        table = str(route.get("table", default))
        return "main" if table == "254" else table

    def _owned_provider_routes(
        self, family: int, routes: list[dict]
    ) -> dict[tuple[str, Network], tuple[str | None, str | None]]:
        owned = {}
        for route in routes:
            network = self._route_network(route)
            table = self._numeric_provider_table(route.get("table"))
            if (
                network is None
                or network.version != family
                or table is None
                or self._route_protocol(route) != RULE_PROTOCOL
                or route.get("metric") != ROUTE_METRIC
            ):
                continue
            owned[(table, network)] = (route.get("gateway"), route.get("dev"))
        return owned

    async def _mutate_route(
        self,
        action: str,
        network: Network,
        *,
        gateway: str | None = None,
        device: str | None = None,
        table: str = "main",
    ) -> None:
        arguments = [
            IP_BINARY,
            f"-{network.version}",
            "route",
            action,
        ]
        if action != "del" and gateway is None and device is None:
            arguments.append("unreachable")
        arguments.append(str(network))
        if gateway:
            arguments.extend(("via", gateway))
        if device:
            arguments.extend(("dev", device))
        arguments.extend(
            (
                "table",
                table,
                "protocol",
                str(RULE_PROTOCOL),
                "metric",
                str(ROUTE_METRIC),
            )
        )
        rc, _output, _error = await self.runner(*arguments, timeout=10)
        if rc != 0:
            raise ManagementRoutingError(
                "management_route_apply_failed"
                if table == "main"
                else "management_provider_route_apply_failed"
            )

    async def _provider_devices(
        self,
        *,
        rules: dict[int, list[dict]],
    ) -> set[str]:
        devices: set[str] = set()
        for family in (4, 6):
            # Inspect every non-standard policy table, including a provider
            # whose rule is later than ExitLane's destination rules. Such a
            # table does not need a mirrored route, but its default interface
            # is still a known provider egress path and must never be accepted
            # as the canonical path to a local protected destination.
            tables = self._provider_policy_tables(rules[family])
            if not tables:
                continue
            for route in await self._all_routes(family):
                if (
                    self._route_table(route, default="") in tables
                    and route.get("dst") == "default"
                    and route.get("dev")
                ):
                    devices.add(str(route["dev"]))
        return devices

    def _protected_destination_paths(
        self,
        destinations: tuple[ProtectedDestination, ...],
        *,
        main_routes: dict[int, list[dict]],
        provider_devices: set[str],
    ) -> tuple[
        dict[Network, tuple[str | None, str | None]],
        tuple[ProtectedDestination, ...],
    ]:
        paths: dict[Network, tuple[str | None, str | None]] = {}
        unavailable: list[ProtectedDestination] = []
        for destination in destinations:
            candidates = []
            for route in main_routes[destination.network.version]:
                network = self._route_network(route)
                device = route.get("dev")
                if (
                    network is None
                    or not destination.network.subnet_of(network)
                    or self._route_protocol(route) == RULE_PROTOCOL
                    or self._route_type(route) in FAIL_CLOSED_ROUTE_TYPES
                    or not device
                ):
                    continue
                candidates.append((network, route))
            selected = (
                max(candidates, key=lambda item: item[0].prefixlen)[1] if candidates else None
            )
            device = str(selected.get("dev")) if selected is not None else None
            gateway_value = (
                selected.get("gateway", selected.get("via")) if selected is not None else None
            )
            gateway = str(gateway_value) if gateway_value is not None else None
            valid_gateway = True
            if gateway is not None:
                try:
                    valid_gateway = (
                        ipaddress.ip_address(gateway).version == destination.network.version
                    )
                except ValueError:
                    valid_gateway = False
            if (
                selected is None
                or device != destination.expected_device
                or device in provider_devices
                or not valid_gateway
            ):
                logger.warning(
                    "Protected destination route unavailable: source=%s prefix=%s",
                    destination.source,
                    destination.network,
                )
                unavailable.append(destination)
                continue
            paths[destination.network] = (gateway, device)
        return paths, tuple(unavailable)

    async def _reconcile_provider_routes(
        self,
        *,
        protected_paths: dict[Network, tuple[str | None, str | None]],
        rules: dict[int, list[dict]],
        management_priority: int,
        transition: bool,
    ) -> tuple[int, int, dict[int, tuple[str, ...]]]:
        try:
            cached = self.provider_table_store.load()
        except Exception as error:
            raise ManagementRoutingError("management_provider_table_state_failed") from error
        all_routes = {family: await self._all_routes(family) for family in (4, 6)}
        target_tables: dict[int, tuple[str, ...]] = {}
        discovered: dict[int, tuple[str, ...]] = {}
        for family in (4, 6):
            candidates = self._provider_policy_tables_before(rules[family], management_priority)
            current = tuple(
                sorted(
                    table
                    for table in candidates
                    if any(
                        self._route_table(route, default="") == table
                        and route.get("dst") == "default"
                        for route in all_routes[family]
                    )
                )
            )
            discovered[family] = current
            target_tables[family] = current or (cached.get(family, ()) if transition else ())
        if any(discovered.values()):
            updated = {family: discovered[family] or cached.get(family, ()) for family in (4, 6)}
            try:
                self.provider_table_store.save(updated)
            except Exception as error:
                raise ManagementRoutingError("management_provider_table_state_failed") from error

        added = 0
        removed = 0
        desired_owned: set[tuple[str, Network]] = set()
        owned = {
            family: self._owned_provider_routes(family, all_routes[family]) for family in (4, 6)
        }
        desired_entries = sorted(
            protected_paths.items(),
            key=lambda item: (item[1][0] is not None, _network_sort_key(item[0])),
        )
        for family in (4, 6):
            for table in target_tables[family]:
                table_routes = [
                    route
                    for route in all_routes[family]
                    if self._route_table(route, default="") == table
                ]
                for network, path in desired_entries:
                    if network.version != family:
                        continue
                    exact = [
                        route for route in table_routes if self._route_network(route) == network
                    ]
                    foreign = [
                        route
                        for route in exact
                        if not (
                            self._route_protocol(route) == RULE_PROTOCOL
                            and route.get("metric") == ROUTE_METRIC
                        )
                    ]
                    if foreign:
                        if not all(
                            self._path_matches(route, gateway=path[0], device=path[1])
                            for route in foreign
                        ):
                            raise ManagementRoutingError("management_provider_route_conflict")
                        continue
                    key = (table, network)
                    desired_owned.add(key)
                    if owned[family].get(key) == path:
                        continue
                    await self._mutate_route(
                        "replace" if key in owned[family] else "add",
                        network,
                        gateway=path[0],
                        device=path[1],
                        table=table,
                    )
                    added += 1

        for family in (4, 6):
            for (table, network), _path in sorted(
                owned[family].items(),
                key=lambda item: (int(item[0][0]), _network_sort_key(item[0][1])),
            ):
                if (table, network) in desired_owned:
                    continue
                await self._mutate_route("del", network, table=table)
                removed += 1
        return added, removed, target_tables

    async def _reconcile_routes(
        self,
        configured_networks: tuple[Network, ...],
        fail_closed_networks: tuple[Network, ...] = (),
    ) -> tuple[
        int,
        int,
        dict[Network, tuple[str | None, str | None]],
        dict[int, list[dict]],
    ]:
        desired: dict[Network, tuple[str | None, str | None]] = {}
        existing: dict[Network, tuple[str | None, str | None]] = {}
        expected: dict[Network, tuple[str | None, str | None]] = {}
        main_routes: dict[int, list[dict]] = {}
        for family in (4, 6):
            routes = await self._main_routes(family)
            main_routes[family] = routes
            owned = self._owned_routes(family, routes)
            existing.update(owned)
            non_owned_specific = [
                (network, route)
                for route in routes
                if self._route_protocol(route) != RULE_PROTOCOL
                and (network := self._route_network(route)) is not None
            ]
            defaults = [route for route in routes if route.get("dst") == "default"]
            for network in configured_networks:
                if network.version != family:
                    continue
                covering = [
                    (candidate, route)
                    for candidate, route in non_owned_specific
                    if network.subnet_of(candidate)
                ]
                if covering:
                    _candidate, route = max(covering, key=lambda item: item[0].prefixlen)
                    expected[network] = (route.get("gateway"), route.get("dev"))
                    continue
                default = next(
                    (route for route in defaults if route.get("gateway") or route.get("dev")),
                    None,
                )
                if default is None:
                    raise ManagementRoutingError("management_route_discovery_failed")
                desired[network] = (default.get("gateway"), default.get("dev"))
                expected[network] = desired[network]

        # A configured local destination whose canonical interface is not yet
        # available must fail closed in main as well as provider tables. This
        # prevents its destination rule from falling through to the physical
        # default during interface recreation or startup races.
        for network in fail_closed_networks:
            desired[network] = (None, None)

        added = 0
        removed = 0
        for network, path in sorted(desired.items(), key=lambda item: _network_sort_key(item[0])):
            if existing.get(network) == path:
                continue
            await self._mutate_route(
                "replace" if network in existing else "add",
                network,
                gateway=path[0],
                device=path[1],
            )
            added += 1
        for network in sorted(set(existing) - set(desired), key=_network_sort_key):
            await self._mutate_route("del", network)
            removed += 1
        main_routes = {family: await self._main_routes(family) for family in (4, 6)}
        return added, removed, expected, main_routes

    async def _route_get(self, destination: Address, error_code: str) -> dict:
        routes = await self._json(
            "-j",
            f"-{destination.version}",
            "route",
            "get",
            str(destination),
            error_code=error_code,
        )
        if not routes:
            raise ManagementRoutingError(error_code)
        return routes[0]

    async def _device_local_addresses(
        self,
        device: str,
        family: int,
        *,
        error_code: str,
    ) -> tuple[Address, ...]:
        address_family = "inet" if family == 4 else "inet6"
        interfaces = await self._json(
            "-j",
            f"-{family}",
            "addr",
            "show",
            "dev",
            device,
            "scope",
            "global",
            error_code=error_code,
        )
        addresses: list[Address] = []
        for interface in interfaces:
            for entry in interface.get("addr_info", []):
                if not isinstance(entry, dict) or entry.get("family") != address_family:
                    continue
                local = entry.get("local")
                if not isinstance(local, str):
                    continue
                try:
                    address = ipaddress.ip_address(local)
                except ValueError:
                    continue
                if address.version == family:
                    addresses.append(address)
        return tuple(dict.fromkeys(addresses))

    @staticmethod
    def _representative_address(
        network: Network, *, excluded: tuple[Address, ...] = ()
    ) -> Address | None:
        excluded_values = {int(address) for address in excluded}
        size = int(network.num_addresses)
        offsets = list(range(min(size, 4)))
        if size > 4:
            offsets.append(size - 2 if network.version == 4 else size - 1)
        for offset in offsets:
            candidate = network.network_address + offset
            if int(candidate) in excluded_values:
                continue
            if (
                network.version == 4
                and network.prefixlen < 31
                and (candidate == network.network_address or candidate == network.broadcast_address)
            ):
                continue
            return candidate
        return None

    @staticmethod
    def _path_matches(route: dict, *, gateway: str | None, device: str | None) -> bool:
        route_type = str(route.get("type", "unicast"))
        if gateway is None and device is None:
            return route_type in FAIL_CLOSED_ROUTE_TYPES
        if route_type in FAIL_CLOSED_ROUTE_TYPES:
            return False
        if device and route.get("dev") != device:
            return False
        observed_gateway = route.get("gateway", route.get("via"))
        return not gateway or observed_gateway == gateway

    async def _verify_postconditions(
        self,
        *,
        desired_rules: tuple[tuple[int, Network], ...],
        configured_paths: dict[Network, tuple[str | None, str | None]],
        direct_paths: tuple[DirectManagementPath, ...],
        main_routes: dict[int, list[dict]],
        protected_paths: dict[Network, tuple[str | None, str | None]],
        destination_paths: dict[Network, tuple[str | None, str | None]],
        fail_closed_networks: tuple[Network, ...],
        provider_tables: dict[int, tuple[str, ...]],
    ) -> None:
        refreshed_rules = {family: await self._rules(family) for family in (4, 6)}
        owned_rules = self._owned_rules(4, refreshed_rules[4]) + self._owned_rules(
            6, refreshed_rules[6]
        )
        if Counter(owned_rules) != Counter(desired_rules) or any(
            priority == 0 for priority, _network in owned_rules
        ):
            raise ManagementRoutingError("management_rule_postcondition_failed")

        for network in fail_closed_networks:
            routes = main_routes[network.version]
            exact = [route for route in routes if self._route_network(route) == network]
            if not any(
                self._route_protocol(route) == RULE_PROTOCOL
                and route.get("metric") == ROUTE_METRIC
                and self._path_matches(route, gateway=None, device=None)
                for route in exact
            ):
                raise ManagementRoutingError(
                    "protected_destination_fail_closed_postcondition_failed"
                )

        for family in (4, 6):
            for table in provider_tables[family]:
                routes = await self._table_routes(family, table)
                for network, (gateway, device) in protected_paths.items():
                    if network.version != family:
                        continue
                    exact = [route for route in routes if self._route_network(route) == network]
                    if not exact or not any(
                        self._path_matches(route, gateway=gateway, device=device) for route in exact
                    ):
                        raise ManagementRoutingError(
                            "management_provider_route_postcondition_failed"
                        )

        physical_gateways: set[tuple[Address, str]] = set()
        for family, routes in main_routes.items():
            for route in routes:
                if (
                    route.get("dst") != "default"
                    or not route.get("gateway")
                    or not route.get("dev")
                ):
                    continue
                try:
                    gateway = ipaddress.ip_address(str(route["gateway"]))
                except ValueError:
                    raise ManagementRoutingError(
                        "management_gateway_postcondition_failed"
                    ) from None
                if gateway.version == family:
                    physical_gateways.add((gateway, str(route["dev"])))
        for gateway, device in physical_gateways:
            route = await self._route_get(gateway, "management_gateway_postcondition_failed")
            if not self._path_matches(route, gateway=None, device=device):
                raise ManagementRoutingError("management_gateway_postcondition_failed")

        gateway_addresses = tuple(gateway for gateway, _device in physical_gateways)
        for path in direct_paths:
            destination = self._representative_address(
                path.network,
                excluded=(*path.local_addresses, *gateway_addresses),
            )
            if destination is None:
                continue
            route = await self._route_get(
                destination, "management_direct_route_postcondition_failed"
            )
            if not self._path_matches(route, gateway=None, device=path.device):
                raise ManagementRoutingError("management_direct_route_postcondition_failed")

        for network, (gateway, device) in configured_paths.items():
            destination = self._representative_address(network)
            if destination is None:
                continue
            route = await self._route_get(
                destination, "management_routed_route_postcondition_failed"
            )
            if not self._path_matches(route, gateway=gateway, device=device):
                raise ManagementRoutingError("management_routed_route_postcondition_failed")

        for network, (gateway, device) in destination_paths.items():
            local_addresses = (
                await self._device_local_addresses(
                    device,
                    network.version,
                    error_code="protected_destination_route_postcondition_failed",
                )
                if device
                else ()
            )
            destination = self._representative_address(
                network,
                excluded=local_addresses,
            )
            if destination is None:
                continue
            route = await self._route_get(
                destination,
                "protected_destination_route_postcondition_failed",
            )
            if not self._path_matches(route, gateway=gateway, device=device):
                raise ManagementRoutingError("protected_destination_route_postcondition_failed")

        ipv4_defaults = [
            route
            for route in main_routes.get(4, [])
            if route.get("dst") == "default" and route.get("dev")
        ]
        if not ipv4_defaults:
            raise ManagementRoutingError("provider_route_postcondition_failed")
        public_route = await self._route_get(
            ipaddress.ip_address("1.1.1.1"), "provider_route_postcondition_failed"
        )
        provider_rule_tables = self._provider_policy_tables(refreshed_rules[4])
        if provider_rule_tables:
            if str(public_route.get("table")) not in provider_rule_tables:
                raise ManagementRoutingError("provider_route_postcondition_failed")
        else:
            default = ipv4_defaults[0]
            if not self._path_matches(
                public_route,
                gateway=default.get("gateway"),
                device=default.get("dev"),
            ):
                raise ManagementRoutingError("provider_route_postcondition_failed")

    async def _reconcile(
        self,
        configured_networks: tuple[Network, ...],
        protected_destinations: tuple[ProtectedDestination, ...],
        *,
        transition: bool,
    ) -> ReconcileResult:
        priority = PRIORITY_MIN if transition else PRIORITY_BASE
        rules = {family: await self._rules(family) for family in (4, 6)}
        initial_main_routes = {family: await self._main_routes(family) for family in (4, 6)}
        provider_devices = await self._provider_devices(
            rules=rules,
        )
        destination_paths, unavailable_destinations = self._protected_destination_paths(
            protected_destinations,
            main_routes=initial_main_routes,
            provider_devices=provider_devices,
        )
        fail_closed_networks = tuple(
            destination.network for destination in unavailable_destinations
        )
        route_added, route_removed, configured_paths, main_routes = await self._reconcile_routes(
            configured_networks,
            fail_closed_networks,
        )
        direct_paths = await self._direct_management_paths()
        direct = tuple(dict.fromkeys(path.network for path in direct_paths))
        desired_networks = tuple(
            dict.fromkeys(
                sorted(
                    (
                        *configured_networks,
                        *direct,
                        *(destination.network for destination in protected_destinations),
                    ),
                    key=_network_sort_key,
                )
            )
        )
        if len(desired_networks) > MAX_PREFIXES + len(direct_paths) + len(protected_destinations):
            raise ManagementRoutingError("too_many_management_prefixes")
        protected_paths = dict(configured_paths)
        for path in direct_paths:
            protected_paths[path.network] = (None, path.device)
        protected_paths.update(destination_paths)
        protected_paths.update({network: (None, None) for network in fail_closed_networks})

        # A priority-zero provider rule cannot be preempted by a safe ExitLane
        # destination rule: Linux evaluates lower RPDB numbers first. Instead,
        # mirror the canonical underlay paths into every earlier provider table.
        provider_added, provider_removed, provider_tables = await self._reconcile_provider_routes(
            protected_paths=protected_paths,
            rules=rules,
            management_priority=priority,
            transition=transition,
        )

        desired = tuple((priority, network) for network in desired_networks)
        existing = self._owned_rules(4, rules[4]) + self._owned_rules(6, rules[6])
        remaining = Counter(existing)
        missing: list[tuple[int, Network]] = []
        for item in desired:
            if remaining[item]:
                remaining[item] -= 1
            else:
                missing.append(item)

        added = route_added + provider_added
        removed = route_removed + provider_removed
        # Add first so a configuration or priority transition never opens a
        # management-routing gap.
        for desired_priority, network in missing:
            await self._mutate("add", desired_priority, network)
            added += 1
        for (stale_priority, network), count in sorted(
            remaining.items(), key=lambda item: (item[0][0], _network_sort_key(item[0][1]))
        ):
            for _ in range(count):
                await self._mutate("del", stale_priority, network)
                removed += 1

        await self._verify_postconditions(
            desired_rules=desired,
            configured_paths=configured_paths,
            direct_paths=direct_paths,
            main_routes=main_routes,
            protected_paths=protected_paths,
            destination_paths=destination_paths,
            fail_closed_networks=fail_closed_networks,
            provider_tables=provider_tables,
        )
        if unavailable_destinations:
            raise ManagementRoutingError("protected_destination_route_unavailable")
        return ReconcileResult(tuple(str(network) for network in desired_networks), added, removed)

    @staticmethod
    def _configured_networks(
        configured: str | list[str] | tuple[str, ...] | tuple[Network, ...],
    ) -> tuple[Network, ...]:
        if all(
            isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) for item in configured
        ):
            return tuple(configured)  # type: ignore[return-value]
        return parse_management_prefixes(configured, confirm_broad=True)  # type: ignore[arg-type]

    async def reconcile(
        self,
        configured: str | list[str] | tuple[str, ...] | tuple[Network, ...],
        protected_destinations: tuple[ProtectedDestination, ...] = (),
    ) -> ReconcileResult:
        configured_networks = self._configured_networks(configured)
        return await self._reconcile(
            configured_networks,
            protected_destinations,
            transition=False,
        )

    async def prepare_provider_transition(
        self,
        configured: str | list[str] | tuple[str, ...] | tuple[Network, ...],
        protected_destinations: tuple[ProtectedDestination, ...] = (),
    ) -> ReconcileResult:
        configured_networks = self._configured_networks(configured)
        # Priority 1 is the strongest safe non-local priority. Holding the
        # management rules there before the provider mutates its policy rules
        # prevents a connect/reconnect transition from opening an underlay gap.
        return await self._reconcile(
            configured_networks,
            protected_destinations,
            transition=True,
        )


_backend = ManagementRoutingBackend(provider_table_store=CoreProviderTableStore())
_lock: asyncio.Lock | None = None
_lock_loop: asyncio.AbstractEventLoop | None = None


def _reconcile_lock() -> asyncio.Lock:
    global _lock, _lock_loop
    loop = asyncio.get_running_loop()
    if _lock is None or _lock_loop is not loop:
        _lock = asyncio.Lock()
        _lock_loop = loop
    return _lock


async def reconcile() -> ReconcileResult:
    async with _reconcile_lock():
        return await _backend.reconcile(
            configured_prefixes(),
            configured_protected_destinations(),
        )


async def prepare_provider_transition() -> ReconcileResult:
    async with _reconcile_lock():
        return await _backend.prepare_provider_transition(
            configured_prefixes(),
            configured_protected_destinations(),
        )
