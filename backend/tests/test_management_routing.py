import asyncio
import ipaddress
import json

import pytest

from exitlane import cli, core, main
from exitlane.services import management_routing, network_security


class StatefulNetworkRunner:
    def __init__(self, *, rules=None, routes=None, provider_routes=None, fail_on=None):
        self.calls = []
        self.fail_on = fail_on
        source_rules = rules or {4: [], 6: []}
        self.rules = {
            family: [dict(rule) for rule in source_rules.get(family, [])] for family in (4, 6)
        }
        default_routes = {
            4: [
                {"dst": "default", "gateway": "172.16.130.1", "dev": "eth0"},
                {
                    "dst": "172.16.130.0/24",
                    "dev": "eth0",
                    "protocol": "kernel",
                },
            ],
            6: [],
        }
        source_routes = routes or default_routes
        self.routes = {
            family: [dict(route) for route in source_routes.get(family, [])] for family in (4, 6)
        }
        self.provider_routes = {4: {}, 6: {}}
        for family in (4, 6):
            for rule in self.rules[family]:
                table = str(rule.get("table"))
                if table in management_routing.STANDARD_ROUTE_TABLES:
                    continue
                self.provider_routes[family].setdefault(
                    table,
                    [
                        {
                            "dst": "default",
                            "dev": "wg0-mullvad",
                            "table": table,
                            "protocol": "static",
                        }
                    ],
                )
            for table, table_routes in (provider_routes or {}).get(family, {}).items():
                self.provider_routes[family][str(table)] = [
                    {**route, "table": str(table)} for route in table_routes
                ]

    @staticmethod
    def _route_network(route):
        if route.get("dst") == "default":
            return None
        return ipaddress.ip_network(route["dst"], strict=False)

    def _main_route(self, family, destination):
        candidates = [
            route
            for route in self.routes[family]
            if route.get("dst") != "default" and destination in self._route_network(route)
        ]
        if candidates:
            return max(
                candidates,
                key=lambda route: self._route_network(route).prefixlen,
            )
        return next(
            (route for route in self.routes[family] if route.get("dst") == "default"),
            None,
        )

    def _provider_route(self, family, table, destination):
        routes = self.provider_routes[family].get(str(table), [])
        candidates = [
            route
            for route in routes
            if route.get("dst") != "default" and destination in self._route_network(route)
        ]
        if candidates:
            return max(candidates, key=lambda route: self._route_network(route).prefixlen)
        return next((route for route in routes if route.get("dst") == "default"), None)

    def _route_get(self, family, destination_text):
        destination = ipaddress.ip_address(destination_text)
        for rule in sorted(
            enumerate(self.rules[family]),
            key=lambda item: (int(item[1].get("priority", 32766)), item[0]),
        ):
            value = rule[1]
            if value.get("dst") and destination not in ipaddress.ip_network(
                value["dst"], strict=False
            ):
                continue
            table = str(value.get("table"))
            if table in {"main", "254"}:
                route = self._main_route(family, destination)
                suppresses_default = (
                    value.get("suppress_prefixlen") is not None
                    or value.get("suppress_prefixlength") is not None
                )
                if route and (route.get("dst") != "default" or not suppresses_default):
                    return {"dst": destination_text, **route}
                continue
            if table not in {"local", "default", "255", "253", "None"}:
                route = self._provider_route(family, table, destination)
                if route:
                    return {"dst": destination_text, **route}
                continue
        route = self._main_route(family, destination)
        return {"dst": destination_text, **route} if route else None

    def _mutate_rule(self, family, arguments):
        action = arguments[3]
        priority = int(arguments[5])
        destination = arguments[7]
        if action == "add":
            self.rules[family].append(
                {
                    "priority": priority,
                    "dst": destination,
                    "table": "main",
                    "protocol": management_routing.RULE_PROTOCOL,
                }
            )
            return
        for index, rule in enumerate(self.rules[family]):
            rule_destination = str(rule.get("dst"))
            if "/" not in rule_destination and rule.get("dstlen") is not None:
                rule_destination = f"{rule_destination}/{rule['dstlen']}"
            if (
                int(rule.get("priority", -1)) == priority
                and ipaddress.ip_network(rule_destination, strict=False)
                == ipaddress.ip_network(destination, strict=False)
                and str(rule.get("table")) in {"main", "254"}
                and int(rule.get("protocol", -1)) == management_routing.RULE_PROTOCOL
            ):
                self.rules[family].pop(index)
                return

    def _mutate_route(self, family, arguments):
        action = arguments[3]
        route_type = "unicast"
        destination_index = 4
        if arguments[destination_index] in management_routing.FAIL_CLOSED_ROUTE_TYPES:
            route_type = arguments[destination_index]
            destination_index += 1
        destination = arguments[destination_index]
        table = str(arguments[arguments.index("table") + 1])
        routes = (
            self.routes[family]
            if table in {"main", "254"}
            else self.provider_routes[family].setdefault(table, [])
        )

        def owned(route):
            try:
                protocol = int(route.get("protocol", -1))
            except (TypeError, ValueError):
                return False
            return (
                route.get("dst") == destination
                and protocol == management_routing.RULE_PROTOCOL
                and route.get("metric") == management_routing.ROUTE_METRIC
            )

        routes[:] = [route for route in routes if not owned(route)]
        if action == "del":
            return
        route = {
            "dst": destination,
            "protocol": management_routing.RULE_PROTOCOL,
            "metric": management_routing.ROUTE_METRIC,
        }
        if route_type != "unicast":
            route["type"] = route_type
        if table not in {"main", "254"}:
            route["table"] = table
        if "via" in arguments:
            route["gateway"] = arguments[arguments.index("via") + 1]
        if "dev" in arguments:
            route["dev"] = arguments[arguments.index("dev") + 1]
        routes.append(route)

    async def __call__(self, *arguments, timeout=10, **_kwargs):
        self.calls.append(arguments)
        if self.fail_on and self.fail_on in arguments:
            return 2, "", "untrusted kernel detail"
        family = 4 if "-4" in arguments else 6
        if arguments[1:] == (
            "-j",
            f"-{family}",
            "route",
            "show",
            "table",
            "main",
            "default",
        ):
            routes = [route for route in self.routes[family] if route.get("dst") == "default"]
            return 0, json.dumps(routes), ""
        if arguments[1:] == (
            "-j",
            f"-{family}",
            "route",
            "show",
            "table",
            "main",
        ):
            return 0, json.dumps(self.routes[family]), ""
        if arguments[1:] == (
            "-j",
            f"-{family}",
            "route",
            "show",
            "table",
            "all",
        ):
            routes = [*self.routes[family]]
            for table_routes in self.provider_routes[family].values():
                routes.extend(table_routes)
            return 0, json.dumps(routes), ""
        if arguments[1:5] == ("-j", f"-{family}", "route", "show"):
            table = str(arguments[6])
            return 0, json.dumps(self.provider_routes[family].get(table, [])), ""
        if arguments[1:5] == ("-j", f"-{family}", "route", "get"):
            route = self._route_get(family, arguments[5])
            return (0, json.dumps([route]), "") if route else (2, "", "no route")
        if arguments[1:6] == (
            "-j",
            f"-{family}",
            "addr",
            "show",
            "dev",
        ):
            device = arguments[6]
            addresses = (
                [
                    {
                        "ifname": "eth0",
                        "addr_info": [
                            {
                                "family": "inet",
                                "local": "172.16.130.81",
                                "prefixlen": 24,
                                "scope": "global",
                            }
                        ],
                    }
                ]
                if family == 4 and device == "eth0"
                else self._addresses_for_device(family, device)
            )
            return 0, json.dumps(addresses), ""
        if arguments[1:] == ("-j", f"-{family}", "rule", "show"):
            return 0, json.dumps(self.rules[family]), ""
        if arguments[2:4] == ("rule", "add") or arguments[2:4] == (
            "rule",
            "del",
        ):
            self._mutate_rule(family, arguments)
            return 0, "", ""
        if arguments[2:4] in {("route", "add"), ("route", "replace"), ("route", "del")}:
            self._mutate_route(family, arguments)
            return 0, "", ""
        return 0, "", ""

    def _addresses_for_device(self, family, device):
        for route in self.routes[family]:
            network = self._route_network(route)
            if network is None or route.get("dev") != device:
                continue
            local = network.network_address + 1
            return [
                {
                    "ifname": device,
                    "addr_info": [
                        {
                            "family": "inet" if family == 4 else "inet6",
                            "local": str(local),
                            "prefixlen": network.prefixlen,
                            "scope": "global",
                        }
                    ],
                }
            ]
        return []


def network_runner(*, rules=None, routes=None, provider_routes=None, fail_on=None):
    return StatefulNetworkRunner(
        rules=rules,
        routes=routes,
        provider_routes=provider_routes,
        fail_on=fail_on,
    )


def protected_wireguard(subnet="10.99.99.0/24", interface="wg0"):
    return (
        management_routing.ProtectedDestination(
            network=ipaddress.ip_network(subnet),
            expected_device=interface,
            source="wireguard_ingress",
        ),
    )


def mullvad_rules(table=1836018789):
    return {
        4: [
            {"priority": 0, "table": table, "fwmark": "0x6d6f6c65"},
            {"priority": 0, "table": "main", "suppress_prefixlength": 0},
        ],
        6: [],
    }


def routes_with_wireguard(subnet="10.99.99.0/24", interface="wg0"):
    return {
        4: [
            {"dst": "default", "gateway": "172.16.130.1", "dev": "eth0"},
            {"dst": "172.16.130.0/24", "dev": "eth0", "protocol": "kernel"},
            {"dst": subnet, "dev": interface, "protocol": "kernel"},
        ],
        6: [],
    }


def test_configured_management_prefixes_are_exact_and_not_generic_private_bypass():
    configured = management_routing.parse_management_prefixes(
        [" 172.16.5.251/24 ", "192.168.44.9", "172.16.5.0/24"]
    )

    assert [str(prefix) for prefix in configured] == [
        "172.16.5.0/24",
        "192.168.44.9/32",
    ]
    assert management_routing.destination_is_protected(configured, "172.16.5.251")
    assert not management_routing.destination_is_protected(configured, "10.8.0.1")
    assert not management_routing.destination_is_protected(configured, "1.1.1.1")


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "not-a-prefix", "*"])
def test_universal_or_invalid_management_bypass_is_rejected(value):
    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        management_routing.parse_management_prefixes([value])

    assert caught.value.code in {
        "invalid_management_prefix",
        "management_prefix_too_broad",
    }


def test_full_rfc1918_root_requires_explicit_confirmation():
    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        management_routing.parse_management_prefixes(["10.0.0.0/8"])

    assert caught.value.code == "broad_management_prefix_confirmation_required"
    assert (
        str(management_routing.parse_management_prefixes(["10.0.0.0/8"], confirm_broad=True)[0])
        == "10.0.0.0/8"
    )


def test_reconcile_protects_direct_and_routed_management_destinations_only():
    runner = network_runner()
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    result = asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert result.prefixes == ("172.16.5.0/24", "172.16.130.0/24")
    add_calls = [call for call in runner.calls if call[2:4] == ("rule", "add")]
    assert add_calls == [
        (
            "/usr/sbin/ip",
            "-4",
            "rule",
            "add",
            "priority",
            "10000",
            "to",
            "172.16.5.0/24",
            "lookup",
            "main",
            "protocol",
            "196",
        ),
        (
            "/usr/sbin/ip",
            "-4",
            "rule",
            "add",
            "priority",
            "10000",
            "to",
            "172.16.130.0/24",
            "lookup",
            "main",
            "protocol",
            "196",
        ),
    ]
    assert all("from" not in call for call in add_calls)
    assert all(int(call[5]) < 32764 for call in add_calls)
    assert (
        "/usr/sbin/ip",
        "-4",
        "route",
        "add",
        "172.16.5.0/24",
        "via",
        "172.16.130.1",
        "dev",
        "eth0",
        "table",
        "main",
        "protocol",
        "196",
        "metric",
        "42760",
    ) in runner.calls


def test_reconcile_removes_only_stale_exitlane_owned_rules_and_preserves_provider_rules():
    rules = {
        4: [
            {"priority": 10000, "dst": "172.16.4.0/24", "table": "main", "protocol": 196},
            {"priority": 10001, "dst": "172.16.130.0/24", "table": "main", "protocol": 196},
            {"priority": 32764, "table": "main", "suppress_prefixlength": 0},
            {"priority": 32765, "not": True, "fwmark": "0x6d6f6c65", "table": 1836018789},
        ],
        6: [],
    }
    runner = network_runner(rules=rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    delete_calls = [call for call in runner.calls if "del" in call]
    assert delete_calls == [
        (
            "/usr/sbin/ip",
            "-4",
            "rule",
            "del",
            "priority",
            "10000",
            "to",
            "172.16.4.0/24",
            "lookup",
            "main",
            "protocol",
            "196",
        ),
        (
            "/usr/sbin/ip",
            "-4",
            "rule",
            "del",
            "priority",
            "10001",
            "to",
            "172.16.130.0/24",
            "lookup",
            "main",
            "protocol",
            "196",
        ),
    ]
    assert not any("32764" in call or "32765" in call for call in delete_calls)


def test_reconcile_accepts_iproute_json_with_separate_destination_prefix_length():
    rules = {
        4: [
            {
                "priority": 10000,
                "dst": "172.16.5.0",
                "dstlen": 24,
                "table": "main",
                "protocol": "196",
            },
            {
                "priority": 10001,
                "dst": "172.16.130.0",
                "dstlen": 24,
                "table": "main",
                "protocol": "196",
            },
        ],
        6: [],
    }
    runner = network_runner(rules=rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    result = asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert result.added == 2
    assert result.removed == 1
    assert [call[5] for call in runner.calls if call[2:4] == ("rule", "add")] == ["10000"]


def test_provider_policy_before_base_priority_gets_underlay_routes():
    rules = {
        4: [
            {
                "priority": 9998,
                "table": "main",
                "suppress_prefixlen": 0,
            },
            {
                "priority": 9999,
                "not": None,
                "fwmark": "0x6d6f6c65",
                "table": "1836018789",
            },
            {
                "priority": 10000,
                "dst": "172.16.5.0/24",
                "table": "main",
                "protocol": 196,
            },
            {
                "priority": 10001,
                "dst": "172.16.130.0/24",
                "table": "main",
                "protocol": 196,
            },
        ],
        6: [],
    }
    runner = network_runner(rules=rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    added_rules = [call for call in runner.calls if call[2:4] == ("rule", "add")]
    assert [call[5] for call in added_rules] == ["10000"]
    provider_route_calls = [
        call for call in runner.calls if call[2:4] == ("route", "add") and "1836018789" in call
    ]
    assert [call[4] for call in provider_route_calls] == [
        "172.16.130.0/24",
        "172.16.5.0/24",
    ]
    assert all(call[call.index("protocol") + 1] == "196" for call in provider_route_calls)


def test_priority_zero_provider_table_is_reconciled_instead_of_preempted():
    rules = {
        4: [
            {"priority": 0, "table": 1836018789, "fwmark": "0x6d6f6c65"},
            {"priority": 0, "table": "main", "suppress_prefixlength": 0},
            {
                "priority": 1,
                "dst": "172.16.5.0/24",
                "table": "main",
                "protocol": 196,
            },
            {
                "priority": 1,
                "dst": "172.16.130.0/24",
                "table": "main",
                "protocol": 196,
            },
        ],
        6: [],
    }
    runner = network_runner(rules=rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    assert runner._route_get(4, "172.16.130.1")["dev"] == "wg0-mullvad"

    result = asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert result.prefixes == ("172.16.5.0/24", "172.16.130.0/24")
    assert backend._owned_rules(4, runner.rules[4]) == [
        (10000, ipaddress.ip_network("172.16.5.0/24")),
        (10000, ipaddress.ip_network("172.16.130.0/24")),
    ]
    assert runner._route_get(4, "172.16.130.1")["dev"] == "eth0"
    assert runner._route_get(4, "172.16.5.251")["gateway"] == "172.16.130.1"
    assert runner._route_get(4, "1.1.1.1")["dev"] == "wg0-mullvad"


def test_mullvad_table_mirrors_management_and_wireguard_protected_destinations():
    runner = network_runner(
        rules=mullvad_rules(),
        routes=routes_with_wireguard(),
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    result = asyncio.run(backend.reconcile(["172.16.5.0/24"], protected_wireguard()))

    assert result.prefixes == (
        "10.99.99.0/24",
        "172.16.5.0/24",
        "172.16.130.0/24",
    )
    protected = backend._owned_provider_routes(
        4,
        runner.provider_routes[4]["1836018789"],
    )
    assert protected == {
        ("1836018789", ipaddress.ip_network("10.99.99.0/24")): (None, "wg0"),
        ("1836018789", ipaddress.ip_network("172.16.5.0/24")): (
            "172.16.130.1",
            "eth0",
        ),
        ("1836018789", ipaddress.ip_network("172.16.130.0/24")): (
            None,
            "eth0",
        ),
    }
    assert runner._route_get(4, "10.99.99.2")["dev"] == "wg0"
    assert runner._route_get(4, "172.16.5.10")["dev"] == "eth0"
    assert runner._route_get(4, "172.16.130.2")["dev"] == "eth0"
    assert runner._route_get(4, "1.1.1.1")["dev"] == "wg0-mullvad"


def test_wireguard_protected_destination_uses_configured_subnet_and_interface():
    subnet = "10.55.0.0/24"
    interface = "wg-ingress"
    runner = network_runner(
        rules=mullvad_rules(),
        routes=routes_with_wireguard(subnet, interface),
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile([], protected_wireguard(subnet, interface)))

    assert runner._route_get(4, "10.55.0.2")["dev"] == interface
    assert not any(
        route.get("dst") == "10.99.99.0/24" for route in runner.provider_routes[4]["1836018789"]
    )


def test_wireguard_disabled_removes_stale_owned_rule_and_provider_route():
    runner = network_runner(
        rules=mullvad_rules(),
        routes=routes_with_wireguard(),
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)
    asyncio.run(backend.reconcile([], protected_wireguard()))

    result = asyncio.run(backend.reconcile([], ()))

    assert result.prefixes == ("172.16.130.0/24",)
    assert not any(
        network == ipaddress.ip_network("10.99.99.0/24")
        for _priority, network in backend._owned_rules(4, runner.rules[4])
    )
    assert not any(
        route.get("dst") == "10.99.99.0/24" for route in runner.provider_routes[4]["1836018789"]
    )


def test_wireguard_prefix_change_removes_old_and_installs_new_owned_route():
    runner = network_runner(
        rules=mullvad_rules(),
        routes=routes_with_wireguard(),
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)
    asyncio.run(backend.reconcile([], protected_wireguard()))
    runner.routes[4] = routes_with_wireguard("10.55.0.0/24", "wg-new")[4]

    asyncio.run(backend.reconcile([], protected_wireguard("10.55.0.0/24", "wg-new")))

    destinations = {route.get("dst") for route in runner.provider_routes[4]["1836018789"]}
    assert "10.99.99.0/24" not in destinations
    assert "10.55.0.0/24" in destinations
    assert runner._route_get(4, "10.55.0.2")["dev"] == "wg-new"


def test_wireguard_routes_are_idempotent_and_return_after_provider_table_rebuild():
    runner = network_runner(
        rules=mullvad_rules(),
        routes=routes_with_wireguard(),
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)
    asyncio.run(backend.reconcile([], protected_wireguard()))
    call_count = len(runner.calls)

    asyncio.run(backend.reconcile([], protected_wireguard()))

    assert not any(
        call[2] in {"rule", "route"} and call[3] in {"add", "del", "replace"}
        for call in runner.calls[call_count:]
    )
    runner.provider_routes[4]["1836018789"] = [
        {
            "dst": "default",
            "dev": "wg0-mullvad",
            "table": "1836018789",
            "protocol": "static",
        }
    ]
    rebuild_call_count = len(runner.calls)

    asyncio.run(backend.reconcile([], protected_wireguard()))

    rebuilt = [
        call
        for call in runner.calls[rebuild_call_count:]
        if call[2:4] == ("route", "add") and "1836018789" in call
    ]
    assert {call[4] for call in rebuilt} == {
        "10.99.99.0/24",
        "172.16.130.0/24",
    }


def test_provider_owned_canonical_route_is_rejected_and_blocked_fail_closed():
    routes = routes_with_wireguard()
    routes[4][-1]["dev"] = "wg0-mullvad"
    runner = network_runner(rules=mullvad_rules(), routes=routes)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        asyncio.run(backend.reconcile([], protected_wireguard()))

    assert caught.value.code == "protected_destination_route_unavailable"
    main_block = next(
        route
        for route in runner.routes[4]
        if route.get("dst") == "10.99.99.0/24"
        and route.get("protocol") == management_routing.RULE_PROTOCOL
    )
    provider_block = next(
        route
        for route in runner.provider_routes[4]["1836018789"]
        if route.get("dst") == "10.99.99.0/24"
    )
    assert main_block["type"] == "unreachable"
    assert provider_block["type"] == "unreachable"
    assert provider_block.get("dev") is None


def test_later_provider_table_device_is_rejected_as_protected_destination_path():
    table = "205"
    rules = {
        4: [
            {"priority": 32764, "table": "main", "suppress_prefixlength": 0},
            {"priority": 32765, "table": int(table), "fwmark": "0xe1f1"},
        ],
        6: [],
    }
    routes = routes_with_wireguard(interface="nordlynx")
    runner = network_runner(
        rules=rules,
        routes=routes,
        provider_routes={4: {table: [{"dst": "default", "dev": "nordlynx", "protocol": "static"}]}},
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        asyncio.run(backend.reconcile([], protected_wireguard(interface="nordlynx")))

    assert caught.value.code == "protected_destination_route_unavailable"
    assert (
        next(
            route
            for route in runner.routes[4]
            if route.get("dst") == "10.99.99.0/24"
            and route.get("protocol") == management_routing.RULE_PROTOCOL
        )["type"]
        == "unreachable"
    )


def test_wireguard_gateway_route_is_copied_without_hardcoded_path_assumptions():
    routes = routes_with_wireguard("10.77.0.0/24", "wg-edge")
    routes[4][-1]["gateway"] = "192.0.2.9"
    runner = network_runner(rules=mullvad_rules(), routes=routes)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile([], protected_wireguard("10.77.0.0/24", "wg-edge")))

    copied = next(
        route
        for route in runner.provider_routes[4]["1836018789"]
        if route.get("dst") == "10.77.0.0/24"
    )
    assert copied["gateway"] == "192.0.2.9"
    assert copied["dev"] == "wg-edge"


def test_canonical_wireguard_destination_comes_only_from_enabled_runtime_config(
    monkeypatch,
):
    values = {
        management_routing.WIREGUARD_CONFIGURED_SETTING: False,
        management_routing.WIREGUARD_SUBNET_SETTING: "10.55.0.0/24",
        management_routing.WIREGUARD_INTERFACE_SETTING: "wg-custom",
    }
    monkeypatch.setattr(core, "setting", lambda key, default=None: values.get(key, default))

    assert management_routing.configured_protected_destinations() == ()
    values[management_routing.WIREGUARD_CONFIGURED_SETTING] = True

    assert management_routing.configured_protected_destinations() == (
        management_routing.ProtectedDestination(
            network=ipaddress.ip_network("10.55.0.0/24"),
            expected_device="wg-custom",
            source="wireguard_ingress",
        ),
    )


@pytest.mark.parametrize(
    ("subnet", "interface"),
    [
        ("10.55.0.1/24", "wg-custom"),
        ("0.0.0.0/0", "wg-custom"),
        ("2001:db8::/64", "wg-custom"),
        ("10.55.0.0/24", "invalid interface"),
    ],
)
def test_invalid_canonical_wireguard_destination_fails_with_stable_code(
    monkeypatch, subnet, interface
):
    values = {
        management_routing.WIREGUARD_CONFIGURED_SETTING: True,
        management_routing.WIREGUARD_SUBNET_SETTING: subnet,
        management_routing.WIREGUARD_INTERFACE_SETTING: interface,
    }
    monkeypatch.setattr(core, "setting", lambda key, default=None: values.get(key, default))

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        management_routing.configured_protected_destinations()

    assert caught.value.code == "protected_destination_configuration_invalid"


def test_provider_route_reconciliation_is_idempotent_and_recovers_table_rebuild():
    rules = {
        4: [
            {"priority": 0, "table": 1836018789, "fwmark": "0x6d6f6c65"},
            {"priority": 0, "table": "main", "suppress_prefixlength": 0},
        ],
        6: [],
    }
    runner = network_runner(rules=rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))
    first_call_count = len(runner.calls)
    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert not any(
        call[2] in {"rule", "route"} and call[3] in {"add", "del", "replace"}
        for call in runner.calls[first_call_count:]
    )

    runner.provider_routes[4]["1836018789"] = [
        {
            "dst": "default",
            "dev": "wg0-mullvad",
            "table": "1836018789",
            "protocol": "static",
        }
    ]
    rebuild_call_count = len(runner.calls)
    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    rebuilt = [
        call
        for call in runner.calls[rebuild_call_count:]
        if call[2:4] == ("route", "add") and "1836018789" in call
    ]
    assert [call[4] for call in rebuilt] == ["172.16.130.0/24", "172.16.5.0/24"]


def test_provider_table_id_change_adds_new_routes_and_removes_stale_owned_routes():
    old_table = "1836018789"
    new_table = "424242"
    store = management_routing.MemoryProviderTableStore()
    store.save({4: (old_table,), 6: ()})
    rules = {
        4: [
            {"priority": 0, "table": int(new_table), "fwmark": "0x1234"},
            {"priority": 0, "table": "main", "suppress_prefixlength": 0},
        ],
        6: [],
    }
    provider_routes = {
        4: {
            old_table: [
                {
                    "dst": "172.16.130.0/24",
                    "dev": "eth0",
                    "protocol": 196,
                    "metric": 42760,
                },
                {
                    "dst": "172.16.5.0/24",
                    "gateway": "172.16.130.1",
                    "dev": "eth0",
                    "protocol": 196,
                    "metric": 42760,
                },
            ],
            new_table: [
                {"dst": "default", "dev": "wg-new", "protocol": "static"},
            ],
        }
    }
    runner = network_runner(rules=rules, provider_routes=provider_routes)
    backend = management_routing.ManagementRoutingBackend(runner=runner, provider_table_store=store)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert store.load()[4] == (new_table,)
    assert {
        (call[3], call[4], call[call.index("table") + 1])
        for call in runner.calls
        if call[2] == "route"
        and call[3] in {"add", "del"}
        and call[call.index("table") + 1] != "main"
    } == {
        ("add", "172.16.130.0/24", new_table),
        ("add", "172.16.5.0/24", new_table),
        ("del", "172.16.5.0/24", old_table),
        ("del", "172.16.130.0/24", old_table),
    }


def test_correct_provider_owned_underlay_route_is_preserved_without_churn():
    table = "1836018789"
    rules = {4: [{"priority": 0, "table": int(table)}], 6: []}
    provider_routes = {
        4: {
            table: [
                {"dst": "default", "dev": "wg0-mullvad", "protocol": "static"},
                {"dst": "172.16.130.0/24", "dev": "eth0", "protocol": "static"},
                {
                    "dst": "172.16.5.0/24",
                    "gateway": "172.16.130.1",
                    "dev": "eth0",
                    "protocol": "static",
                },
            ]
        }
    }
    runner = network_runner(rules=rules, provider_routes=provider_routes)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert not any(call[2] == "route" and "1836018789" in call for call in runner.calls)


def test_conflicting_provider_owned_route_fails_safe_without_replacement():
    table = "1836018789"
    rules = {4: [{"priority": 0, "table": int(table)}], 6: []}
    provider_routes = {
        4: {
            table: [
                {"dst": "default", "dev": "wg0-mullvad", "protocol": "static"},
                {
                    "dst": "172.16.130.0/24",
                    "dev": "wg0-mullvad",
                    "protocol": "static",
                },
            ]
        }
    }
    runner = network_runner(rules=rules, provider_routes=provider_routes)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert caught.value.code == "management_provider_route_conflict"
    assert not any(
        call[2] == "route"
        and call[3] in {"add", "del", "replace"}
        and call[call.index("table") + 1] == table
        for call in runner.calls
    )


def test_later_nordvpn_policy_table_is_not_modified():
    table = "205"
    rules = {
        4: [
            {"priority": 32764, "table": "main", "suppress_prefixlength": 0},
            {"priority": 32765, "table": int(table), "fwmark": "0xe1f1"},
        ],
        6: [],
    }
    provider_routes = {4: {table: [{"dst": "default", "dev": "nordlynx", "protocol": "static"}]}}
    runner = network_runner(
        rules=rules,
        routes=routes_with_wireguard(),
        provider_routes=provider_routes,
    )
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"], protected_wireguard()))

    assert not any(call[2] == "route" and table in call for call in runner.calls)
    assert runner.provider_routes[4][table] == [
        {"dst": "default", "dev": "nordlynx", "protocol": "static", "table": table}
    ]
    assert runner._route_get(4, "10.99.99.2")["dev"] == "wg0"


def test_boot_transition_prepopulates_cached_provider_table_before_rule_exists():
    table = "1836018789"
    store = management_routing.MemoryProviderTableStore()
    store.save({4: (table,), 6: ()})
    runner = network_runner(provider_routes={4: {table: []}})
    backend = management_routing.ManagementRoutingBackend(runner=runner, provider_table_store=store)

    asyncio.run(backend.prepare_provider_transition(["172.16.5.0/24"]))

    assert backend._owned_rules(4, runner.rules[4]) == [
        (1, ipaddress.ip_network("172.16.5.0/24")),
        (1, ipaddress.ip_network("172.16.130.0/24")),
    ]
    assert [route["dst"] for route in runner.provider_routes[4][table]] == [
        "172.16.130.0/24",
        "172.16.5.0/24",
    ]


def test_reconcile_removes_legacy_priority_zero_and_duplicate_owned_rules_only():
    rules = {
        4: [
            {
                "priority": 0,
                "dst": "172.16.5.0/24",
                "table": "main",
                "protocol": 196,
            },
            {
                "priority": 10000,
                "dst": "172.16.5.0/24",
                "table": "main",
                "protocol": 196,
            },
            {
                "priority": 10001,
                "dst": "172.16.130.0/24",
                "table": "main",
                "protocol": 196,
            },
            {"priority": 2, "table": "main", "suppress_prefixlength": 0},
            {
                "priority": 3,
                "not": True,
                "fwmark": "0x6d6f6c65",
                "table": 1836018789,
            },
        ],
        6: [],
    }
    runner = network_runner(rules=rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    result = asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert result.prefixes == ("172.16.5.0/24", "172.16.130.0/24")
    assert backend._owned_rules(4, runner.rules[4]) == [
        (10000, ipaddress.ip_network("172.16.5.0/24")),
        (10000, ipaddress.ip_network("172.16.130.0/24")),
    ]
    delete_calls = [call for call in runner.calls if call[2:4] == ("rule", "del")]
    assert {call[5] for call in delete_calls} == {"0", "10001"}
    assert not any(call[5] in {"2", "3"} for call in delete_calls)
    assert [
        rule
        for rule in runner.rules[4]
        if int(rule.get("protocol", -1)) != management_routing.RULE_PROTOCOL
    ] == rules[4][-2:]


def test_reconcile_connect_reconnect_and_reboot_are_idempotent():
    duplicate_rules = {
        4: [
            {
                "priority": 10000,
                "dst": destination,
                "table": "main",
                "protocol": 196,
            }
            for destination in (
                "172.16.5.0/24",
                "172.16.5.0/24",
                "172.16.130.0/24",
                "172.16.130.0/24",
            )
        ],
        6: [],
    }
    runner = network_runner(rules=duplicate_rules)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))
    first_call_count = len(runner.calls)
    asyncio.run(backend.reconcile(["172.16.5.0/24"]))
    repeated_calls = runner.calls[first_call_count:]
    assert not any(
        call[2] in {"rule", "route"} and call[3] in {"add", "del", "replace"}
        for call in repeated_calls
    )

    asyncio.run(backend.prepare_provider_transition(["172.16.5.0/24"]))
    runner.rules[4].extend(
        [
            {"priority": 2, "table": "main", "suppress_prefixlength": 0},
            {"priority": 3, "table": 1836018789, "fwmark": "0x6d6f6c65"},
        ]
    )
    runner.provider_routes[4]["1836018789"] = [
        {
            "dst": "default",
            "dev": "wg0-mullvad",
            "table": "1836018789",
            "protocol": "static",
        }
    ]
    asyncio.run(backend.reconcile(["172.16.5.0/24"]))
    reconnect_call_count = len(runner.calls)
    asyncio.run(backend.prepare_provider_transition(["172.16.5.0/24"]))
    asyncio.run(backend.reconcile(["172.16.5.0/24"]))
    reboot_backend = management_routing.ManagementRoutingBackend(runner=runner)
    asyncio.run(reboot_backend.reconcile(["172.16.5.0/24"]))

    lifecycle_calls = runner.calls[reconnect_call_count:]
    assert not any(
        call[2] == "route" and call[3] in {"add", "del", "replace"} for call in lifecycle_calls
    )
    assert reboot_backend._owned_rules(4, runner.rules[4]) == [
        (10000, ipaddress.ip_network("172.16.5.0/24")),
        (10000, ipaddress.ip_network("172.16.130.0/24")),
    ]


def test_reconcile_checks_gateway_direct_routed_and_public_route_resolution():
    runner = network_runner()
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    route_get_destinations = [
        call[5] for call in runner.calls if call[1:5] == ("-j", "-4", "route", "get")
    ]
    assert route_get_destinations == [
        "172.16.130.1",
        "172.16.130.2",
        "172.16.5.1",
        "1.1.1.1",
    ]


def test_physical_gateway_postcondition_rejects_tunnel_resolution():
    runner = network_runner()
    original_route_get = runner._route_get

    def route_get(family, destination):
        if destination == "172.16.130.1":
            return {
                "dst": destination,
                "dev": "wg0-mullvad",
                "table": 1836018789,
            }
        return original_route_get(family, destination)

    runner._route_get = route_get
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert caught.value.code == "management_gateway_postcondition_failed"


def test_transition_preparation_keeps_owned_main_route_and_removes_only_owned_rules():
    rules = {
        4: [
            {
                "priority": 9996,
                "dst": "172.16.5.0/24",
                "table": "main",
                "protocol": 196,
            },
            {
                "priority": 9998,
                "table": "main",
                "suppress_prefixlen": 0,
            },
        ],
        6: [],
    }
    routes = {
        4: [
            {"dst": "default", "gateway": "172.16.130.1", "dev": "eth0"},
            {
                "dst": "172.16.5.0/24",
                "gateway": "172.16.130.1",
                "dev": "eth0",
                "protocol": "196",
                "metric": 42760,
            },
            {"dst": "172.16.130.0/24", "dev": "eth0", "protocol": "kernel"},
        ],
        6: [],
    }
    runner = network_runner(rules=rules, routes=routes)
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    asyncio.run(backend.prepare_provider_transition(["172.16.5.0/24"]))

    assert any(call[2:4] == ("rule", "del") for call in runner.calls)
    assert not any(call[2:4] == ("route", "del") for call in runner.calls)
    assert not any(call[2:4] == ("route", "add") for call in runner.calls)


@pytest.mark.parametrize("provider_state", ["disconnected", "connected", "failed"])
def test_reconcile_is_provider_neutral(provider_state):
    runner = network_runner()
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    result = asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert provider_state not in str(runner.calls)
    assert result.prefixes == ("172.16.5.0/24", "172.16.130.0/24")


def test_kernel_failure_exposes_only_stable_error_code():
    runner = network_runner(fail_on="add")
    backend = management_routing.ManagementRoutingBackend(runner=runner)

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert caught.value.code == "management_route_apply_failed"
    assert "untrusted kernel detail" not in str(caught.value)


@pytest.mark.parametrize("operation", ["load", "save"])
def test_provider_table_state_failure_exposes_only_stable_error_code(operation):
    class FailingStore(management_routing.MemoryProviderTableStore):
        def load(self):
            if operation == "load":
                raise RuntimeError("untrusted storage detail")
            return super().load()

        def save(self, tables):
            if operation == "save":
                raise RuntimeError("untrusted storage detail")
            super().save(tables)

    runner = network_runner(
        rules={
            4: [{"priority": 0, "table": 1836018789, "fwmark": "0x6d6f6c65"}],
            6: [],
        }
    )
    backend = management_routing.ManagementRoutingBackend(
        runner=runner,
        provider_table_store=FailingStore(),
    )

    with pytest.raises(management_routing.ManagementRoutingError) as caught:
        asyncio.run(backend.reconcile(["172.16.5.0/24"]))

    assert caught.value.code == "management_provider_table_state_failed"
    assert "untrusted storage detail" not in str(caught.value)


def test_network_configuration_persists_explicit_management_prefixes_atomically(
    tmp_path, monkeypatch
):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    for environment in network_security.ENVIRONMENT_KEYS.values():
        monkeypatch.delenv(environment, raising=False)
    core.init()

    configured, changed = network_security.update_config(
        public_url="",
        trusted_proxies=[],
        secure_cookie_policy="auto",
        management_prefixes=["172.16.5.251/24"],
    )

    assert changed == ["management_prefixes"]
    assert configured.as_public_dict()["management_prefixes"] == ["172.16.5.0/24"]
    assert core.setting(management_routing.SETTING_KEY) == ["172.16.5.0/24"]


def test_boot_unit_runs_management_reconcile_before_providers():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    unit = (root / "systemd/exitlane-management-routing.service").read_text(encoding="utf-8")
    application_unit = (root / "systemd/exitlane.service").read_text(encoding="utf-8")
    installer = (root / "installer/install-debian.sh").read_text(encoding="utf-8")
    wireguard_dropin = (root / "systemd/wg-quick@.service.d/exitlane.conf").read_text(
        encoding="utf-8"
    )

    assert "ExecStart=/usr/local/sbin/exitlane-cli prepare-management-routes" in unit
    assert "Before=exitlane.service nordvpnd.service" in unit
    assert "mullvad-daemon.service" not in unit
    assert "After=networking.service" in unit
    assert "Wants=networking.service" in unit
    for protected_unit in (unit, application_unit):
        assert "RuntimeDirectory=exitlane-routing" in protected_unit
        assert "RuntimeDirectoryMode=0700" in protected_unit
        assert "RuntimeDirectoryPreserve=yes" in protected_unit
    assert (
        "Requires=exitlane-provider-egress.service exitlane-management-routing.service"
        in wireguard_dropin
    )
    assert (
        "After=exitlane-provider-egress.service exitlane-management-routing.service"
        in wireguard_dropin
    )
    assert "After=network-online.target" not in unit
    assert "Wants=network-online.target" not in unit
    assert "exitlane-management-routing.service" in application_unit
    assert "systemctl enable exitlane-management-routing.service" in installer
    assert "systemctl restart exitlane-management-routing.service" in installer
    assert (
        "ExecStartPost=/usr/local/sbin/exitlane-cli reconcile-management-routes" in wireguard_dropin
    )
    assert (
        "ExecStopPost=/usr/local/sbin/exitlane-cli reconcile-management-routes" in wireguard_dropin
    )
    assert "WIREGUARD_ROUTING_DROPIN_SOURCE" in installer
    assert "WIREGUARD_ROUTING_DROPIN_TARGET" in installer
    recovery_section = installer[
        installer.index("prepare_upgrade_recovery()") : installer.index("rollback_upgrade()")
    ]
    restore_section = installer[
        installer.index("restore_recovery_files()") : installer.index("snapshot_recovery_path()")
    ]
    source_check = installer[
        installer.index("check_source_layout()") : installer.index("check_tun_device()")
    ]
    assert "WIREGUARD_ROUTING_DROPIN_TARGET" in recovery_section
    assert "WIREGUARD_ROUTING_DROPIN_TARGET" in restore_section
    assert "WIREGUARD_ROUTING_DROPIN_SOURCE" in source_check


def test_boot_cli_reports_only_stable_reconciliation_errors(monkeypatch, capsys):
    async def fail():
        raise management_routing.ManagementRoutingError("management_rule_apply_failed")

    monkeypatch.setattr(management_routing, "reconcile", fail)

    assert cli.reconcile_management_routes(effective_user_id=0) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        "Management routing reconciliation failed: management_rule_apply_failed.\n"
    )


def test_wireguard_hook_cli_accepts_verified_fail_closed_interface_stop(monkeypatch, capsys):
    async def blocked():
        raise management_routing.ManagementRoutingError("protected_destination_route_unavailable")

    monkeypatch.setattr(management_routing, "reconcile", blocked)

    assert cli.reconcile_management_routes(effective_user_id=0) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == (
        "Protected destination routing is fail-closed pending interface startup.\n"
    )


def test_boot_prepare_cli_reports_only_stable_errors(monkeypatch, capsys):
    async def fail():
        raise management_routing.ManagementRoutingError("management_provider_route_apply_failed")

    monkeypatch.setattr(management_routing, "prepare_provider_transition", fail)

    assert cli.prepare_management_routes(effective_user_id=0) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        "Management routing preparation failed: management_provider_route_apply_failed.\n"
    )


def test_boot_prepare_cli_accepts_verified_fail_closed_interface_startup_race(monkeypatch, capsys):
    async def blocked():
        raise management_routing.ManagementRoutingError("protected_destination_route_unavailable")

    monkeypatch.setattr(management_routing, "prepare_provider_transition", blocked)

    assert cli.prepare_management_routes(effective_user_id=0) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == (
        "Protected destination routing is fail-closed pending interface startup.\n"
    )


def test_runtime_monitor_retries_after_provider_or_daemon_rule_loss(monkeypatch):
    attempts = []
    sleeps = []
    events = []

    async def reconcile():
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            raise management_routing.ManagementRoutingError("management_rule_inspection_failed")
        return management_routing.ReconcileResult(("172.16.130.0/24",), 1, 0)

    async def sleep(_seconds):
        sleeps.append(True)
        if len(sleeps) == 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(main.management_routing, "reconcile", reconcile)
    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(
        main,
        "record_event",
        lambda code, **values: events.append((code, values)),
    )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._monitor_management_routing())

    assert attempts == [1, 2]
    assert events == [
        (
            "network.management_routing_error",
            {"metadata": {"reason": "management_rule_inspection_failed"}},
        )
    ]


@pytest.mark.parametrize("first_method", ["prepare_provider_transition", "reconcile"])
def test_independent_processes_serialize_reconciliation_without_blocking_event_loop(
    tmp_path, first_method
):
    import sys

    second_method = (
        "reconcile"
        if first_method == "prepare_provider_transition"
        else "prepare_provider_transition"
    )
    # Separate Python processes model the boot oneshot, wg-quick hook and app.
    script = r"""
import asyncio
import sys
from pathlib import Path
from exitlane.services import management_routing as routing
root = Path(sys.argv[1])
method, label = sys.argv[2:]
routing.LOCK_PATH = root / 'management.lock'
routing.configured_prefixes = lambda: ()
routing.configured_protected_destinations = lambda: ()
class Backend:
    async def work(self, *args):
        with (root / 'events').open('a') as stream:
            stream.write(label + '-enter\n')
        print('entered', flush=True)
        if label == 'first':
            while not (root / 'release').exists():
                await asyncio.sleep(0.01)
        with (root / 'events').open('a') as stream:
            stream.write(label + '-exit\n')
        return routing.ReconcileResult((), 0, 0)
    reconcile = work
    prepare_provider_transition = work
routing._backend = Backend()
async def heartbeat():
    await asyncio.sleep(0.05)
    print('tick', flush=True)
async def run():
    task = asyncio.create_task(heartbeat())
    await getattr(routing, method)()
    await task
asyncio.run(run())
"""

    async def run():
        processes = []
        try:
            first = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                script,
                str(tmp_path),
                first_method,
                "first",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            processes.append(first)
            assert await asyncio.wait_for(first.stdout.readline(), 5) == b"entered\n"
            second = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                script,
                str(tmp_path),
                second_method,
                "second",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            processes.append(second)
            # A heartbeat runs while the second process waits; it cannot enter the backend.
            assert await asyncio.wait_for(second.stdout.readline(), 5) == b"tick\n"
            assert (tmp_path / "events").read_text().splitlines() == ["first-enter"]
            (tmp_path / "release").touch()
            for process in processes:
                _stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
                assert process.returncode == 0, stderr.decode()
            assert (tmp_path / "events").read_text().splitlines() == [
                "first-enter",
                "first-exit",
                "second-enter",
                "second-exit",
            ]
            assert (tmp_path / "management.lock").stat().st_mode & 0o777 == 0o600
        finally:
            for process in processes:
                if process.returncode is None:
                    process.kill()
                    await process.wait()

    asyncio.run(run())


def test_management_process_lock_timeout_is_bounded_and_does_not_mutate(tmp_path, monkeypatch):
    import fcntl
    import os

    path = tmp_path / "management.lock"
    monkeypatch.setattr(management_routing, "LOCK_PATH", path)
    monkeypatch.setattr(management_routing, "LOCK_TIMEOUT_SECONDS", 0.03)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    async def run():
        with pytest.raises(
            management_routing.ManagementRoutingError, match="^management_lock_timeout$"
        ):
            async with management_routing._process_reconcile_lock():
                pytest.fail("entered a busy management transaction")

    try:
        asyncio.run(run())
        assert path.read_bytes() == b""
    finally:
        os.close(descriptor)

    # The timed-out waiter must not keep a descriptor or advisory lock alive.
    async def acquire():
        async with management_routing._process_reconcile_lock():
            pass

    asyncio.run(acquire())


@pytest.mark.parametrize("cancel_while", ["waiting", "holding"])
def test_management_process_lock_cancellation_releases_descriptors(
    tmp_path, monkeypatch, cancel_while
):
    import fcntl
    import os
    from pathlib import Path

    path = tmp_path / "management.lock"
    monkeypatch.setattr(management_routing, "LOCK_PATH", path)

    async def run():
        descriptor = None
        if cancel_while == "waiting":
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        baseline = len(list(Path("/proc/self/fd").iterdir()))
        entered = asyncio.Event()

        async def holder():
            async with management_routing._process_reconcile_lock():
                entered.set()
                await asyncio.Future()

        task = asyncio.create_task(holder())
        try:
            if cancel_while == "holding":
                await asyncio.wait_for(entered.wait(), 2)
            else:
                await asyncio.sleep(0.02)
                assert not entered.is_set()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert len(list(Path("/proc/self/fd").iterdir())) == baseline
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        async with management_routing._process_reconcile_lock():
            pass

    asyncio.run(run())


def test_management_process_lock_rejects_symlink_without_touching_target(tmp_path, monkeypatch):
    target = tmp_path / "unrelated"
    target.write_text("preserve")
    path = tmp_path / "management.lock"
    path.symlink_to(target)
    monkeypatch.setattr(management_routing, "LOCK_PATH", path)

    async def run():
        with pytest.raises(
            management_routing.ManagementRoutingError, match="^management_lock_unavailable$"
        ):
            async with management_routing._process_reconcile_lock():
                pytest.fail("followed an unsafe lock path")

    asyncio.run(run())
    assert target.read_text() == "preserve"
