import asyncio
import base64
import json
import time

import pytest

from exitlane import cli
from exitlane.services.provider_wireguard import (
    EgressConfig,
    ProviderWireGuard,
    ProviderWireGuardError,
)

PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode()
PEER_KEY = base64.b64encode(bytes(range(1, 33))).decode()


def config(**changes):
    values = {
        "provider_id": "mullvad",
        "generation": "0123456789abcdef",
        "interface": "wg-mullvad",
        "private_key": PRIVATE_KEY,
        "address": "10.67.12.34/32",
        "peer_public_key": PEER_KEY,
        "endpoint_address": "193.138.218.78",
        "dns_address": "10.64.0.1",
        "endpoint_port": 51820,
        "mtu": 1380,
    }
    values.update(changes)
    return EgressConfig(**values)


class Runner:
    def __init__(self):
        self.calls = []
        self.interface = False
        self.handshake = 0
        self.source_rules = []

    async def __call__(self, *args, timeout):
        self.calls.append(args)
        if args[:2] == ("ip", "-j"):
            if args[2:] == ("-4", "rule", "show"):
                return (
                    0,
                    json.dumps(
                        [
                            {"priority": 0, "src": "all", "table": "local", "protocol": "kernel"},
                            *self.source_rules,
                        ]
                    ),
                    "",
                )
            if "address" in args:
                return (
                    0,
                    json.dumps(
                        [
                            {
                                "addr_info": [
                                    {"family": "inet", "local": "198.18.0.254", "prefixlen": 15}
                                ]
                            }
                        ]
                    ),
                    "",
                )
            return 0, json.dumps([]), ""
        if args[:7] == ("ip", "-4", "rule", "add", "priority", "0", "from"):
            self.source_rules.append(
                {"priority": 0, "src": args[7], "table": 51820, "protocol": 196}
            )
            return 0, "", ""
        if args[:5] == ("ip", "link", "show", "dev", "wg-mullvad"):
            return (0 if self.interface else 1), "", ""
        if args[:2] == ("wg-quick", "up"):
            self.interface = True
            return 0, "", ""
        if args[:2] == ("wg-quick", "down"):
            self.interface = False
            return 0, "", ""
        if args[:4] == ("ip", "-4", "route", "get"):
            return 0, "1.1.1.1 dev wg-mullvad table 51820", ""
        if args[0] == "ip" and args[1] in {"-4", "-6"} and args[2:4] == ("rule", "del"):
            return 1, "", "not found"
        if args[:3] == ("wg", "show", "wg-mullvad"):
            if args[3] == "endpoints":
                return 0, f"{PEER_KEY}\t193.138.218.78:51820\n", ""
            return 0, f"{PEER_KEY}\t{self.handshake}\n", ""
        return 0, "", ""


def test_configuration_rejects_non_host_address_private_endpoint_and_bad_key():
    for invalid in (
        config(address="10.67.12.34/24"),
        config(endpoint_address="192.168.1.1"),
        config(peer_public_key="not-a-key"),
        config(interface="this-interface-is-too-long"),
    ):
        with pytest.raises(ProviderWireGuardError, match="provider_egress_configuration_invalid"):
            invalid.validated()


def test_start_owns_only_provider_interface_and_ingress_policy(tmp_path):
    runner = Runner()

    async def dns_probe(*_args):
        return True

    service = ProviderWireGuard(runner, root=tmp_path, dns_probe=dns_probe)

    asyncio.run(service.start(config(), ("wg0", "lan0")))

    rendered = (tmp_path / "wg-mullvad.conf").read_text()
    assert "Table = off" in rendered
    assert "AllowedIPs = 0.0.0.0/0" in rendered
    assert "Address = 10.67.12.34/32" in rendered
    assert (tmp_path / "wg-mullvad.conf").stat().st_mode & 0o777 == 0o600
    assert ("wg-quick", "up", str(tmp_path / "wg-mullvad.conf")) in runner.calls
    assert any(
        call[:8] == ("ip", "-4", "rule", "add", "priority", "20000", "iif", "wg0")
        for call in runner.calls
    )
    assert any(
        call[:8] == ("ip", "-4", "rule", "add", "priority", "20000", "iif", "lan0")
        for call in runner.calls
    )


def test_start_rejects_egress_interface_as_ingress_before_any_mutation(tmp_path):
    runner = Runner()
    root = tmp_path / "provider-egress"
    service = ProviderWireGuard(runner, root=root)

    with pytest.raises(ProviderWireGuardError, match="provider_egress_configuration_invalid"):
        asyncio.run(service.start(config(), ("wg0", "wg-mullvad")))

    assert runner.calls == []
    assert not root.exists()


def test_probe_requires_dataplane_and_exact_peer_handshake(tmp_path):
    runner = Runner()
    runner.interface = True

    async def dns_probe(*_args):
        return True

    service = ProviderWireGuard(runner, root=tmp_path, dns_probe=dns_probe)

    assert asyncio.run(service.probe(config()))["ready"] is False
    runner.handshake = int(time.time())
    assert asyncio.run(service.probe(config())) == {
        "ready": True,
        "handshake": runner.handshake,
        "dataplane": True,
        "dns": True,
        "peer_matches": True,
    }


def test_observe_does_not_generate_probe_traffic(tmp_path):
    runner = Runner()
    runner.interface = True
    runner.handshake = int(time.time())
    service = ProviderWireGuard(runner, root=tmp_path)

    assert asyncio.run(service.observe(config()))["connected"] is True
    assert not any(call[0] == "ping" for call in runner.calls)


def test_observe_rejects_stale_handshake(tmp_path):
    runner = Runner()
    runner.interface = True
    runner.handshake = int(time.time()) - 181
    service = ProviderWireGuard(runner, root=tmp_path)

    assert asyncio.run(service.observe(config()))["connected"] is False


def test_dns_failure_prevents_readiness(tmp_path):
    runner = Runner()
    runner.interface = True
    runner.handshake = int(time.time())

    async def dns_probe(*_args):
        return False

    service = ProviderWireGuard(runner, root=tmp_path, dns_probe=dns_probe)
    result = asyncio.run(service.probe(config()))

    assert result["dataplane"] is True
    assert result["peer_matches"] is True
    assert result["dns"] is False
    assert result["ready"] is False


def test_rearm_keeps_existing_owned_rules_without_delete_or_duplicate(tmp_path):
    runner = Runner()

    async def existing(*args, timeout):
        runner.calls.append(args)
        if args[:2] == ("ip", "-j") and args[-2:] == ("rule", "show"):
            family = args[2]
            rules = [
                {
                    "priority": 20000,
                    "iif": "wg0",
                    "table": 51820,
                    "protocol": 196,
                },
            ]
            if family == "-4":
                rules.append(
                    {
                        "priority": 19999,
                        "oif": "wg-mullvad",
                        "table": 51820,
                        "protocol": 196,
                    }
                )
            return 0, json.dumps(rules), ""
        if args[:2] == ("ip", "-j"):
            return 0, "[]", ""
        return 0, "", ""

    service = ProviderWireGuard(existing, root=tmp_path)
    asyncio.run(service.arm(("wg0",), "wg-mullvad"))

    assert not any("del" in call for call in runner.calls)
    assert not any(
        call[:4] in {("ip", "-4", "rule", "add"), ("ip", "-6", "rule", "add")}
        for call in runner.calls
    )


def test_foreign_provider_table_route_is_rejected_before_mutation(tmp_path):
    runner = Runner()

    async def foreign(*args, timeout):
        runner.calls.append(args)
        if args[:5] == ("ip", "-j", "-4", "route", "show"):
            return 0, json.dumps([{"dst": "default", "protocol": "static", "metric": 10}]), ""
        if args[:2] == ("ip", "-j"):
            return 0, "[]", ""
        return 0, "", ""

    service = ProviderWireGuard(foreign, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad"))
    assert not any(call[:4] == ("ip", "-4", "route", "replace") for call in runner.calls)


def test_missing_kernel_route_table_is_empty_during_first_guard_install(tmp_path):
    runner = Runner()

    async def absent(*args, timeout):
        if args[:2] == ("ip", "-j") and args[3:5] == ("route", "show"):
            runner.calls.append(args)
            family = args[2].removeprefix("-")
            return 2, "[]", f"Error: ipv{family}: FIB table does not exist.\nDump terminated\n"
        return await Runner.__call__(runner, *args, timeout=timeout)

    service = ProviderWireGuard(absent, root=tmp_path)
    asyncio.run(service.arm(("wg0",), "wg-mullvad"))

    assert (
        "ip",
        "-4",
        "route",
        "replace",
        "unreachable",
        "default",
        "table",
        "51820",
        "metric",
        "42760",
        "proto",
        "196",
    ) in runner.calls
    assert (
        "ip",
        "-6",
        "route",
        "replace",
        "unreachable",
        "default",
        "table",
        "51820",
        "metric",
        "42760",
        "proto",
        "196",
    ) in runner.calls


def test_route_table_errors_other_than_absence_still_fail_closed(tmp_path):
    async def denied(*args, timeout):
        if args[:2] == ("ip", "-j") and args[3:5] == ("route", "show"):
            return 2, "[]", "RTNETLINK answers: Operation not permitted"
        return 0, "[]", ""

    service = ProviderWireGuard(denied, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_apply_failed"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad"))


def test_ipv6_or_rule_collision_is_rejected_before_any_route_mutation(tmp_path):
    runner = Runner()

    async def foreign(*args, timeout):
        runner.calls.append(args)
        if args[:5] == ("ip", "-j", "-6", "route", "show"):
            return 0, json.dumps([{"dst": "default", "protocol": "static"}]), ""
        if args[:2] == ("ip", "-j"):
            return 0, "[]", ""
        return 0, "", ""

    service = ProviderWireGuard(foreign, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad"))
    assert not any("replace" in call for call in runner.calls)


def test_start_preflight_conflict_performs_no_mutating_cleanup(tmp_path):
    runner = Runner()

    async def foreign(*args, timeout):
        runner.calls.append(args)
        if args[:5] == ("ip", "-j", "-6", "route", "show"):
            return 0, json.dumps([{"dst": "default", "protocol": "static"}]), ""
        if args[:2] == ("ip", "-j"):
            return 0, "[]", ""
        return 0, "", ""

    service = ProviderWireGuard(foreign, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(service.start(config(), ("wg0",)))
    assert all(call[:2] == ("ip", "-j") for call in runner.calls)


def test_rule_with_extra_source_selector_is_not_accepted_as_owned(tmp_path):
    runner = Runner()

    async def restricted(*args, timeout):
        runner.calls.append(args)
        if args[:2] == ("ip", "-j") and args[-2:] == ("rule", "show"):
            return (
                0,
                json.dumps(
                    [
                        {
                            "priority": 20000,
                            "src": "192.0.2.0/24",
                            "iif": "wg0",
                            "table": "51820",
                            "protocol": "196",
                        }
                    ]
                ),
                "",
            )
        if args[:2] == ("ip", "-j"):
            return 0, "[]", ""
        return 0, "", ""

    service = ProviderWireGuard(restricted, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad"))
    assert not any("replace" in call for call in runner.calls)


def test_boot_guard_arms_unreachable_provider_table_for_persisted_active_tunnel(monkeypatch):
    calls = []

    class Guard:
        async def arm(self, ingress, egress, *, source_address=None):
            calls.append((tuple(ingress), egress, source_address))

    monkeypatch.setattr(
        cli.provider_secrets,
        "load",
        lambda provider_id: {"active": {}, "ipv4_address": "10.67.12.34/32"},
    )
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0", "lan0"), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 0
    assert calls == [(("wg0", "lan0"), "wg-mullvad", "10.67.12.34/32")]


def test_boot_guard_is_noop_after_intentional_disconnect(monkeypatch):
    monkeypatch.setattr(
        cli.provider_secrets, "load", lambda provider_id: {"registration": "registered"}
    )

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 0


def test_boot_guard_also_restores_crashed_pending_connection(monkeypatch):
    calls = []

    class Guard:
        async def arm(self, ingress, egress, *, source_address=None):
            calls.append((tuple(ingress), egress, source_address))

    monkeypatch.setattr(
        cli.provider_secrets,
        "load",
        lambda provider_id: {"pending": {}, "ipv4_address": "10.67.12.34/32"},
    )
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0",), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 0
    assert calls == [(("wg0",), "wg-mullvad", "10.67.12.34/32")]


def test_boot_guard_failure_propagates_when_route_and_firewall_guards_fail(monkeypatch):
    class Guard:
        async def arm(self, ingress, egress, *, source_address=None):
            raise ProviderWireGuardError("provider_egress_apply_failed")

    async def fail_firewall():
        raise cli.killswitch.KillswitchError("firewall_apply_failed")

    monkeypatch.setattr(
        cli.provider_secrets,
        "load",
        lambda provider_id: {"pending": {}, "ipv4_address": "10.67.12.34/32"},
    )
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0",), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)
    monkeypatch.setattr(cli.killswitch, "arm_provider_transition", fail_firewall)

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 1


def test_source_guard_precedes_tunnel_start_and_survives_disarm_for_late_host_replies(tmp_path):
    runner = Runner()
    service = ProviderWireGuard(runner, root=tmp_path)
    asyncio.run(service.start(config(), ("wg0",)))
    source_rule = (
        "ip",
        "-4",
        "rule",
        "add",
        "priority",
        "0",
        "from",
        "10.67.12.34/32",
        "table",
        "51820",
        "protocol",
        "196",
    )
    tunnel_up = ("wg-quick", "up", str(tmp_path / "wg-mullvad.conf"))
    assert runner.calls.index(source_rule) < runner.calls.index(tunnel_up)
    assert runner.calls.index(
        (
            "ip",
            "-4",
            "route",
            "replace",
            "unreachable",
            "default",
            "table",
            "51820",
            "metric",
            "42760",
            "proto",
            "196",
        )
    ) < runner.calls.index(source_rule)
    asyncio.run(service.stop_interface("wg-mullvad"))
    asyncio.run(service.disarm(("wg0",), "wg-mullvad"))
    assert runner.source_rules == [
        {
            "priority": 0,
            "src": "10.67.12.34/32",
            "table": 51820,
            "protocol": 196,
        }
    ]
    assert not any("flush" in call for call in runner.calls)
    assert not any("rule" in call and "del" in call and "0" in call for call in runner.calls)


def test_multiple_retired_source_guards_are_preserved_and_rearm_is_idempotent(tmp_path):
    runner = Runner()
    service = ProviderWireGuard(runner, root=tmp_path)
    for source in ("10.67.12.34/32", "10.67.12.35/32", "10.67.12.34/32"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad", source_address=source))
    assert [rule["src"] for rule in runner.source_rules] == ["10.67.12.34/32", "10.67.12.35/32"]
    assert (
        sum(
            call[:7] == ("ip", "-4", "rule", "add", "priority", "0", "from")
            for call in runner.calls
        )
        == 2
    )
    assert not any("del" in call or "flush" in call for call in runner.calls)


@pytest.mark.parametrize(
    "changes",
    [
        {"src": "10.67.12.0/24"},
        {"src": "0.0.0.0/0"},
        {"dst": "1.1.1.1"},
        {"fwmark": "0x1"},
        {"iif": "lo"},
        {"uidrange": "0-0"},
        {"table": 254},
        {"protocol": "static"},
        {"src": "::1/128"},
    ],
)
def test_source_guard_rejects_foreign_or_extra_selectors_at_priority_zero(tmp_path, changes):
    runner = Runner()
    runner.source_rules = [
        {
            "priority": 0,
            "src": "10.67.12.34/32",
            "table": 51820,
            "protocol": 196,
            **changes,
        }
    ]
    service = ProviderWireGuard(runner, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad", source_address="10.67.12.35/32"))
    assert all(call[:2] == ("ip", "-j") for call in runner.calls)


def test_source_guard_refuses_shadowed_builtin_local_without_mutation(tmp_path):
    runner = Runner()

    async def wrong_order(*args, timeout):
        runner.calls.append(args)
        if args == ("ip", "-j", "-4", "rule", "show"):
            return (
                0,
                json.dumps(
                    [
                        {"priority": 0, "src": "10.67.12.35", "table": 51820, "protocol": 196},
                        {"priority": 0, "src": "all", "table": "local", "protocol": "kernel"},
                    ]
                ),
                "",
            )
        return 0, "[]", ""

    service = ProviderWireGuard(wrong_order, root=tmp_path)
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(service.arm(("wg0",), "wg-mullvad", source_address="10.67.12.34/32"))
    assert all(call[:2] == ("ip", "-j") for call in runner.calls)


@pytest.mark.parametrize("interface", ["eth0", "wg0", "lo"])
def test_provider_source_colliding_with_another_local_interface_is_rejected(tmp_path, interface):
    runner = Runner()

    async def collision(*args, timeout):
        if args == ("ip", "-j", "-4", "address", "show"):
            runner.calls.append(args)
            return (
                0,
                json.dumps(
                    [
                        {
                            "ifname": interface,
                            "addr_info": [{"family": "inet", "local": "10.67.12.34"}],
                        }
                    ]
                ),
                "",
            )
        return await runner(*args, timeout=timeout)

    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(ProviderWireGuard(collision, root=tmp_path).start(config(), ("wg0",)))
    assert all(call[:2] == ("ip", "-j") for call in runner.calls)


def test_missing_source_rule_readback_prevents_tunnel_activation(tmp_path):
    runner = Runner()

    async def disappears(*args, timeout):
        result = await runner(*args, timeout=timeout)
        if args[:7] == ("ip", "-4", "rule", "add", "priority", "0", "from"):
            runner.source_rules.clear()
        return result

    with pytest.raises(ProviderWireGuardError, match="provider_egress_source_guard_failed"):
        asyncio.run(ProviderWireGuard(disappears, root=tmp_path).start(config(), ("wg0",)))
    assert not any(call[:2] == ("wg-quick", "up") for call in runner.calls)


def test_forwarding_firewall_fallback_cannot_mask_boot_source_guard_failure(monkeypatch):
    fallbacks = []

    class Guard:
        async def arm(self, ingress, egress, *, source_address=None):
            assert source_address == "10.67.12.34/32"
            raise ProviderWireGuardError("provider_egress_source_guard_failed")

    async def forwarding_only_fallback():
        fallbacks.append(True)

    monkeypatch.setattr(
        cli.provider_secrets,
        "load",
        lambda _: {
            "active": {},
            "ipv4_address": "10.67.12.34/32",
        },
    )
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0",), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)
    monkeypatch.setattr(cli.killswitch, "arm_provider_transition", forwarding_only_fallback)
    assert cli.restore_provider_egress_guard(effective_user_id=0) == 1
    assert fallbacks == [True]


def test_source_only_guard_does_not_arm_ingress_or_probe_policy_during_inactive_signout(tmp_path):
    runner = Runner()

    async def nord_active(*args, timeout):
        result = await runner(*args, timeout=timeout)
        if args == ("ip", "-j", "-4", "rule", "show"):
            rules = json.loads(result[1])
            # An unrelated high-priority slot belongs to the current provider.
            rules.append({"priority": 20000, "iif": "wg0", "table": 51821, "protocol": "static"})
            return 0, json.dumps(rules), ""
        return result

    service = ProviderWireGuard(nord_active, root=tmp_path)
    asyncio.run(service.arm_source("wg-mullvad", "10.67.12.34/32"))
    mutations = [call for call in runner.calls if call[:2] != ("ip", "-j")]
    assert not any("iif" in call or "oif" in call for call in mutations)
    assert not any("del" in call or "flush" in call for call in mutations)
    assert len(runner.source_rules) == 1


def test_disarm_rejects_foreign_ipv6_unreachable_metric_before_any_mutation(tmp_path):
    runner = Runner()
    foreign_route = {
        "dst": "default",
        "type": "unreachable",
        "metric": 42760,
        "protocol": "static",
    }

    async def foreign(*args, timeout):
        if args == ("ip", "-j", "-6", "route", "show", "table", "51820"):
            runner.calls.append(args)
            return 0, json.dumps([foreign_route]), ""
        return await runner(*args, timeout=timeout)

    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(ProviderWireGuard(foreign, root=tmp_path).disarm(("wg0",), "wg-mullvad"))
    assert all(call[:2] == ("ip", "-j") for call in runner.calls)
    assert foreign_route["protocol"] == "static"


@pytest.mark.parametrize(
    "direction,interface,priority",
    [
        ("iif", "wg0", 20000),
        ("oif", "wg-mullvad", 19999),
    ],
)
@pytest.mark.parametrize("extra", [{"src": "192.0.2.0/24"}, {"fwmark": "0x1"}, {"dst": "1.1.1.1"}])
def test_disarm_does_not_delete_foreign_rules_with_extra_selectors(
    tmp_path,
    direction,
    interface,
    priority,
    extra,
):
    runner = Runner()

    async def foreign(*args, timeout):
        if args == ("ip", "-j", "-4", "rule", "show"):
            runner.calls.append(args)
            return (
                0,
                json.dumps(
                    [
                        {
                            "priority": priority,
                            direction: interface,
                            "table": 51820,
                            "protocol": 196,
                            **extra,
                        }
                    ]
                ),
                "",
            )
        return await runner(*args, timeout=timeout)

    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(ProviderWireGuard(foreign, root=tmp_path).disarm(("wg0",), "wg-mullvad"))
    assert all(call[:2] == ("ip", "-j") for call in runner.calls)


def test_disarm_ignores_other_provider_slots_and_removes_exact_detached_owned_rules(tmp_path):
    runner = Runner()

    async def mixed(*args, timeout):
        if args == ("ip", "-j", "-4", "rule", "show"):
            runner.calls.append(args)
            return (
                0,
                json.dumps(
                    [
                        {
                            "priority": 20000,
                            "iif": "wg0",
                            "table": 51821,
                            "protocol": "static",
                            "fwmark": "0x1",
                        },
                        {
                            "priority": 19999,
                            "oif": "wg-mullvad",
                            "oif_detached": True,
                            "table": 51820,
                            "protocol": 196,
                        },
                    ]
                ),
                "",
            )
        return await runner(*args, timeout=timeout)

    asyncio.run(ProviderWireGuard(mixed, root=tmp_path).disarm(("wg0",), "wg-mullvad"))
    assert not any("51821" in call or "static" in call for call in runner.calls)
    assert (
        "ip",
        "-4",
        "rule",
        "del",
        "priority",
        "19999",
        "oif",
        "wg-mullvad",
        "table",
        "51820",
        "protocol",
        "196",
    ) in runner.calls
