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

    async def __call__(self, *args, timeout):
        self.calls.append(args)
        if args[:2] == ("ip", "-j"):
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
        if args[:4] == ("ip", "-4", "rule", "del"):
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
        async def arm(self, ingress, egress):
            calls.append((tuple(ingress), egress))

    monkeypatch.setattr(cli.provider_secrets, "load", lambda provider_id: {"active": {}})
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0", "lan0"), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 0
    assert calls == [(("wg0", "lan0"), "wg-mullvad")]


def test_boot_guard_is_noop_after_intentional_disconnect(monkeypatch):
    monkeypatch.setattr(
        cli.provider_secrets, "load", lambda provider_id: {"registration": "registered"}
    )

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 0


def test_boot_guard_also_restores_crashed_pending_connection(monkeypatch):
    calls = []

    class Guard:
        async def arm(self, ingress, egress):
            calls.append((tuple(ingress), egress))

    monkeypatch.setattr(cli.provider_secrets, "load", lambda provider_id: {"pending": {}})
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0",), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 0
    assert calls == [(("wg0",), "wg-mullvad")]


def test_boot_guard_failure_propagates_when_route_and_firewall_guards_fail(monkeypatch):
    class Guard:
        async def arm(self, ingress, egress):
            raise ProviderWireGuardError("provider_egress_apply_failed")

    async def fail_firewall():
        raise cli.killswitch.KillswitchError("firewall_apply_failed")

    monkeypatch.setattr(cli.provider_secrets, "load", lambda provider_id: {"pending": {}})
    monkeypatch.setattr(cli.killswitch, "configuration", lambda: (("wg0",), ()))
    monkeypatch.setattr(cli, "ProviderWireGuard", Guard)
    monkeypatch.setattr(cli.killswitch, "arm_provider_transition", fail_firewall)

    assert cli.restore_provider_egress_guard(effective_user_id=0) == 1
