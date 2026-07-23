from __future__ import annotations

import asyncio

import pytest

from exitlane import core
from exitlane.services import killswitch
from exitlane.providers import nordvpn


class FakeNft:
    def __init__(self, *, fail_check: bool = False, fail_apply: bool = False):
        self.installed = False
        self.fail_check = fail_check
        self.fail_apply = fail_apply
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self.loaded: list[str] = []
        self.ruleset = ""

    async def __call__(self, *arguments, timeout=0, input_text=None):
        self.calls.append((arguments, input_text))
        if arguments[:4] == ("nft", "list", "table", "inet"):
            return (0, self.ruleset, "") if self.installed else (1, "", "not found")
        if "-f" in arguments:
            path = arguments[-1]
            rules = open(path, encoding="utf-8").read()  # noqa: SIM115
            if "-c" in arguments:
                return (1, "", "syntax") if self.fail_check else (0, "", "")
            if self.fail_apply:
                return 1, "", "apply"
            self.loaded.append(rules)
            self.ruleset = rules
            self.installed = "destroy table inet exitlane_killswitch\n" not in rules
            if "table inet exitlane_killswitch {" in rules:
                self.installed = True
            return 0, "", ""
        return 127, "", "unexpected"


@pytest.fixture(autouse=True)
def database(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA", tmp_path)
    monkeypatch.setattr(core, "DB", tmp_path / "exitlane.db")
    core.init()


def facts(**changes):
    values = {
        "available": True,
        "interface": "vpn0",
        "supports_ipv4": True,
        "supports_ipv6": False,
        "protected_egress": True,
        "reason": "tunnel_available",
    }
    values.update(changes)
    return killswitch.TunnelFacts(**values)


def test_rules_cover_ipv4_ipv6_dns_management_and_provider_control():
    rules = killswitch.generate_ruleset(
        facts(), ingress=("wg0", "vlan20"), local_allowlist=("192.168.1.0/24", "fd00::/64")
    )
    assert "hook forward" in rules
    assert 'oifname "vpn0"' in rules
    assert "meta nfproto ipv4" in rules
    assert "meta nfproto ipv6" not in rules
    assert "udp dport 53 drop" in rules and "tcp dport 53 drop" in rules
    assert 'iifname @protected_ingress drop comment "ExitLane fail closed"' in rules
    assert "hook input" not in rules and "hook output" not in rules
    assert "192.168.1.0/24" in rules and "fd00::/64" in rules


def test_unknown_tunnel_is_fail_closed_and_effective():
    runner = FakeNft()
    result = asyncio.run(
            killswitch.enable(
                facts(
                    available=False,
                    interface=None,
                    supports_ipv4=False,
                    protected_egress=False,
                    reason="tunnel_interface_unknown",
                ),
                killswitch.NftBackend(runner),
            )
    )
    assert result.configured and result.effective
    assert result.state == "enabled_degraded"
    assert result.reason == "tunnel_interface_unknown"
    assert 'iifname @protected_ingress drop comment "ExitLane fail closed"' in runner.ruleset
    assert "masquerade" not in runner.ruleset


def test_enable_disable_are_idempotent_and_only_touch_owned_table():
    runner = FakeNft()
    backend = killswitch.NftBackend(runner)
    asyncio.run(killswitch.enable(facts(), backend))
    asyncio.run(killswitch.enable(facts(), backend))
    disabled = asyncio.run(killswitch.disable(backend))
    disabled = asyncio.run(killswitch.disable(backend))
    assert not disabled.configured
    assert runner.loaded
    assert all("exitlane_killswitch" in rules for rules in runner.loaded)
    assert all("flush ruleset" not in rules for rules in runner.loaded)


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "not-a-network", "10.0.0.1/24"])
def test_invalid_or_default_cidr_is_rejected(value):
    with pytest.raises(killswitch.KillswitchError):
        killswitch.validate_allowlist([value])


def test_syntax_or_apply_failure_does_not_enable_setting():
    for runner in (FakeNft(fail_check=True), FakeNft(fail_apply=True)):
        with pytest.raises(killswitch.KillswitchError):
            asyncio.run(killswitch.enable(facts(), killswitch.NftBackend(runner)))
        assert core.setting(killswitch.SETTING_CONFIGURED, False) is False


def test_ipv6_only_released_when_provider_protects_it():
    blocked = killswitch.generate_ruleset(
        facts(supports_ipv6=False), ingress=("wg0",), local_allowlist=()
    )
    released = killswitch.generate_ruleset(
        facts(supports_ipv6=True), ingress=("wg0",), local_allowlist=()
    )
    assert "meta nfproto ipv6" not in blocked
    assert "meta nfproto ipv6" in released


def test_disconnected_tunnel_waits_without_claiming_unknown_interface():
    core.set_setting(killswitch.SETTING_CONFIGURED, True)
    firewall = FakeNft()
    firewall.installed = True
    firewall.ruleset = "table inet exitlane_killswitch {}"

    result = asyncio.run(
        killswitch.status(
            killswitch.TunnelFacts(False, reason="tunnel_unavailable"),
            killswitch.NftBackend(firewall),
        )
    )

    assert result.state == "enabled_waiting_for_tunnel"
    assert result.reason == "tunnel_unavailable"
    assert result.effective is True


def test_nordvpn_fails_closed_when_official_status_omits_technology(monkeypatch):
    async def status(*, timeout=8):
        return {"connected": True, "technology": ""}

    provider = nordvpn.NordVPN()
    monkeypatch.setattr(provider, "status", status)
    result = asyncio.run(provider.network_facts())
    assert not result.available
    assert result.interface is None
    assert result.reason == "tunnel_interface_unknown"
