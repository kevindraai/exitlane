from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from exitlane import cli, core
from exitlane.providers import nordvpn
from exitlane.services import killswitch


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
            rules = Path(path).read_text(encoding="utf-8")
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
    monkeypatch.setattr(core, "WG_DIR", tmp_path / "wireguard")
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
    assert rules.index('iifname @protected_ingress drop comment "ExitLane fail closed"') < (
        rules.index('ct state established,related accept comment "ExitLane return traffic"')
    )


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


def test_provider_transition_is_persisted_and_blocks_only_forwarded_ingress():
    runner = FakeNft()
    result = asyncio.run(killswitch.arm_provider_transition(killswitch.NftBackend(runner)))

    assert core.setting(killswitch.SETTING_TRANSITION) is True
    assert core.setting(killswitch.SETTING_CONFIGURED, False) is False
    assert result.state == "enabled_transition"
    assert result.effective is True
    assert 'iifname @protected_ingress drop comment "ExitLane fail closed"' in runner.ruleset
    assert "hook input" not in runner.ruleset
    assert "hook output" not in runner.ruleset
    assert "masquerade" not in runner.ruleset


def test_provider_transition_cannot_be_released_by_normal_reconcile():
    runner = FakeNft()
    backend = killswitch.NftBackend(runner)
    asyncio.run(killswitch.arm_provider_transition(backend))

    result = asyncio.run(killswitch.reconcile(facts(), backend))

    assert result.state == "enabled_transition"
    assert core.setting(killswitch.SETTING_TRANSITION) is True
    assert 'oifname "vpn0"' not in runner.ruleset
    assert "masquerade" not in runner.ruleset

    enabled = asyncio.run(killswitch.enable(facts(), backend))
    assert enabled.state == "enabled_transition"
    assert core.setting(killswitch.SETTING_CONFIGURED) is True
    assert 'oifname "vpn0"' not in runner.ruleset
    assert "masquerade" not in runner.ruleset


@pytest.mark.parametrize("configured", [False, True])
def test_completed_provider_transition_converges_to_operator_killswitch_policy(configured):
    runner = FakeNft()
    backend = killswitch.NftBackend(runner)
    core.set_setting(killswitch.SETTING_CONFIGURED, configured)
    asyncio.run(killswitch.arm_provider_transition(backend))

    result = asyncio.run(killswitch.complete_provider_transition(facts(), backend))

    assert core.setting(killswitch.SETTING_TRANSITION) is False
    if configured:
        assert result.state == "enabled_protected"
        assert runner.installed is True
        assert 'oifname "vpn0"' in runner.ruleset
    else:
        assert result.state == "disabled"
        assert runner.installed is False


def test_failed_transition_arm_remains_persisted_for_fail_closed_boot_restore():
    runner = FakeNft(fail_apply=True)

    with pytest.raises(killswitch.KillswitchError):
        asyncio.run(killswitch.arm_provider_transition(killswitch.NftBackend(runner)))

    assert core.setting(killswitch.SETTING_TRANSITION) is True


class InterleavingFirewall:
    def __init__(self):
        self.first_apply_started = asyncio.Event()
        self.release_first_apply = asyncio.Event()
        self.apply_count = 0
        self.installed_value = True
        self.last_ruleset = ""

    async def apply(self, ruleset):
        self.apply_count += 1
        if self.apply_count == 1:
            self.first_apply_started.set()
            await self.release_first_apply.wait()
        self.installed_value = True
        self.last_ruleset = ruleset

    async def remove(self):
        self.installed_value = False
        self.last_ruleset = ""

    async def installed(self):
        return self.installed_value


def test_late_reconcile_cannot_overwrite_newer_transition_arm():
    async def scenario():
        core.set_setting(killswitch.SETTING_CONFIGURED, True)
        firewall = InterleavingFirewall()
        reconcile = asyncio.create_task(killswitch.reconcile(facts(), firewall))
        await firewall.first_apply_started.wait()
        arm = asyncio.create_task(killswitch.arm_provider_transition(firewall))
        await asyncio.sleep(0)
        firewall.release_first_apply.set()
        await asyncio.gather(reconcile, arm)
        return firewall

    firewall = asyncio.run(scenario())

    assert core.setting(killswitch.SETTING_TRANSITION) is True
    assert "masquerade" not in firewall.last_ruleset
    assert 'iifname @protected_ingress drop comment "ExitLane fail closed"' in (
        firewall.last_ruleset
    )


def test_late_reconcile_cannot_overwrite_newer_transition_completion():
    async def scenario():
        core.set_setting(killswitch.SETTING_TRANSITION, True)
        firewall = InterleavingFirewall()
        reconcile = asyncio.create_task(killswitch.reconcile(facts(), firewall))
        await firewall.first_apply_started.wait()
        complete = asyncio.create_task(killswitch.complete_provider_transition(facts(), firewall))
        await asyncio.sleep(0)
        firewall.release_first_apply.set()
        await asyncio.gather(reconcile, complete)
        return firewall

    firewall = asyncio.run(scenario())

    assert core.setting(killswitch.SETTING_TRANSITION) is False
    assert firewall.installed_value is False
    assert firewall.last_ruleset == ""


def test_boot_restore_rearms_persisted_provider_transition(monkeypatch):
    calls = []
    core.set_setting(killswitch.SETTING_TRANSITION, True)

    async def arm_provider_transition():
        calls.append("armed")

    monkeypatch.setattr(killswitch, "arm_provider_transition", arm_provider_transition)

    assert cli.restore_killswitch(effective_user_id=0) == 0
    assert calls == ["armed"]


def test_nordvpn_fails_closed_when_official_status_omits_technology(monkeypatch):
    async def status(*, timeout=8):
        return {"connected": True, "technology": ""}

    provider = nordvpn.NordVPN()
    monkeypatch.setattr(provider, "status", status)
    result = asyncio.run(provider.network_facts())
    assert not result.available
    assert result.interface is None
    assert result.reason == "tunnel_interface_unknown"
