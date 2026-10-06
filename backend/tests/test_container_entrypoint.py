"""Parent ingress ownership and sole-live-worker policy boundaries."""

import asyncio
import base64
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_container_runtime import Namespace, config

from exitlane.container_entrypoint import ContainerController, ContainerEntrypoint, EntrypointError
from exitlane.container_runtime import ContainerLifecycleError
from exitlane.providers.wireguard_keys import _public_key_for_private
from exitlane.services.provider_wireguard import EgressConfig


def test_already_guarded_activation_does_not_reset_worker_proof():
    ns = Namespace()
    ns.guard_exists = True
    network = ns.network
    candidate, proof, committed = object(), object(), object()
    network.policy_epoch = 72
    network.policy_candidate, network.policy_proof, network.policy_committed = (
        candidate,
        proof,
        committed,
    )
    asyncio.run(network.activate_already_guarded(network.observe_guard))
    assert network.active
    assert network.policy_epoch == 72
    assert network.policy_candidate is candidate
    assert network.policy_proof is proof
    assert network.policy_committed is committed
    assert not any(
        command[0] in {"guard"} or command[:2] == ("nft", "-f") for command in ns.commands
    )


def test_already_guarded_activation_fails_before_creation_on_unproven_guard():
    ns = Namespace()

    async def refuse():
        raise ContainerLifecycleError("container_guard_unproven")

    with pytest.raises(ContainerLifecycleError, match="guard_unproven"):
        asyncio.run(ns.network.activate_already_guarded(refuse))
    assert not ns.exists


def test_parent_owned_ifindex_observation_has_no_policy_cache_dependency():
    ns = Namespace()
    asyncio.run(ns.network.activate())
    ns.bad_observation = True
    assert asyncio.run(ns.network.observe_owned_ingress()) is True
    ns.ifindex += 1
    with pytest.raises(ContainerLifecycleError, match="ownership_changed"):
        asyncio.run(ns.network.observe_owned_ingress())


class Maintenance:
    def __init__(self):
        self.identities = ()
        self.active = True
        self.calls = []

    async def observed(self, identities):
        self.calls.append(("observed", identities))

    async def arm(self, identities):
        self.identities = identities
        self.calls.append(("arm", identities))

    async def release(self):
        self.calls.append(("release",))


def test_first_run_controller_has_no_fabricated_ingress():
    maintenance = Maintenance()
    controller = ContainerController(SimpleNamespace(), maintenance)
    assert controller.network is None
    asyncio.run(controller.observe_policy())
    assert maintenance.calls == [("observed", ())]


@pytest.mark.parametrize("phase", ["fresh_initialization", "interrupted_publication"])
def test_empty_namespace_reset_does_not_read_unpublished_pair(phase):
    calls = []

    async def absent(*argv, **kwargs):
        calls.append(argv)
        return 1, "", ""

    def unpublished():
        pytest.fail("reset must not inspect the unpublished pair: " + phase)

    state = SimpleNamespace(validate=unpublished)
    maintenance = Maintenance()
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.state = state
    entry.controller = ContainerController(state, maintenance, runner=absent)
    asyncio.run(entry.reset())
    assert [command[-1] for command in calls] == ["wg-mullvad", "wg-pia", "wg-proton"]
    assert maintenance.calls == [("observed", ())]


def test_ingress_revoked_lease_refuses_before_file_or_network_access():
    controller = ContainerController(
        SimpleNamespace(), Maintenance(), operation_valid=lambda: False
    )
    with pytest.raises(EntrypointError, match="lease_revoked"):
        asyncio.run(controller.ingress({"action": "activate", "interface": "wg-office"}))


def test_ingress_deactivate_uses_owned_interface_and_keeps_guard(monkeypatch):
    config = SimpleNamespace(interface="wg-office", address="10.77.0.1/24")
    calls = []

    class OwnedNetwork:
        def __init__(self):
            self.config = config

        async def deactivate(self):
            calls.append("deactivate")

    maintenance = Maintenance()
    controller = ContainerController(SimpleNamespace(), maintenance)
    controller.network = OwnedNetwork()

    async def observe_policy(**_kwargs):
        calls.append("guard-observed")

    monkeypatch.setattr(controller, "observe_policy", observe_policy)
    with pytest.raises(EntrypointError, match="config_invalid"):
        asyncio.run(controller.ingress({"action": "deactivate", "interface": "wg-other"}))
    assert calls == []
    assert asyncio.run(controller.ingress({"action": "deactivate", "interface": "wg-office"})) == {
        "active": False
    }
    assert calls == ["deactivate", "guard-observed"]
    assert maintenance.calls[0][0] == "arm"
    assert not any(call[0] == "release" for call in maintenance.calls)


def test_rolled_back_first_ingress_accepts_changed_identity_under_guard(monkeypatch, tmp_path):
    from exitlane import container_runtime

    old = SimpleNamespace(interface="wg-office", address="10.77.0.1/24")
    changed = SimpleNamespace(interface="wg-retry", address="10.88.0.1/24")
    calls = []

    class Network:
        def __init__(self, config, *, runner=None):
            self.config = config
            self.active = config is old

        async def deactivate(self):
            calls.append(("deactivate", self.config.interface))
            self.active = False

        async def activate_already_guarded(self, observer):
            await observer()
            self.active = True

        async def observe_owned_ingress(self):
            return self.active

    maintenance = Maintenance()
    controller = ContainerController(
        SimpleNamespace(layout=SimpleNamespace(wireguard=tmp_path)), maintenance
    )
    controller.network = Network(old)

    async def observe_policy(*, config=None):
        calls.append(("observe", config.interface))

    monkeypatch.setattr(controller, "observe_policy", observe_policy)
    monkeypatch.setattr(container_runtime, "ContainerWireGuardLifecycle", Network)
    monkeypatch.setattr(
        container_runtime.IngressConfig, "from_file", classmethod(lambda cls, _path: changed)
    )
    with pytest.raises(EntrypointError, match="config_invalid"):
        asyncio.run(controller.ingress({"action": "activate", "interface": "wg-retry"}))
    assert asyncio.run(controller.ingress({"action": "deactivate", "interface": "wg-office"})) == {
        "active": False
    }
    assert asyncio.run(controller.ingress({"action": "activate", "interface": "wg-retry"})) == {
        "active": True
    }
    assert ("observe", "wg-office") in calls
    assert {item.interface for item in maintenance.identities} == {"wg-office", "wg-retry"}
    assert asyncio.run(controller.ingress({"action": "observe", "interface": "wg-retry"})) == {
        "active": True
    }
    assert controller.initial_rollback_ready is False
    assert ("release",) in maintenance.calls


def test_failed_initial_guard_before_publication_retries_with_no_cached_network(monkeypatch):
    from exitlane.container_runtime import ContainerLifecycleError

    config = SimpleNamespace(interface="wg-office", address="10.77.0.1/24")
    network = SimpleNamespace(config=config, active=False, uncertain_creation=False)

    async def deactivate():
        return None

    network.deactivate = deactivate

    async def absent(*_args, **_kwargs):
        return 1, "", ""

    controller = ContainerController(SimpleNamespace(), Maintenance(), runner=absent)
    controller.network = network

    async def missing_guard(*, config=None):
        raise ContainerLifecycleError("container_guard_unproven")

    async def no_table(*_args):
        return '{"nftables":[]}'

    monkeypatch.setattr(controller, "observe_policy", missing_guard)
    monkeypatch.setattr(controller, "checked", no_table)

    async def retired(_observer, _interface):
        return None

    monkeypatch.setattr(controller, "retire_recovered_selector", retired)
    assert asyncio.run(controller.ingress({"action": "deactivate", "interface": "wg-office"})) == {
        "active": False
    }
    assert controller.network is None
    assert controller.initial_rollback_ready is True


def test_first_nft_preflight_failure_retires_owned_selector_before_changed_retry(
    monkeypatch, tmp_path
):
    """An RPDB write before first nft publication cannot poison the next setup."""
    from exitlane import container_runtime
    from exitlane.services.provider_wireguard import RULE_PRIORITY, TABLE_ID

    old_config = config()
    new_config = replace(
        old_config,
        interface="wg-retry",
        address="10.89.0.1/24",
        allowed_ips="10.89.0.2/32",
    )
    ns = ActiveResetNamespace(detached=False)
    ns.guard_exists = False
    ns.network.source_addresses = ()
    ns.routes[4] = [row for row in ns.routes[4] if row.get("dev") is None]
    ns.rules = {
        family: [
            row
            for row in rows
            if row.get("iif") is None
            and row.get("oif") is None
            and row.get("src") not in ("10.64.0.2", "10.65.0.2")
        ]
        for family, rows in ns.rules.items()
    }
    ns.live = False
    fail_nft_check = True
    link = None
    selected = old_config
    lifecycle = container_runtime.ContainerWireGuardLifecycle

    async def runner(*args, **kwargs):
        nonlocal fail_nft_check, link
        if (
            args[:3] == ("nft", "-j", "list")
            and args[-2:] == ("inet", "exitlane_container_guard")
            and not ns.guard_exists
        ):
            return 1, "", ""
        if args[:3] == ("nft", "-c", "-f") and fail_nft_check:
            fail_nft_check = False
            return 1, "", ""
        if args[:3] == ("nft", "-f", "/dev/stdin"):
            ns.network = lifecycle(new_config, runner=runner)
            ns.guard_exists = True
        if args[:3] == ("ip", "link", "show") and args[-2] == "dev":
            return (0 if link == args[-1] else 1), "", ""
        if args[:4] == ("ip", "-j", "link", "show"):
            return (
                (0, json.dumps([{"ifname": link, "ifindex": 101}]), "")
                if link == args[-1]
                else (1, "", "")
            )
        if args[:4] == ("ip", "link", "add", "dev"):
            link = args[-3]
        if args[:4] == ("ip", "link", "delete", "dev"):
            link = None
        return await ns.run(*args, **kwargs)

    monkeypatch.setattr(
        container_runtime,
        "ContainerWireGuardLifecycle",
        lambda value, **_kwargs: lifecycle(value, runner=runner),
    )
    monkeypatch.setattr(
        container_runtime.IngressConfig,
        "from_file",
        classmethod(lambda _cls, _path: selected),
    )
    maintenance = Maintenance()
    controller = ContainerController(
        SimpleNamespace(layout=SimpleNamespace(wireguard=tmp_path)),
        maintenance,
        runner=runner,
    )
    with pytest.raises(ContainerLifecycleError, match="container_network_command_failed"):
        asyncio.run(controller.ingress({"action": "activate", "interface": old_config.interface}))
    assert not ns.guard_exists
    assert all(
        any(
            row.get("iif") == old_config.interface
            and row.get("priority") == RULE_PRIORITY
            and row.get("table") == TABLE_ID
            for row in ns.rules[family]
        )
        for family in (4, 6)
    )
    assert asyncio.run(
        controller.ingress({"action": "deactivate", "interface": old_config.interface})
    ) == {"active": False}
    assert controller.network is None
    assert all(
        not any(row.get("iif") == old_config.interface for row in ns.rules[family])
        for family in (4, 6)
    )
    selected = new_config
    assert asyncio.run(
        controller.ingress({"action": "activate", "interface": new_config.interface})
    ) == {"active": True}
    assert asyncio.run(
        controller.ingress({"action": "observe", "interface": new_config.interface})
    ) == {"active": True}
    assert controller.network.active
    assert ("release",) in maintenance.calls


def test_new_namespace_reset_observes_persisted_ingress_maintenance_selectors():
    from exitlane.container_recovery import IngressIdentity

    maintenance = Maintenance()
    maintenance.identities = (IngressIdentity("wg-office", "10.77.0.0/24"),)
    controller = ContainerController(SimpleNamespace(), maintenance)
    asyncio.run(controller.reset_policy())
    assert maintenance.calls == [("observed", maintenance.identities)]


def test_ingress_observe_cannot_release_maintenance_after_lease_revocation(monkeypatch, tmp_path):
    from exitlane.container_runtime import IngressConfig

    ns = Namespace()
    valid = True
    maintenance = Maintenance()
    controller = ContainerController(
        SimpleNamespace(layout=SimpleNamespace(wireguard=tmp_path)),
        maintenance,
        operation_valid=lambda: valid,
    )
    controller.network = ns.network
    monkeypatch.setattr(IngressConfig, "from_file", lambda _path: ns.network.config)

    async def observed(**kwargs):
        nonlocal valid
        valid = False

    async def owned():
        return True

    monkeypatch.setattr(controller, "observe_policy", observed)
    monkeypatch.setattr(ns.network, "observe_owned_ingress", owned)
    with pytest.raises(EntrypointError, match="lease_revoked"):
        asyncio.run(
            controller.ingress({"action": "observe", "interface": ns.network.config.interface})
        )
    assert ("release",) not in maintenance.calls


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"action": "shell", "interface": "wg-office"},
        {"action": "activate", "interface": "../host"},
        {"action": "activate", "interface": "wg-office", "config": "secret"},
    ],
)
def test_ingress_rpc_rejects_raw_config_and_hostile_names(payload):
    controller = ContainerController(SimpleNamespace(), Maintenance())
    with pytest.raises(EntrypointError, match="config_invalid"):
        asyncio.run(controller.ingress(payload))


def provider_config():
    key = base64.b64encode(bytes(range(32))).decode()
    peer = base64.b64encode(bytes(range(1, 33))).decode()
    return EgressConfig(
        "mullvad",
        "synthetic-generation",
        "wg-mullvad",
        key,
        "10.64.0.2/32",
        peer,
        "192.0.0.9",
        "10.64.0.1",
    )


@pytest.mark.parametrize("mismatch", [None, "public", "peer", "address", "index", "kind"])
def test_reset_removes_only_generation_proven_provider_interface(mismatch):
    config = provider_config()
    calls = []
    reads = 0

    async def runner(*argv, **_kwargs):
        nonlocal reads
        calls.append(argv)
        if argv[:5] == ("ip", "-j", "-d", "link", "show"):
            if argv[-1] != "wg-mullvad":
                return 1, "", ""
            return (
                0,
                json.dumps(
                    [
                        {
                            "ifname": "wg-mullvad",
                            "ifindex": 7,
                            "linkinfo": {
                                "info_kind": "dummy" if mismatch == "kind" else "wireguard"
                            },
                        }
                    ]
                ),
                "",
            )
        if argv[:3] == ("wg", "show", "wg-mullvad"):
            output = {
                "public-key": _public_key_for_private(config.private_key),
                "peers": config.peer_public_key,
                "endpoints": f"{config.peer_public_key}\t{config.endpoint_address}:51820",
            }[argv[-1]]
            if mismatch == "public" and argv[-1] == "public-key":
                output = config.peer_public_key
            if mismatch == "peer" and argv[-1] == "peers":
                output = "synthetic-other-peer"
            return 0, output, ""
        if argv[:4] == ("ip", "-4", "-j", "address"):
            return (
                0,
                json.dumps(
                    [
                        {
                            "addr_info": [
                                {
                                    "family": "inet",
                                    "prefixlen": 32,
                                    "local": "10.64.0.3" if mismatch == "address" else "10.64.0.2",
                                }
                            ]
                        }
                    ]
                ),
                "",
            )
        if argv[:4] == ("ip", "-j", "link", "show"):
            reads += 1
            return 0, json.dumps([{"ifindex": 8 if mismatch == "index" else 7}]), ""
        if argv[:2] == ("ip", "-j") and "show" in argv:
            return 0, "[]", ""
        if "rule" in argv and "del" in argv:
            return 1, "", ""
        return 0, "", ""

    state = SimpleNamespace(
        validate=lambda: SimpleNamespace(intents=(SimpleNamespace(config=config),))
    )
    controller = ContainerController(state, Maintenance(), runner=runner)
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.controller, entry.state = controller, state
    if mismatch:
        with pytest.raises(EntrypointError):
            asyncio.run(entry.reset())
        assert not any(command[:3] == ("ip", "link", "delete") for command in calls)
    else:
        asyncio.run(entry.reset())
        assert ("ip", "link", "delete", "dev", "wg-mullvad") in calls
    assert config.private_key not in str(calls)


class ActiveResetNamespace(Namespace):
    """Real shared route/rule ownership engine over an active synthetic kernel."""

    def __init__(self, *, foreign_route=False, foreign_key=False, detached=True, race=0):
        from exitlane.services.provider_wireguard import (
            PROBE_RULE_PRIORITY,
            ROUTE_PROTOCOL,
            RULE_PRIORITY,
            TABLE_ID,
            UNREACHABLE_METRIC,
            ProviderWireGuard,
        )

        super().__init__()
        self.provider = provider_config()
        self.live = True
        self.foreign_key, self.race, self.reads = foreign_key, race, 0
        self.guard_exists = True
        self.network.policy_interface = "wg-mullvad"
        self.network.probe_interface = "wg-mullvad"
        self.network.source_addresses = ("10.64.0.2", "10.65.0.2")
        self.routes = {
            family: [
                {
                    "type": "unreachable",
                    "dst": "default",
                    "metric": UNREACHABLE_METRIC,
                    "protocol": ROUTE_PROTOCOL,
                }
            ]
            for family in (4, 6)
        }
        self.routes[4].append(
            {
                "dst": "default",
                "dev": "foreign0" if foreign_route else "wg-mullvad",
                "metric": 10,
                "protocol": ROUTE_PROTOCOL,
            }
        )
        self.rules = {
            family: [
                {"priority": 0, "src": "all", "table": "local", "protocol": "kernel"},
                {
                    "priority": RULE_PRIORITY,
                    "src": "all",
                    "iif": "wg-office",
                    "table": TABLE_ID,
                    "protocol": ROUTE_PROTOCOL,
                    **({"iif_detached": True} if detached else {}),
                },
            ]
            for family in (4, 6)
        }
        self.rules[4] += [
            {"priority": 0, "src": source, "table": TABLE_ID, "protocol": ROUTE_PROTOCOL}
            for source in self.network.source_addresses
        ]
        self.rules[4].append(
            {
                "priority": PROBE_RULE_PRIORITY,
                "src": "all",
                "oif": "wg-mullvad",
                "table": TABLE_ID,
                "protocol": ROUTE_PROTOCOL,
            }
        )
        self.network.provider_guard = ProviderWireGuard(self.run)

    def nft(self):
        from exitlane.container_runtime import TABLE

        value = json.loads(super().nft())
        interface = self.network.policy_interface
        if interface:
            value["nftables"].append(
                {
                    "chain": {
                        "family": "inet",
                        "table": TABLE,
                        "name": "postrouting",
                        "type": "nat",
                        "hook": "postrouting",
                        "prio": 100,
                        "policy": "accept",
                    }
                }
            )
            value["nftables"] += [
                {"rule": {"family": "inet", "table": TABLE, "chain": "postrouting", "expr": e}}
                for e in self.network.nat_expressions(interface)
            ]
        return json.dumps(value)

    async def run(self, *args, **kwargs):
        from exitlane.services.provider_wireguard import ROUTE_PROTOCOL

        if args[0] == "ip" and "show" in args and "route" in args:
            self.commands.append(args)
            family = 6 if "-6" in args else 4
            return 0, json.dumps(self.routes[family]), ""
        if args[0] == "ip" and "show" in args and "rule" in args:
            self.commands.append(args)
            family = 6 if "-6" in args else 4
            return 0, json.dumps(self.rules[family]), ""
        if args[0] == "ip" and args[1] in {"-4", "-6"} and args[2] in {"rule", "route"}:
            self.commands.append(args)
            family = int(args[1][-1])
            if args[2:4] == ("rule", "del"):
                priority, direction, interface = int(args[5]), args[6], args[7]
                for rule in self.rules[family]:
                    if (
                        rule.get("priority") == priority
                        and rule.get(direction) == interface
                        and str(rule.get("table")) == args[9]
                        and str(rule.get("protocol")) == args[11]
                    ):
                        self.rules[family].remove(rule)
                        return 0, "", ""
                return 1, "", ""
            if args[2:4] == ("rule", "add"):
                self.rules[family].append(
                    {
                        "priority": int(args[5]),
                        "src": "all",
                        args[6]: args[7],
                        "table": int(args[9]),
                        "protocol": int(args[11]),
                    }
                )
                return 0, "", ""
            if args[2:4] == ("route", "replace"):
                assert args[4] == "unreachable"
                return 0, "", ""  # Already present; never remove historical source rules.
            if args[2:4] == ("route", "del"):
                self.routes[family] = [r for r in self.routes[family] if r.get("dev") != args[6]]
                return 0, "", ""
        if args[0] == "ip" and "link" in args and "show" in args and args[-1].startswith("wg-"):
            self.commands.append(args)
            if args[-1] != "wg-mullvad" or not self.live:
                return 1, "", ""
            self.reads += 1
            index = 8 if self.race and self.reads >= self.race else 7
            return (
                0,
                json.dumps(
                    [
                        {
                            "ifname": "wg-mullvad",
                            "ifindex": index,
                            "linkinfo": {"info_kind": "wireguard"},
                        }
                    ]
                ),
                "",
            )
        if args[:3] == ("wg", "show", "wg-mullvad"):
            self.commands.append(args)
            values = {
                "public-key": self.provider.peer_public_key
                if self.foreign_key
                else _public_key_for_private(self.provider.private_key),
                "peers": self.provider.peer_public_key,
                "endpoints": f"{self.provider.peer_public_key}\t{self.provider.endpoint_address}:51820",
            }
            return 0, values[args[-1]], ""
        if args[:4] == ("ip", "-4", "-j", "address"):
            self.commands.append(args)
            return (
                0,
                json.dumps(
                    [{"addr_info": [{"family": "inet", "local": "10.64.0.2", "prefixlen": 32}]}]
                ),
                "",
            )
        if args[:5] == ("ip", "link", "delete", "dev", "wg-mullvad"):
            self.commands.append(args)
            self.live = False
            return 0, "", ""
        assert ROUTE_PROTOCOL == 196
        return await super().run(*args, **kwargs)

    def entrypoint(self):
        state = SimpleNamespace(
            validate=lambda: SimpleNamespace(intents=(SimpleNamespace(config=self.provider),))
        )
        maintenance = Maintenance()
        controller = ContainerController(state, maintenance, runner=self.run)
        controller.network = self.network
        maintenance.identities = (controller.identity(self.network.config),)
        entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
        entry.controller, entry.state = controller, state
        return entry


def test_active_provider_reset_revokes_exact_owned_residue_before_ingress_only_guard():
    from exitlane.services.provider_wireguard import ProviderWireGuardError

    ns = ActiveResetNamespace()
    # Reproduce the actual pre-fix reset boundary with the real shared checker.
    with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
        asyncio.run(ns.network.arm_guard())
    assert not any("del" in c or "delete" in c for c in ns.commands)
    ns.commands.clear()
    original_sources = [dict(r) for r in ns.rules[4] if r.get("src") in ns.network.source_addresses]
    entry = ns.entrypoint()
    asyncio.run(entry.reset())
    assert not ns.live
    assert all(r in ns.rules[4] for r in original_sources)
    assert ns.network.source_addresses == ("10.64.0.2", "10.65.0.2")
    assert ns.network.policy_interface is None
    assert all(not any(r.get("dev") for r in rows) for rows in ns.routes.values())
    assert not any(r.get("oif") for r in ns.rules[4])
    assert not any(r.get("iif_detached") for rows in ns.rules.values() for r in rows)
    assert entry.controller.maintenance.active
    assert not any(c[0] in {"systemctl", "wg-quick"} for c in ns.commands)


@pytest.mark.parametrize(
    "fault", ["foreign_route", "foreign_key", "index_race", "guard", "identity"]
)
def test_reset_refuses_unowned_residue_before_any_mutation(fault):
    from exitlane.services.provider_wireguard import ProviderWireGuardError

    ns = ActiveResetNamespace(
        foreign_route=fault == "foreign_route",
        foreign_key=fault == "foreign_key",
        race=3 if fault == "index_race" else 0,
    )
    ns.bad_observation = fault == "guard"
    entry = ns.entrypoint()
    if fault == "identity":
        entry.controller.maintenance.identities = ()
    with pytest.raises((EntrypointError, ContainerLifecycleError, ProviderWireGuardError)):
        asyncio.run(entry.reset())
    assert ns.live
    assert not any(
        "del" in c or "delete" in c or "replace" in c or "add" in c or c[:2] == ("nft", "-f")
        for c in ns.commands
    )


def test_ifindex_change_after_owned_selector_cleanup_keeps_link_and_guard():
    ns = ActiveResetNamespace(race=5)
    with pytest.raises(EntrypointError, match="container_interface_ownership_changed"):
        asyncio.run(ns.entrypoint().reset())
    assert ns.live and not any(c[:3] == ("ip", "link", "delete") for c in ns.commands)
    assert (
        ns.network.policy_interface == "wg-mullvad"
    )  # Independent maintenance remains authoritative.


@pytest.mark.parametrize("fault", ["second_key", "multiple_defaults"])
def test_all_surviving_generations_and_single_default_are_proven_before_cleanup(fault):
    from dataclasses import replace

    ns = ActiveResetNamespace()
    pia = replace(ns.provider, provider_id="pia", interface="wg-pia", address="10.65.0.2/32")
    original = ns.run

    async def runner(*args, **kwargs):
        if args[-1] == "wg-pia" and "link" in args and "show" in args:
            ns.commands.append(args)
            return (
                0,
                json.dumps(
                    [{"ifname": "wg-pia", "ifindex": 9, "linkinfo": {"info_kind": "wireguard"}}]
                ),
                "",
            )
        if args[:3] == ("wg", "show", "wg-pia"):
            ns.commands.append(args)
            values = {
                "public-key": pia.peer_public_key
                if fault == "second_key"
                else _public_key_for_private(pia.private_key),
                "peers": pia.peer_public_key,
                "endpoints": f"{pia.peer_public_key}\t{pia.endpoint_address}:51820",
            }
            return 0, values[args[-1]], ""
        if args[:4] == ("ip", "-4", "-j", "address") and args[-1] == "wg-pia":
            ns.commands.append(args)
            return (
                0,
                json.dumps(
                    [{"addr_info": [{"family": "inet", "local": "10.65.0.2", "prefixlen": 32}]}]
                ),
                "",
            )
        return await original(*args, **kwargs)

    entry = ns.entrypoint()
    entry.controller.runner = runner
    entry.state.validate = lambda: SimpleNamespace(
        intents=(SimpleNamespace(config=ns.provider), SimpleNamespace(config=pia))
    )
    if fault == "multiple_defaults":
        ns.routes[4].append({"dst": "default", "dev": "wg-pia", "metric": 10, "protocol": 196})
    with pytest.raises(EntrypointError, match="container_provider_recovery_required"):
        asyncio.run(entry.reset())
    assert not any("del" in c or "delete" in c or "replace" in c or "add" in c for c in ns.commands)


@pytest.mark.parametrize(
    "foreign",
    [
        {"priority": 12345, "src": "all", "iif": "other-ingress", "table": 999, "protocol": 999},
        {"priority": 20000, "src": "all", "iif": "wg-office", "table": 51820, "protocol": 999},
        {"priority": 20000, "src": "all", "iif": "other-ingress", "table": 51820, "protocol": 196},
    ],
)
def test_cleanup_never_removes_foreign_ingress_preference_or_protocol(foreign):
    from exitlane.services.provider_wireguard import ProviderWireGuardError

    ns = ActiveResetNamespace()
    ns.rules[4].append(dict(foreign))
    if foreign["priority"] == 20000:
        with pytest.raises(ProviderWireGuardError, match="provider_egress_resource_conflict"):
            asyncio.run(ns.entrypoint().reset())
    else:
        asyncio.run(ns.entrypoint().reset())
    assert foreign in ns.rules[4]
    deletions = [c for c in ns.commands if c[:4] == ("ip", "-4", "rule", "del")]
    assert all(
        c[6:8] in {("oif", "wg-mullvad"), ("iif", "wg-office")}
        and c[9] == "51820"
        and c[11] == "196"
        for c in deletions
    )


def test_reopen_preserves_worker_policy_and_releases_only_maintenance():
    calls = []

    class Controller:
        async def observe_policy(self):
            calls.append("observe")

        network = SimpleNamespace()

    controller = Controller()

    async def observe_ingress():
        calls.append("ifindex")
        return True

    controller.network.observe_owned_ingress = observe_ingress
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.controller, entry.maintenance = controller, Maintenance()
    entry.supervisor = SimpleNamespace(maintenance=True)
    asyncio.run(entry.reopen())
    assert calls == ["observe", "ifindex"]
    assert entry.maintenance.calls == [("release",)]
    assert entry.ready is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", 1000),
        ("capabilities", (1 << 12) | (1 << 21)),
        ("capabilities", 0),
        ("no_new_privileges", 0),
        ("root_readonly", False),
        ("data_mount", False),
        ("run_private", False),
        ("tmp_private", False),
        ("tun", False),
        ("tools", False),
        ("ipv4_forwarding", "0"),
        ("ipv6_forwarding", "1"),
        ("ping_group_range", "0 2147483647"),
        ("runtime", "native"),
    ],
)
def test_production_preflight_rejects_privilege_and_image_contract_mismatch(field, value):
    from exitlane.container_entrypoint import _validate_preflight

    facts = {
        "uid": 0,
        "capabilities": 1 << 12,
        "no_new_privileges": 1,
        "ipv4_forwarding": "1",
        "ipv6_forwarding": "0",
        "ping_group_range": "0 0",
        "tun": True,
        "tools": True,
        "root_readonly": True,
        "data_mount": True,
        "run_private": True,
        "tmp_private": True,
        "runtime": "container",
    }
    _validate_preflight(facts)
    facts[field] = value
    with pytest.raises(EntrypointError, match="container_preflight_failed"):
        _validate_preflight(facts)
