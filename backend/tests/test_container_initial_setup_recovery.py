"""The parent resolves an interrupted first ingress before strict worker startup."""

import asyncio
import os
import re
import sqlite3
from types import SimpleNamespace

import pytest
from test_container_entrypoint import ActiveResetNamespace, Maintenance

from exitlane import container_runtime, container_state, core
from exitlane.container_entrypoint import ContainerController, ContainerEntrypoint
from exitlane.container_recovery import (
    ContainerRecoveryCoordinator,
    ContainerRecoveryError,
    RecoveryHooks,
)
from exitlane.container_state import ContainerLayout, ContainerState, ContainerStateError
from exitlane.runtime import ContainerRuntime
from exitlane.services import wireguard, wireguard_initial, wireguard_peers


class Hooks:
    def __init__(self):
        self.events = []

    async def guard(self, identities):
        self.events.append(("guard", identities))

    async def quiesce(self):
        self.events.append("quiesce")

    async def reset(self):
        self.events.append("reset")

    async def reconcile(self, _inventory):
        self.events.append("reconcile")

    async def health(self):
        self.events.append("health")
        return True

    async def reopen(self):
        self.events.append("reopen")

    def bundle(self, initial_setup=None, initial_setup_complete=None):
        return RecoveryHooks(
            self.guard,
            self.quiesce,
            self.reset,
            self.reconcile,
            self.health,
            self.reopen,
            initial_setup,
            initial_setup_complete,
        )


@pytest.fixture
def recovery(tmp_path, monkeypatch, synthetic_wireguard_keys):
    monkeypatch.setattr(container_state, "ROOT_UID", os.geteuid())
    state = ContainerState(ContainerLayout(tmp_path / "data"))
    hooks = Hooks()
    asyncio.run(
        ContainerRecoveryCoordinator(
            state, hooks.bundle(), require_exclusive=lambda: True
        ).startup()
    )
    monkeypatch.setattr(core, "DB", state.layout.database)
    monkeypatch.setattr(core, "WG_DIR", state.layout.wireguard)
    monkeypatch.setattr(wireguard, "WG_DIR", state.layout.wireguard)
    hooks.events.clear()
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.state = state
    entry.guard = hooks.guard
    entry.quiesce = hooks.quiesce

    async def absent(*_args, **_kwargs):
        return 1, "", ""

    async def no_policy(_identity):
        return None

    entry.controller = SimpleNamespace(
        network=None,
        runner=absent,
        preserve_initial_policy=no_policy,
        recovered_initial_policy=None,
        recovered_retired_interface=None,
    )
    coordinator = ContainerRecoveryCoordinator(
        state,
        hooks.bundle(entry.recover_initial_setup, entry.finish_initial_setup),
        require_exclusive=lambda: True,
    )
    entry.coordinator = coordinator
    return state, hooks, coordinator, entry


def journal(state, *, phase="pending", activated=False):
    wireguard_initial.write(
        state.layout.database,
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/24",
            "activation_attempted": activated,
            "settings": {},
            "phase": phase,
        },
    )


async def create_migrated(state):
    await wireguard.create(
        endpoint="192.0.2.10",
        subnet="10.90.0.0/24",
        dns="1.1.1.1",
        interface="wg0",
        client="router",
    )
    await wireguard_peers.migrate_legacy("wg0", "router")
    core.set_settings(
        {
            "wireguard_configured": True,
            "wireguard_interface": "wg0",
            "wireguard_client_name": "router",
            "wireguard_subnet": "10.90.0.0/24",
        }
    )


def assert_original(state):
    assert core.setting("wireguard_configured", False) is False
    assert not (state.layout.wireguard / "wg0.conf").exists()
    assert not (state.layout.wireguard / "router.conf").exists()
    assert not wireguard_initial.path(state.layout.database).exists()
    with sqlite3.connect(state.layout.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM wireguard_ingress_profile").fetchone()[0] == 0
        )
    state.validate()


@pytest.mark.parametrize(
    ("configured", "remove_files"),
    [(True, True), (True, False), (False, False)],
)
def test_parent_recovers_pending_crash_cuts_before_worker(recovery, configured, remove_files):
    state, hooks, coordinator, _entry = recovery
    asyncio.run(create_migrated(state))
    journal(state)
    if not configured:
        core.set_setting("wireguard_configured", False)
    if remove_files:
        (state.layout.wireguard / "wg0.conf").unlink()
        (state.layout.wireguard / "router.conf").unlink()
        with pytest.raises(ContainerStateError, match="component_missing"):
            state.validate()
    asyncio.run(coordinator.startup())
    assert hooks.events[0][0] == "guard"
    assert {item.interface for item in hooks.events[0][1]} == {"wg0"}
    assert hooks.events[1] == "quiesce"
    assert hooks.events[-1] == "reopen"
    assert_original(state)


def test_parent_removes_only_owned_atomic_write_temp_before_strict_validation(recovery):
    state, hooks, coordinator, _entry = recovery
    journal(state)
    temporary = state.layout.wireguard / ".wg0.conf.abcdefgh"
    temporary.write_text("partial synthetic config", encoding="ascii")
    temporary.chmod(0o600)
    # The container parser ignores this non-.conf name, but the recovery
    # transaction must still remove its root-private secret-bearing residue.
    state.validate()
    asyncio.run(coordinator.startup())
    assert not temporary.exists()
    assert hooks.events[0][0] == "guard"
    assert_original(state)


def test_pending_two_address_ingress_recovers_under_supported_subnet_boundary(recovery):
    state, _hooks, coordinator, _entry = recovery
    wireguard_initial.write(
        state.layout.database,
        {
            "interface": "wg0",
            "client": "router",
            "subnet": "10.90.0.0/31",
            "activation_attempted": False,
            "settings": {},
            "phase": "pending",
        },
    )
    asyncio.run(coordinator.startup())
    assert_original(state)


@pytest.mark.parametrize("stage", ["reset", "reconcile"])
def test_pending_journal_remains_until_provider_reset_and_reconcile_succeed(recovery, stage):
    state, hooks, _coordinator, entry = recovery
    asyncio.run(create_migrated(state))
    journal(state)

    async def failed(*_args):
        raise ContainerRecoveryError("recovery_required")

    setattr(hooks, stage, failed)
    coordinator = ContainerRecoveryCoordinator(
        state,
        hooks.bundle(entry.recover_initial_setup, entry.finish_initial_setup),
        require_exclusive=lambda: True,
    )
    entry.coordinator = coordinator
    with pytest.raises(ContainerRecoveryError, match="recovery_required"):
        asyncio.run(coordinator.startup())
    assert wireguard_initial.path(state.layout.database).exists()
    assert core.setting("wireguard_configured", False) is False
    assert not (state.layout.wireguard / "wg0.conf").exists()
    assert not (state.layout.wireguard / "router.conf").exists()

    setattr(hooks, stage, getattr(Hooks, stage).__get__(hooks))
    coordinator = ContainerRecoveryCoordinator(
        state,
        hooks.bundle(entry.recover_initial_setup, entry.finish_initial_setup),
        require_exclusive=lambda: True,
    )
    entry.coordinator = coordinator
    asyncio.run(coordinator.startup())
    assert_original(state)


def test_committed_missing_file_fails_closed_with_journal_retained(recovery):
    state, hooks, coordinator, _entry = recovery
    asyncio.run(create_migrated(state))
    journal(state, phase="committed")
    (state.layout.wireguard / "wg0.conf").unlink()
    with pytest.raises(ContainerStateError, match="component_missing"):
        asyncio.run(coordinator.startup())
    assert wireguard_initial.path(state.layout.database).exists()
    assert hooks.events == []


def test_unknown_live_interface_is_not_deleted_or_adopted(recovery):
    state, hooks, coordinator, entry = recovery
    asyncio.run(create_migrated(state))
    journal(state, activated=True)

    async def live(*_args, **_kwargs):
        return 0, "", ""

    entry.controller.runner = live
    with pytest.raises(ContainerRecoveryError, match="recovery_required"):
        asyncio.run(coordinator.startup())
    assert core.setting("wireguard_configured") is True
    assert wireguard_initial.path(state.layout.database).exists()
    assert len(hooks.events) == 2
    assert hooks.events[0][0] == "guard"
    assert hooks.events[1] == "quiesce"


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "world_readable"])
def test_parent_refuses_unsafe_pending_source_without_clearing_journal(recovery, unsafe):
    state, hooks, coordinator, _entry = recovery
    journal(state)
    server = state.layout.wireguard / "wg0.conf"
    server.write_text("synthetic private file", encoding="ascii")
    server.chmod(0o600)
    if unsafe == "symlink":
        target = state.layout.state / "private-config-target"
        target.write_bytes(server.read_bytes())
        target.chmod(0o600)
        server.unlink()
        server.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(server, state.layout.state / "other-config-link")
    else:
        server.chmod(0o644)
    with pytest.raises(ContainerRecoveryError, match="recovery_required"):
        asyncio.run(coordinator.startup())
    assert wireguard_initial.path(state.layout.database).exists()
    assert server.exists()
    assert hooks.events[0][0] == "guard"
    assert hooks.events[1] == "quiesce"
    assert "reopen" not in hooks.events


@pytest.mark.parametrize("failure", ["none", "partial_retirement", "nft_applied_then_error"])
@pytest.mark.parametrize("journal_target", ["old", "retry"])
def test_recovered_parent_and_fresh_worker_accept_corrected_identity(
    recovery, monkeypatch, failure, journal_target
):
    """The old blocked policy and source guards survive parent/worker handoff."""
    state, _hooks, _coordinator, _entry = recovery
    old = "wg-office"
    new = "wg-retry"
    original = "10.88.0.0/24"
    corrected = "10.89.0.0/24"
    wireguard_initial.write(
        state.layout.database,
        {
            "interface": old if journal_target == "old" else new,
            "client": "router",
            "subnet": original if journal_target == "old" else corrected,
            "activation_attempted": False,
            "settings": {},
            "phase": "pending",
        },
    )
    ns = ActiveResetNamespace(detached=False)
    ns.network.policy_interface = None
    ns.network.probe_interface = None
    ns.routes[4] = [row for row in ns.routes[4] if row.get("dev") is None]
    ns.rules[4] = [row for row in ns.rules[4] if row.get("oif") is None]
    ns.live = False
    protected_sources = tuple(ns.network.source_addresses)
    link = None
    fail_retirement = failure == "partial_retirement"
    fail_rebind = failure == "nft_applied_then_error"
    lifecycle = container_runtime.ContainerWireGuardLifecycle

    async def runner(*args, **kwargs):
        nonlocal link, fail_retirement, fail_rebind
        if fail_retirement and args[:4] == ("ip", "-6", "rule", "del") and args[7] == old:
            fail_retirement = False
            return 1, "", ""
        if args[:3] == ("ip", "link", "show") and args[-2] == "dev":
            return (0 if link == args[-1] else 1), "", ""
        if args[:4] == ("ip", "-j", "link", "show"):
            return (
                (0, '[{"ifname":"' + link + '","ifindex":101}]', "")
                if link == args[-1]
                else (1, "", "")
            )
        if args[:4] == ("ip", "link", "add", "dev"):
            link = args[-3]
        if args[:4] == ("ip", "link", "delete", "dev"):
            link = None
        if args[:3] == ("nft", "-f", "/dev/stdin"):
            payload = kwargs["input_text"]
            interface = re.search(r'iifname "([A-Za-z0-9-]+)" drop', payload)
            subnet = re.search(r"ip saddr ([0-9.]+/[0-9]+) drop", payload)
            assert interface is not None and subnet is not None
            network = wireguard._validated_ingress_network(subnet.group(1))
            ns.network = lifecycle(
                container_runtime._PolicyIngress(
                    interface.group(1), f"{next(network.hosts())}/{network.prefixlen}"
                ),
                runner=runner,
            )
            ns.network.source_addresses = protected_sources
            ns.guard_exists = True
            if fail_rebind and interface.group(1) == new:
                fail_rebind = False
                return 1, "", ""
        return await ns.run(*args, **kwargs)

    def lifecycle_with_runner(config, **_kwargs):
        return lifecycle(config, runner=runner)

    monkeypatch.setattr(container_runtime, "ContainerWireGuardLifecycle", lifecycle_with_runner)
    maintenance = Maintenance()
    controller = ContainerController(state, maintenance, runner=runner)
    if journal_target == "retry":
        # The first attempt left a proved old guard; a changed retry then
        # published its own pending intent before the worker was interrupted.
        controller.initial_guard_config = ns.network.config
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.state = state
    entry.controller = controller
    entry.maintenance = maintenance
    entry.ready = False

    async def stopped():
        return None

    entry.supervisor = SimpleNamespace(stop_worker=stopped, maintenance=False)

    async def healthy():
        return True

    coordinator = ContainerRecoveryCoordinator(
        state,
        RecoveryHooks(
            entry.guard,
            entry.quiesce,
            stopped,
            controller.reconcile,
            healthy,
            stopped,
            entry.recover_initial_setup,
            entry.finish_initial_setup,
        ),
        require_exclusive=lambda: True,
    )
    entry.coordinator = coordinator
    asyncio.run(coordinator.startup())
    assert_original(state)
    assert controller.network is None
    assert controller.recovered_initial_policy is not None
    assert controller.recovered_initial_policy.source_addresses == protected_sources
    assert maintenance.active

    asyncio.run(
        wireguard.create(
            endpoint="192.0.2.10",
            subnet=corrected,
            dns="1.1.1.1",
            interface=new,
            client="router",
        )
    )

    class Client:
        async def request(self, command, payload):
            assert command == "ingress"
            return await controller.ingress(payload)

    worker = ContainerRuntime.__new__(ContainerRuntime)
    worker.client = Client()
    worker.network = None
    worker._initial_ingress_rolled_back = False
    monkeypatch.setattr(core, "setting", lambda _key, default=False: default)
    from exitlane.providers import catalog

    monkeypatch.setattr(catalog.provider_registry, "direct_egress_providers", lambda: ())
    if failure != "none":
        with pytest.raises(
            Exception, match="container_guard_unproven|container_network_command_failed"
        ):
            asyncio.run(worker.activate_ingress(new))
        assert controller.recovered_initial_policy is not None
        assert controller.recovered_retired_interface[0] == (
            old if failure == "partial_retirement" else new
        )
        assert link is None
        assert not any(call == ("release",) for call in maintenance.calls)
        # The application rollback removes its unpublished files; a fresh
        # worker startup must retire any interrupted RPDB selector before the
        # corrected setup can be attempted again.
        (state.layout.wireguard / f"{new}.conf").unlink()
        (state.layout.wireguard / "router.conf").unlink()
        asyncio.run(coordinator.startup())
        assert controller.recovered_retired_interface is None
        asyncio.run(
            wireguard.create(
                endpoint="192.0.2.10",
                subnet=corrected,
                dns="1.1.1.1",
                interface=new,
                client="router",
            )
        )
    asyncio.run(worker.activate_ingress(new))
    assert controller.network is not None and controller.network.active
    assert worker.network is not None
    assert controller.recovered_initial_policy is None
    assert ("release",) in maintenance.calls
    assert ns.network.config.interface == new
    assert ns.network.source_addresses == protected_sources
    assert all(not any(row.get("iif") == old for row in ns.rules[family]) for family in (4, 6))
    assert all(any(row.get("iif") == new for row in ns.rules[family]) for family in (4, 6))
