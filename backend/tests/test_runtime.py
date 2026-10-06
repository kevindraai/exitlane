from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from test_provider_abstraction import client as provider_client

from exitlane import main
from exitlane.runtime import (
    NativeSystemdRuntime,
    RuntimeCapabilities,
    RuntimeCapabilityUnavailable,
    RuntimePaths,
    runtime,
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    yield from provider_client.__wrapped__(tmp_path, monkeypatch)


def test_unknown_runtime_refuses_before_state_creation(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", "from exitlane import main"],
        env={
            **os.environ,
            "EXITLANE_RUNTIME": "unknown-runtime",
            "EXITLANE_DATA_DIR": str(tmp_path / "data"),
            "EXITLANE_CONFIG_DIR": str(tmp_path / "config"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "runtime_unavailable" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_native_paths_preserve_historical_defaults_and_explicit_environment(monkeypatch, tmp_path):
    for name in ("EXITLANE_CONFIG_DIR", "EXITLANE_DATA_DIR", "EXITLANE_LOG_DIR"):
        monkeypatch.delenv(name, raising=False)
    paths = RuntimePaths.native()
    assert str(paths.application_data) == "/etc/exitlane"
    assert str(paths.service_data) == "/var/lib/exitlane"
    monkeypatch.setenv("EXITLANE_DATA_DIR", str(tmp_path))
    assert RuntimePaths.native().application_data == RuntimePaths.native().service_data == tmp_path


def test_projection_excludes_paths_and_mutable_state():
    projection = runtime.capabilities.projection()
    assert projection["runtime"] == "native"
    assert projection["system_actions"] == ["restart", "reboot", "shutdown"]
    assert set(projection["providers"]) == {"nordvpn", "mullvad", "pia", "proton"}
    projection["providers"].clear()
    assert runtime.capabilities.providers
    assert "paths" not in projection


def test_denied_action_cannot_launch_subprocess():
    calls = []

    async def launch(*args, **kwargs):
        calls.append(args)

    restricted = NativeSystemdRuntime(replace(RuntimeCapabilities(), system_actions=()))
    with pytest.raises(RuntimeCapabilityUnavailable):
        asyncio.run(restricted.launch_system_action("reboot", launcher=launch))
    assert calls == []


def test_denied_ingress_cannot_touch_files_or_launch(tmp_path):
    restricted = NativeSystemdRuntime(replace(RuntimeCapabilities(), ingress=False))

    async def fail(*args, **kwargs):
        pytest.fail("command executed")

    with pytest.raises(RuntimeCapabilityUnavailable):
        asyncio.run(
            restricted.activate_ingress(
                "wg0", source_directory=tmp_path, system_directory=tmp_path / "system", runner=fail
            )
        )
    assert list(tmp_path.iterdir()) == []


def test_native_ingress_sync_uses_private_temporary_file_and_cleans_up(tmp_path):
    calls = []

    async def launch(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("wg-quick", "strip"):
            return 0, "[Interface]\nPrivateKey = sensitive", ""
        staged = args[3]
        assert os.stat(staged).st_mode & 0o777 == 0o600
        assert (await asyncio.to_thread(Path(staged).read_text)).endswith(
            "PrivateKey = sensitive\n"
        )
        return 0, "", ""

    asyncio.run(
        NativeSystemdRuntime().sync_ingress(
            "wg0",
            source_directory=tmp_path,
            runner=launch,
        )
    )
    assert calls[1][:3] == ("wg", "syncconf", "wg0")
    assert list(tmp_path.iterdir()) == []


def test_denied_restore_does_not_decrypt_or_mutate():
    restricted = NativeSystemdRuntime(replace(RuntimeCapabilities(), restore=False))
    with pytest.raises(RuntimeCapabilityUnavailable):
        restricted.restore(
            None, None, restore_transaction=lambda *a, **k: pytest.fail("restore ran")
        )


@pytest.mark.parametrize(
    "function,args,capability",
    [
        ("proton_profiles", (), "providers"),
        ("import_proton_profile", (None, None), "providers"),
        ("delete_proton_profile", ("fixture", None), "providers"),
        ("start_browser_login", (), "providers"),
        ("start_connection_diagnostics", (), "diagnostics"),
        ("create_wireguard_ingress", (None, None), "ingress"),
        ("regenerate_wireguard_configuration", (None,), "ingress"),
    ],
)
def test_api_denial_precedes_state_and_command_access(monkeypatch, function, args, capability):
    monkeypatch.setattr(
        runtime,
        "capabilities",
        replace(RuntimeCapabilities(), **{capability: () if capability == "providers" else False}),
    )
    with pytest.raises(RuntimeCapabilityUnavailable):
        asyncio.run(getattr(main, function)(*args))


def test_excluded_stored_provider_never_falls_back_to_nord(monkeypatch):
    monkeypatch.setattr(runtime, "capabilities", replace(RuntimeCapabilities(), providers=("pia",)))
    monkeypatch.setattr(main, "setting", lambda *a: "nordvpn")
    with pytest.raises(RuntimeCapabilityUnavailable):
        main._active_provider()


def test_capabilities_endpoint_requires_authentication(client):
    response = client.get("/api/runtime/capabilities")
    assert response.status_code == 200
    assert response.json() == runtime.capabilities.projection()
    client.cookies.clear()
    assert client.get("/api/runtime/capabilities").status_code == 401


def test_denied_system_action_returns_stable_error_without_acceptance(client, monkeypatch):
    monkeypatch.setattr(runtime, "capabilities", replace(RuntimeCapabilities(), system_actions=()))
    monkeypatch.setattr(main, "schedule_system_action", lambda *a: pytest.fail("action scheduled"))
    monkeypatch.setattr(main, "record_event", lambda *a, **k: pytest.fail("action recorded"))
    response = client.post("/api/system/actions/reboot")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "runtime_capability_unavailable"


def test_registered_excluded_provider_denied_but_unknown_remains_404(client, monkeypatch):
    monkeypatch.setattr(runtime, "capabilities", replace(RuntimeCapabilities(), providers=("pia",)))
    assert client.get("/api/vpn/providers/nordvpn/status").status_code == 409
    assert client.get("/api/vpn/providers/unknown/status").status_code == 404


def test_cli_killswitch_denial_does_not_prompt_or_mutate(monkeypatch, capsys):
    from exitlane import cli

    monkeypatch.setattr(
        runtime, "capabilities", replace(RuntimeCapabilities(), direct_egress=False)
    )
    assert (
        cli.disable_killswitch(effective_user_id=0, input_reader=lambda *a: pytest.fail("prompted"))
        == 2
    )
    assert "runtime_capability_unavailable" in capsys.readouterr().err


def test_cli_entrypoint_denial_precedes_database_initialization(monkeypatch, capsys):
    from exitlane import cli

    monkeypatch.setattr(
        runtime, "capabilities", replace(RuntimeCapabilities(), direct_egress=False)
    )
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.core, "init", lambda: pytest.fail("state initialized before denial"))
    assert cli.main(["disable-killswitch"]) == 2
    assert "runtime_capability_unavailable" in capsys.readouterr().err


def test_container_composition_imports_without_cycle_or_state_mutation(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from exitlane import main; from exitlane.providers.catalog import provider_registry; "
                'assert str(main.DB)=="/data/state/exitlane.db"; '
                'assert provider_registry.default_id=="mullvad"; '
                'assert [p.id for p in provider_registry.all()]==["mullvad","pia","proton"]; '
                "assert main.runtime.capabilities.system_actions==(); "
                "assert main.runtime.capabilities.supported is False"
            ),
        ],
        env={**os.environ, "EXITLANE_RUNTIME": "container"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "name",
    ["EXITLANE_DATA_DIR", "EXITLANE_CONFIG_DIR", "EXITLANE_MASTER_KEY_FILE", "EXITLANE_LOG_DIR"],
)
def test_container_path_override_refuses_before_state(name, tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", "from exitlane import main"],
        env={**os.environ, "EXITLANE_RUNTIME": "container", name: str(tmp_path / "forbidden")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "container_path_override_invalid" in result.stderr
    assert not list(tmp_path.iterdir())


def test_container_metrics_are_scoped_and_never_use_host_facts(tmp_path):
    from exitlane.container_observation import system_status

    group = tmp_path / "cgroup"
    group.mkdir()
    (group / "memory.current").write_text("100\n")
    (group / "memory.max").write_text("max\n")
    result = asyncio.run(system_status(tmp_path, cgroup=group))
    assert result.metric_scope == "container"
    assert result.memory_used_bytes == 100
    assert result.memory_total_bytes is None
    assert result.cpu_percent is None and result.load_average is None
    assert result.temperature_celsius is None
    (group / "memory.max").write_text("200\n")
    assert asyncio.run(system_status(tmp_path, cgroup=group)).memory_percent == 50.0


@pytest.mark.parametrize("provider_id", ["mullvad", "pia", "proton"])
@pytest.mark.parametrize("operation", ["connect", "country", "switch"])
def test_container_connect_and_switch_require_ingress_before_provider_access(
    monkeypatch, provider_id, operation
):
    from fastapi import HTTPException

    fake = NativeSystemdRuntime(replace(RuntimeCapabilities(), runtime_name="container"))
    monkeypatch.setattr(main, "runtime", fake)
    monkeypatch.setattr(main, "setting", lambda *_args: False)
    monkeypatch.setattr(main, "_provider_or_404", lambda *_args: pytest.fail("provider accessed"))
    provider = object()
    with pytest.raises(HTTPException) as error:
        if operation == "switch":
            asyncio.run(main.activate_vpn_provider(provider_id, None))
        elif operation == "country":
            asyncio.run(
                main._connect_provider_country(
                    provider, main.CountryConnect(country_code="NL"), None
                )
            )
        else:
            asyncio.run(main._connect_provider(provider, main.Connect(target=None), None))
    assert error.value.status_code == 409
    assert error.value.detail == "container_ingress_required"


def test_unconfigured_container_adapter_never_uses_native_network_commands():
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    from exitlane.services.provider_wireguard import ProviderWireGuard, ProviderWireGuardError

    adapter = UnconfiguredContainerEgress()
    assert not isinstance(adapter, ProviderWireGuard)
    for name in (
        "start",
        "stop",
        "stop_interface",
        "probe",
        "observe",
        "status",
        "arm",
        "arm_source",
        "arm_for_restore",
        "reapply_guards",
        "disarm",
        "transition_facts",
        "committed",
        "verify_route",
        "interface_exists",
    ):
        with pytest.raises(ProviderWireGuardError, match="container_ingress_required"):
            asyncio.run(getattr(adapter, name)(None))
    with pytest.raises(ProviderWireGuardError, match="container_ingress_required"):
        adapter.remove_config("wg-pia")


@pytest.mark.parametrize("provider_id", ["mullvad", "pia", "proton"])
def test_real_provider_disconnect_before_ingress_cannot_run_native_teardown(
    monkeypatch, provider_id
):
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    from exitlane.providers.catalog import provider_registry
    from exitlane.services import killswitch
    from exitlane.services.provider_wireguard import ProviderWireGuard

    provider = provider_registry.get(provider_id)
    monkeypatch.setattr(provider, "wireguard", UnconfiguredContainerEgress())
    monkeypatch.setattr(provider, "_state", dict)
    monkeypatch.setattr(provider, "_owns_transition", lambda: False)
    monkeypatch.setattr(killswitch, "configuration", lambda: ((), None))
    monkeypatch.setattr(provider, "_save", lambda *_: pytest.fail("state committed"))

    async def native(*_args, **_kwargs):
        pytest.fail("native teardown executed")

    monkeypatch.setattr(ProviderWireGuard, "_run", native)
    result = asyncio.run(provider.disconnect())
    assert result["ok"] is False and result["error_code"] == "provider_disconnect_failed"


@pytest.mark.parametrize("provider_id", ["mullvad", "pia"])
def test_real_provider_signout_before_ingress_cannot_run_native_teardown(monkeypatch, provider_id):
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    from exitlane.providers.catalog import provider_registry
    from exitlane.services import killswitch
    from exitlane.services.provider_wireguard import ProviderWireGuard

    provider = provider_registry.get(provider_id)
    monkeypatch.setattr(provider, "wireguard", UnconfiguredContainerEgress())
    monkeypatch.setattr(provider, "_state", lambda: {"account_number": "synthetic-account"})
    monkeypatch.setattr(killswitch, "configuration", lambda: ((), None))
    monkeypatch.setattr(provider, "api_factory", lambda *_: pytest.fail("external API accessed"))

    async def native(*_args, **_kwargs):
        pytest.fail("native teardown executed")

    monkeypatch.setattr(ProviderWireGuard, "_run", native)
    assert asyncio.run(provider.sign_out()) == {"ok": False, "error": "provider_error"}


@pytest.fixture
def container_resume(monkeypatch):
    """Actual shared killswitch service over an observable, initially stale table."""
    from types import SimpleNamespace

    from exitlane import core
    from exitlane.container_state import ContainerState, ProviderIntent, StateInventory
    from exitlane.providers import catalog
    from exitlane.runtime import ContainerRuntime
    from exitlane.services import killswitch

    events = []
    settings = {
        killswitch.SETTING_CONFIGURED: False,
        killswitch.SETTING_TRANSITION: False,
        "wireguard_interface": "wg-office",
    }
    config = SimpleNamespace(interface="wg-mullvad")
    inventory = StateInventory(
        1, "mullvad", (ProviderIntent("mullvad", "active", "synthetic-generation", config),)
    )
    fixture = SimpleNamespace(
        settings=settings,
        events=events,
        inventory=inventory,
        probe_ready=True,
        fail_guard_at=0,
        fail_shared=False,
    )

    class Network:
        config = SimpleNamespace(interface="wg-office")
        guard_observations = 0

        async def observe_guard(self):
            self.guard_observations += 1
            events.append("guard")
            if self.guard_observations == fixture.fail_guard_at:
                raise RuntimeError("synthetic-private-guard-detail")

    class WireGuard:
        async def start(self, config, ingress):
            assert ingress == ("wg-office",)
            events.append("start")

        async def probe(self, config):
            events.append("probe")
            return {"ready": fixture.probe_ready}

        async def committed(self, config):
            events.append("commit")

    class Firewall:
        def __init__(self):
            self.rules = killswitch.generate_ruleset(
                killswitch.TunnelFacts(False), ingress=("wg-office",), local_allowlist=()
            )

        async def installed(self):
            return self.rules is not None

        async def apply(self, rules):
            events.append("apply")
            if fixture.fail_shared:
                raise killswitch.KillswitchError("firewall_apply_failed")
            self.rules = rules

        async def remove(self):
            events.append("remove")
            if fixture.fail_shared:
                raise killswitch.KillswitchError("firewall_apply_failed")
            self.rules = None

    fixture.firewall = Firewall()
    fixture.runtime = ContainerRuntime.__new__(ContainerRuntime)
    fixture.runtime.network = Network()
    monkeypatch.setattr(core, "setting", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(core, "set_setting", lambda key, value: settings.__setitem__(key, value))
    monkeypatch.setattr(ContainerState, "validate", lambda _: fixture.inventory)
    monkeypatch.setattr(
        catalog.provider_registry, "get", lambda _: SimpleNamespace(wireguard=WireGuard())
    )
    monkeypatch.setattr(killswitch, "NftBackend", lambda: fixture.firewall)
    return fixture


def test_container_restore_disabled_shared_killswitch_removes_stale_transition_after_proof(
    container_resume,
):
    from exitlane.services import killswitch

    case = container_resume
    assert "ExitLane fail closed" in case.firewall.rules
    asyncio.run(case.runtime.resume_provider())
    assert case.firewall.rules is None
    assert case.settings[killswitch.SETTING_CONFIGURED] is False
    assert case.settings[killswitch.SETTING_TRANSITION] is False
    assert case.events == ["guard", "start", "probe", "commit", "guard", "remove"]


@pytest.mark.parametrize("transition", [False, True])
def test_container_restore_enabled_shared_killswitch_rewrites_only_proven_provider(
    container_resume, transition
):
    from exitlane.services import killswitch

    case = container_resume
    case.settings[killswitch.SETTING_CONFIGURED] = True
    case.settings[killswitch.SETTING_TRANSITION] = transition
    asyncio.run(case.runtime.resume_provider())
    assert 'oifname "wg-mullvad" accept comment "ExitLane protected IPv4"' in case.firewall.rules
    assert "ExitLane protected IPv6" not in case.firewall.rules
    assert case.settings[killswitch.SETTING_CONFIGURED] is True
    assert case.settings[killswitch.SETTING_TRANSITION] is False
    assert case.events == ["guard", "start", "probe", "commit", "guard", "apply"]


@pytest.mark.parametrize("selected", ["mullvad", "pia"])
def test_container_any_pending_intent_preserves_shared_guard_and_never_resumes(
    container_resume, selected
):
    from exitlane.container_state import ProviderIntent, StateInventory
    from exitlane.services import killswitch

    case = container_resume
    active = case.inventory.intents[0]
    case.inventory = StateInventory(
        1, selected, (active, ProviderIntent("pia", "pending", "synthetic-pending", None))
    )
    case.settings[killswitch.SETTING_TRANSITION] = True
    asyncio.run(case.runtime.resume_provider())
    assert case.settings[killswitch.SETTING_TRANSITION] is True
    assert "ExitLane fail closed" in case.firewall.rules
    assert "ExitLane protected IPv4" not in case.firewall.rules
    assert case.events == ["guard", "apply"]


@pytest.mark.parametrize("configured,transition", [(True, False), (False, True), (False, False)])
def test_container_unproven_active_provider_preserves_blocked_management(
    container_resume, configured, transition
):
    from exitlane.services import killswitch

    case = container_resume
    case.probe_ready = False
    case.settings[killswitch.SETTING_CONFIGURED] = configured
    case.settings[killswitch.SETTING_TRANSITION] = transition
    asyncio.run(case.runtime.resume_provider())
    assert "ExitLane fail closed" in case.firewall.rules
    assert "ExitLane protected IPv4" not in case.firewall.rules
    assert "commit" not in case.events and "remove" not in case.events
    assert case.settings[killswitch.SETTING_TRANSITION] is transition


@pytest.mark.parametrize(
    "failure", ["initial_guard", "committed_guard", "shared_remove", "shared_apply"]
)
def test_container_reconciliation_failure_cannot_acknowledge_initialized_worker(
    container_resume, failure
):
    import socket

    from exitlane.container_control import _read, _write
    from exitlane.runtime_mutation import StartupBorrower
    from exitlane.services import killswitch

    case = container_resume
    if failure == "initial_guard":
        case.fail_guard_at = 1
    elif failure == "committed_guard":
        case.fail_guard_at = 2
    else:
        case.fail_shared = True
        case.settings[killswitch.SETTING_CONFIGURED] = failure == "shared_apply"

    async def scenario():
        parent, child = socket.socketpair()
        parent.setblocking(False)
        reader, writer = await asyncio.open_connection(sock=parent)
        try:
            await _write(writer, {"command": "startup-grant", "version": 1})
            with pytest.raises((RuntimeError, killswitch.KillswitchError)):
                async with StartupBorrower(child.detach()).context():
                    await case.runtime.resume_provider()
            assert await _read(reader, 1) == {"command": "startup-failed", "version": 1}
        finally:
            child.close()
            writer.close()
            await writer.wait_closed()

    asyncio.run(scenario())
    assert "ExitLane fail closed" in case.firewall.rules
    if failure == "initial_guard":
        assert case.events == ["guard"]
    elif failure == "committed_guard":
        assert "remove" not in case.events and "apply" not in case.events
