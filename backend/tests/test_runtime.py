from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from dataclasses import replace

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
        [sys.executable, '-c',
         ('from exitlane import main; from exitlane.providers.catalog import provider_registry; '
         'assert str(main.DB)=="/data/state/exitlane.db"; '
         'assert provider_registry.default_id=="mullvad"; '
         'assert [p.id for p in provider_registry.all()]==["mullvad","pia","proton"]; '
         'assert main.runtime.capabilities.system_actions==(); '
         'assert main.runtime.capabilities.supported is False')],
        env={**os.environ, 'EXITLANE_RUNTIME': 'container'},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('name', ['EXITLANE_DATA_DIR', 'EXITLANE_CONFIG_DIR',
                                 'EXITLANE_MASTER_KEY_FILE', 'EXITLANE_LOG_DIR'])
def test_container_path_override_refuses_before_state(name, tmp_path):
    result = subprocess.run([sys.executable, '-c', 'from exitlane import main'],
                            env={**os.environ, 'EXITLANE_RUNTIME': 'container',
                                 name: str(tmp_path / 'forbidden')},
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert 'container_path_override_invalid' in result.stderr
    assert not list(tmp_path.iterdir())


def test_container_metrics_are_scoped_and_never_use_host_facts(tmp_path):
    from exitlane.container_observation import system_status

    group = tmp_path / 'cgroup'
    group.mkdir()
    (group / 'memory.current').write_text('100\n')
    (group / 'memory.max').write_text('max\n')
    result = asyncio.run(system_status(tmp_path, cgroup=group))
    assert result.metric_scope == 'container'
    assert result.memory_used_bytes == 100
    assert result.memory_total_bytes is None
    assert result.cpu_percent is None and result.load_average is None
    assert result.temperature_celsius is None
    (group / 'memory.max').write_text('200\n')
    assert asyncio.run(system_status(tmp_path, cgroup=group)).memory_percent == 50.0


@pytest.mark.parametrize('provider_id', ['mullvad', 'pia', 'proton'])
@pytest.mark.parametrize('operation', ['connect', 'country', 'switch'])
def test_container_connect_and_switch_require_ingress_before_provider_access(monkeypatch, provider_id, operation):
    from fastapi import HTTPException

    fake = NativeSystemdRuntime(replace(RuntimeCapabilities(), runtime_name='container'))
    monkeypatch.setattr(main, 'runtime', fake)
    monkeypatch.setattr(main, 'setting', lambda *_args: False)
    monkeypatch.setattr(main, '_provider_or_404', lambda *_args: pytest.fail('provider accessed'))
    provider = object()
    with pytest.raises(HTTPException) as error:
        if operation == 'switch':
            asyncio.run(main.activate_vpn_provider(provider_id, None))
        elif operation == 'country':
            asyncio.run(main._connect_provider_country(provider, main.CountryConnect(country_code='NL'), None))
        else:
            asyncio.run(main._connect_provider(provider, main.Connect(target=None), None))
    assert error.value.status_code == 409
    assert error.value.detail == 'container_ingress_required'


def test_unconfigured_container_adapter_never_uses_native_network_commands():
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    from exitlane.services.provider_wireguard import ProviderWireGuard, ProviderWireGuardError
    adapter = UnconfiguredContainerEgress()
    assert not isinstance(adapter, ProviderWireGuard)
    for name in ('start', 'stop', 'stop_interface', 'probe', 'observe', 'status',
                 'arm', 'arm_source', 'arm_for_restore', 'reapply_guards', 'disarm',
                 'transition_facts', 'committed', 'verify_route', 'interface_exists'):
        with pytest.raises(ProviderWireGuardError, match='container_ingress_required'):
            asyncio.run(getattr(adapter, name)(None))
    with pytest.raises(ProviderWireGuardError, match='container_ingress_required'):
        adapter.remove_config('wg-pia')


@pytest.mark.parametrize('provider_id', ['mullvad', 'pia', 'proton'])
def test_real_provider_disconnect_before_ingress_cannot_run_native_teardown(monkeypatch, provider_id):
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    from exitlane.providers.catalog import provider_registry
    from exitlane.services import killswitch
    from exitlane.services.provider_wireguard import ProviderWireGuard

    provider = provider_registry.get(provider_id)
    monkeypatch.setattr(provider, 'wireguard', UnconfiguredContainerEgress())
    monkeypatch.setattr(provider, '_state', dict)
    monkeypatch.setattr(provider, '_owns_transition', lambda: False)
    monkeypatch.setattr(killswitch, 'configuration', lambda: ((), None))
    monkeypatch.setattr(provider, '_save', lambda *_: pytest.fail('state committed'))
    async def native(*_args, **_kwargs):
        pytest.fail('native teardown executed')
    monkeypatch.setattr(ProviderWireGuard, '_run', native)
    result = asyncio.run(provider.disconnect())
    assert result['ok'] is False and result['error_code'] == 'provider_disconnect_failed'


@pytest.mark.parametrize('provider_id', ['mullvad', 'pia'])
def test_real_provider_signout_before_ingress_cannot_run_native_teardown(monkeypatch, provider_id):
    from exitlane.container_unconfigured import UnconfiguredContainerEgress
    from exitlane.providers.catalog import provider_registry
    from exitlane.services import killswitch
    from exitlane.services.provider_wireguard import ProviderWireGuard

    provider = provider_registry.get(provider_id)
    monkeypatch.setattr(provider, 'wireguard', UnconfiguredContainerEgress())
    monkeypatch.setattr(provider, '_state', lambda: {'account_number': 'synthetic-account'})
    monkeypatch.setattr(killswitch, 'configuration', lambda: ((), None))
    monkeypatch.setattr(provider, 'api_factory', lambda *_: pytest.fail('external API accessed'))
    async def native(*_args, **_kwargs):
        pytest.fail('native teardown executed')
    monkeypatch.setattr(ProviderWireGuard, '_run', native)
    assert asyncio.run(provider.sign_out()) == {'ok': False, 'error': 'provider_error'}
