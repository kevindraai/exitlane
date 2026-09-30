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
            "EXITLANE_RUNTIME": "container",
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
