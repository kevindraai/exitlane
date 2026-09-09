import asyncio
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.services import vpn_operations

PASSWORD = "correct horse battery staple"


def provider_status(provider, *, authenticated=True, connected=False):
    authentication = "signed_in" if authenticated else "signed_out"
    connection = "connected" if connected else "disconnected"
    return {
        "installed": True,
        "available": True,
        "daemon_active": True,
        "authenticated": authenticated,
        "connected": connected,
        "state": connection,
        "country": "Netherlands" if connected else None,
        "country_code": "NL" if connected else None,
        "city": "Amsterdam" if connected else None,
        "server": (
            "nl1234.nordvpn.com"
            if connected and provider.id == "nordvpn"
            else "nl-ams-wg-001"
            if connected
            else None
        ),
        "tunnel_interface": (
            "nordlynx"
            if connected and provider.id == "nordvpn"
            else "wg0-mullvad"
            if connected
            else None
        ),
        "technology": "NORDLYNX" if connected and provider.id == "nordvpn" else "",
        "management": provider.management_status(
            installation_state="available",
            authentication_state=authentication,
            connection_state=connection,
        ),
    }


def transient_mullvad_account_timeout(*, connected=False):
    status = provider_status(main.mullvad_provider, authenticated=False, connected=connected)
    status.update(available=False, error_code="timeout")
    status["management"] = main.mullvad_provider.management_status(
        installation_state="failed",
        authentication_state="unknown",
        connection_state="connected" if connected else "disconnected",
        error_code="timeout",
    )
    return status


@pytest.fixture(autouse=True)
def reset_operations():
    vpn_operations.reset_for_tests()


@pytest.fixture
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", database)
    monkeypatch.setattr(main, "WG_DIR", data / "wireguard")

    async def arm_provider_transition():
        core.set_setting(main.killswitch.SETTING_TRANSITION, True)

    async def complete_provider_transition(_facts):
        core.set_setting(main.killswitch.SETTING_TRANSITION, False)

    async def reconcile_transition(_facts):
        return SimpleNamespace(state="enabled_transition", reason="provider_transition")

    monkeypatch.setattr(
        main.killswitch,
        "arm_provider_transition",
        arm_provider_transition,
    )
    monkeypatch.setattr(
        main.killswitch,
        "complete_provider_transition",
        complete_provider_transition,
    )
    monkeypatch.setattr(main.killswitch, "reconcile", reconcile_transition)
    with TestClient(main.app) as test_client:
        digest, salt = core.hash_password(PASSWORD)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
                ("admin", digest, salt),
            )
        core.set_setting("setup_complete", True)
        response = test_client.post(
            "/api/auth/login",
            json={"username": "admin", "password": PASSWORD},
        )
        assert response.status_code == 200
        yield test_client


def configure_statuses(monkeypatch, states):
    async def nord_status(*, timeout=8):
        return provider_status(main.provider, **states["nordvpn"])

    async def mullvad_status(*, timeout=8):
        return provider_status(main.mullvad_provider, **states["mullvad"])

    async def nord_local_status(*, timeout=6):
        connected = states["nordvpn"].get("connected", False)
        return {
            "installed": states["nordvpn"].get("installed", True),
            "daemon_active": states["nordvpn"].get("daemon_active", True),
            "local_control_available": states["nordvpn"].get("local_control_available", True),
            "connected": connected,
            "connection_state": states["nordvpn"].get(
                "connection_state", "connected" if connected else "disconnected"
            ),
            "error_code": states["nordvpn"].get("error_code"),
        }

    async def mullvad_local_status(*, timeout=6):
        connected = states["mullvad"].get("connected", False)
        return {
            "installed": states["mullvad"].get("installed", True),
            "daemon_active": states["mullvad"].get("daemon_active", True),
            "local_control_available": states["mullvad"].get("local_control_available", True),
            "connected": connected,
            "connection_state": states["mullvad"].get(
                "connection_state", "connected" if connected else "disconnected"
            ),
            "error_code": states["mullvad"].get("error_code"),
        }

    async def nord_connect(_target=None, *, timeout=40):
        states["nordvpn"]["connected"] = True
        return {"ok": True, "error_code": None}

    async def mullvad_connect(_target=None, *, timeout=40):
        states["mullvad"]["connected"] = True
        return {"ok": True, "error_code": None}

    async def nord_disconnect(*, timeout=15):
        states["nordvpn"]["connected"] = False
        return {"ok": True, "error_code": None}

    async def mullvad_disconnect(*, timeout=15):
        states["mullvad"]["connected"] = False
        return {"ok": True, "error_code": None}

    async def mullvad_gateway_ready():
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main.provider, "status", nord_status)
    monkeypatch.setattr(main.mullvad_provider, "status", mullvad_status)
    monkeypatch.setattr(main.provider, "local_status", nord_local_status)
    monkeypatch.setattr(main.mullvad_provider, "local_status", mullvad_local_status)
    monkeypatch.setattr(main.provider, "connect", nord_connect)
    monkeypatch.setattr(main.mullvad_provider, "connect", mullvad_connect)
    monkeypatch.setattr(main.provider, "disconnect", nord_disconnect)
    monkeypatch.setattr(main.mullvad_provider, "disconnect", mullvad_disconnect)
    monkeypatch.setattr(main.mullvad_provider, "prepare_activation", mullvad_gateway_ready)


def test_catalog_has_both_unique_ids_and_backward_compatible_active_default(client, monkeypatch):
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": False, "connected": False},
        },
    )
    response = client.get("/api/vpn/providers")
    assert response.status_code == 200
    payload = response.json()
    providers = {item["id"]: item for item in payload["providers"]}
    assert set(providers) == {"nordvpn", "mullvad"}
    assert payload["active_provider_id"] == "nordvpn"
    assert providers["nordvpn"]["active"] is True
    assert providers["mullvad"]["active"] is False
    assert providers["mullvad"]["authentication_method"] == "account_number"


@pytest.mark.parametrize("stored_provider_id", ["unknown", ["mullvad"]])
def test_invalid_legacy_active_provider_setting_falls_back_to_nordvpn(client, stored_provider_id):
    core.set_setting("vpn.provider_id", stored_provider_id)
    assert main._active_provider_id() == "nordvpn"


def test_inactive_provider_connect_is_rejected_before_provider_command(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": False},
        },
    )

    async def unexpected(*_args, **_kwargs):
        pytest.fail("an inactive provider must never receive a connect command")

    monkeypatch.setattr(main.mullvad_provider, "connect", unexpected)
    response = client.post("/api/vpn/providers/mullvad/connect", json={"target": "nl"})
    assert response.status_code == 409
    assert response.json() == {"detail": "provider_not_active"}


def test_switch_disconnected_nord_to_ready_mullvad(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    response = client.post("/api/vpn/providers/mullvad/activate")
    assert response.status_code == 200
    assert response.json()["active_provider_id"] == "mullvad"
    assert core.setting("vpn.provider_id") == "mullvad"


def test_switch_disconnects_and_verifies_old_provider_before_persisting(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    disconnects = []

    async def disconnect(*, timeout):
        disconnects.append(timeout)
        states["nordvpn"]["connected"] = False
        return {"ok": True}

    monkeypatch.setattr(main.provider, "disconnect", disconnect)
    response = client.post("/api/vpn/providers/mullvad/activate")
    assert response.status_code == 200
    assert disconnects == [15]
    assert core.setting("vpn.provider_id") == "mullvad"


@pytest.mark.parametrize(
    ("source_id", "target_id"),
    [("mullvad", "nordvpn"), ("nordvpn", "mullvad")],
)
def test_connected_provider_switch_is_transactional_and_defers_remote_target_status(
    client, monkeypatch, source_id, target_id
):
    core.set_setting("vpn.provider_id", source_id)
    states = {
        "nordvpn": {"authenticated": True, "connected": source_id == "nordvpn"},
        "mullvad": {"authenticated": True, "connected": source_id == "mullvad"},
    }
    configure_statuses(monkeypatch, states)
    source = main.provider_registry.get(source_id)
    target = main.provider_registry.get(target_id)
    order = []
    original_target_status = target.status

    async def target_status(*, timeout=8):
        assert states[source_id]["connected"] is False
        order.append("target_remote_status")
        return await original_target_status(timeout=timeout)

    async def arm_transition():
        order.append("transition_armed")
        core.set_setting(main.killswitch.SETTING_TRANSITION, True)

    async def source_disconnect(*, timeout=15):
        assert core.setting(main.killswitch.SETTING_TRANSITION) is True
        order.append("source_disconnected")
        states[source_id]["connected"] = False
        return {"ok": True, "error_code": None}

    async def target_prepare():
        order.append("target_prepared")
        return {"ok": True, "error_code": None}

    async def target_connect(_target=None, *, timeout=40):
        order.append("target_connected")
        states[target_id]["connected"] = True
        return {"ok": True, "error_code": None}

    async def complete_transition(_facts):
        assert core.setting("vpn.provider_id") == target_id
        order.append("transition_completed")
        core.set_setting(main.killswitch.SETTING_TRANSITION, False)

    monkeypatch.setattr(target, "status", target_status)
    monkeypatch.setattr(source, "disconnect", source_disconnect)
    monkeypatch.setattr(target, "prepare_activation", target_prepare)
    monkeypatch.setattr(target, "connect", target_connect)
    monkeypatch.setattr(main.killswitch, "arm_provider_transition", arm_transition)
    monkeypatch.setattr(main.killswitch, "complete_provider_transition", complete_transition)

    response = client.post(f"/api/vpn/providers/{target_id}/activate")

    assert response.status_code == 200
    assert response.json()["active_provider_id"] == target_id
    assert response.json()["status"]["connected"] is True
    assert core.setting("vpn.provider_id") == target_id
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False
    assert order[:5] == [
        "transition_armed",
        "source_disconnected",
        "target_remote_status",
        "target_prepared",
        "target_connected",
    ]
    assert order[-1] == "transition_completed"


def test_connected_source_is_not_disconnected_when_target_local_preflight_is_broken(
    client, monkeypatch
):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {
            "authenticated": True,
            "connected": False,
            "daemon_active": False,
            "local_control_available": False,
        },
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)

    async def remote_status_must_not_run(*, timeout=8):
        pytest.fail("remote target status must not run before source handoff")

    async def disconnect_must_not_run(*, timeout=15):
        pytest.fail("healthy source must remain connected after local preflight failure")

    monkeypatch.setattr(main.provider, "status", remote_status_must_not_run)
    monkeypatch.setattr(main.mullvad_provider, "disconnect", disconnect_must_not_run)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 409
    assert response.json()["blockers"] == [
        {"code": "provider_daemon_unavailable", "provider": "nordvpn"}
    ]
    assert states["mullvad"]["connected"] is True
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION, False) is False


def test_transition_protection_failure_does_not_disconnect_connected_source(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)

    async def failed_arm():
        core.set_setting(main.killswitch.SETTING_TRANSITION, True)
        raise main.killswitch.KillswitchError("firewall_apply_failed")

    async def disconnect_must_not_run(*, timeout=15):
        pytest.fail("source disconnect must not run when transition protection failed")

    monkeypatch.setattr(main.killswitch, "arm_provider_transition", failed_arm)
    monkeypatch.setattr(main.mullvad_provider, "disconnect", disconnect_must_not_run)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider_switch_failed"}
    assert states["mullvad"]["connected"] is True
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is True


def test_remote_target_readiness_failure_rolls_back_source_and_releases_transition(
    client, monkeypatch
):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)
    calls = []

    async def target_remote_failure(*, timeout=8):
        calls.append("target_remote_failure")
        status = provider_status(main.provider, authenticated=True, connected=False)
        status.update(available=False, error_code="provider_status_unavailable")
        status["management"] = main.provider.management_status(
            installation_state="failed",
            authentication_state="unknown",
            connection_state="disconnected",
            error_code="provider_status_unavailable",
        )
        return status

    async def source_connect(_target=None, *, timeout=40):
        calls.append("source_rollback_connected")
        states["mullvad"]["connected"] = True
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main.provider, "status", target_remote_failure)
    monkeypatch.setattr(main.mullvad_provider, "connect", source_connect)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider_switch_failed"}
    assert calls == ["target_remote_failure", "source_rollback_connected"]
    assert states["mullvad"]["connected"] is True
    assert states["nordvpn"]["connected"] is False
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_transient_mullvad_account_timeout_retries_without_releasing_transition(
    client, monkeypatch
):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    readiness_attempts = 0
    connect_calls = 0
    sleeps = []

    async def target_status(*, timeout=8):
        nonlocal readiness_attempts
        if not states["mullvad"]["connected"]:
            readiness_attempts += 1
            assert core.setting(main.killswitch.SETTING_TRANSITION) is True
            assert core.setting("vpn.provider_id") == "nordvpn"
            if readiness_attempts == 1:
                return transient_mullvad_account_timeout()
        return provider_status(
            main.mullvad_provider,
            authenticated=True,
            connected=states["mullvad"]["connected"],
        )

    async def target_connect(_target=None, *, timeout=40):
        nonlocal connect_calls
        connect_calls += 1
        states["mullvad"]["connected"] = True
        return {"ok": True, "error_code": None}

    async def no_wait(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(main.mullvad_provider, "status", target_status)
    monkeypatch.setattr(main.mullvad_provider, "connect", target_connect)
    monkeypatch.setattr(main.asyncio, "sleep", no_wait)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 200
    assert readiness_attempts == 2
    assert connect_calls == 1
    assert sleeps == [vpn_operations.TARGET_READINESS_BACKOFF_SECONDS[0]]
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_exhausted_mullvad_account_timeouts_roll_back_after_bounded_attempts(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    attempts = 0
    rollback_calls = 0
    sleeps = []

    async def target_status(*, timeout=8):
        nonlocal attempts
        attempts += 1
        assert core.setting(main.killswitch.SETTING_TRANSITION) is True
        return transient_mullvad_account_timeout()

    async def target_connect_must_not_run(*_args, **_kwargs):
        pytest.fail("readiness exhaustion must not start a target connect")

    async def source_rollback(_target=None, *, timeout=40):
        nonlocal rollback_calls
        rollback_calls += 1
        states["nordvpn"]["connected"] = True
        return {"ok": True, "error_code": None}

    async def no_wait(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(main.mullvad_provider, "status", target_status)
    monkeypatch.setattr(main.mullvad_provider, "connect", target_connect_must_not_run)
    monkeypatch.setattr(main.provider, "connect", source_rollback)
    monkeypatch.setattr(main.asyncio, "sleep", no_wait)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider_switch_failed"}
    assert attempts == vpn_operations.TARGET_READINESS_ATTEMPTS
    assert sleeps == list(vpn_operations.TARGET_READINESS_BACKOFF_SECONDS)
    assert rollback_calls == 1
    assert states["nordvpn"]["connected"] is True
    assert states["mullvad"]["connected"] is False
    assert core.setting("vpn.provider_id") == "nordvpn"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_terminal_mullvad_readiness_failure_is_not_retried(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    attempts = 0

    async def signed_out_target(*, timeout=8):
        nonlocal attempts
        attempts += 1
        return provider_status(main.mullvad_provider, authenticated=False, connected=False)

    async def unexpected_sleep(_seconds):
        pytest.fail("terminal readiness failure must not back off or retry")

    monkeypatch.setattr(main.mullvad_provider, "status", signed_out_target)
    monkeypatch.setattr(main.asyncio, "sleep", unexpected_sleep)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 503
    assert attempts == 1
    assert core.setting("vpn.provider_id") == "nordvpn"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_connect_accepted_then_transient_status_is_reconciled_without_second_connect(
    client, monkeypatch
):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    connect_started = False
    connect_calls = 0
    local_observations = 0
    connected_status_observations = 0

    async def target_connect(_target=None, *, timeout=40):
        nonlocal connect_started, connect_calls
        connect_started = True
        connect_calls += 1
        return {"ok": True, "error_code": None}

    async def target_local_status(*, timeout=6):
        nonlocal local_observations
        if not connect_started:
            state = "disconnected"
        else:
            local_observations += 1
            state = "connecting" if local_observations == 1 else "connected"
            states["mullvad"]["connected"] = state == "connected"
        return {
            "installed": True,
            "daemon_active": True,
            "local_control_available": True,
            "connected": state == "connected",
            "connection_state": state,
            "error_code": None,
        }

    async def target_status(*, timeout=8):
        nonlocal connected_status_observations
        if states["mullvad"]["connected"]:
            connected_status_observations += 1
            if connected_status_observations == 1:
                return transient_mullvad_account_timeout(connected=True)
        return provider_status(
            main.mullvad_provider,
            authenticated=True,
            connected=states["mullvad"]["connected"],
        )

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(main.mullvad_provider, "connect", target_connect)
    monkeypatch.setattr(main.mullvad_provider, "local_status", target_local_status)
    monkeypatch.setattr(main.mullvad_provider, "status", target_status)
    monkeypatch.setattr(main.asyncio, "sleep", no_wait)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 200
    assert connect_calls == 1
    assert local_observations >= 2
    assert connected_status_observations >= 2
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_connect_timeout_late_success_commits_without_starting_another_connect(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    connect_started = False
    connect_calls = 0
    observations = 0

    async def timed_out_connect(_target=None, *, timeout=40):
        nonlocal connect_started, connect_calls
        connect_started = True
        connect_calls += 1
        return {"ok": False, "error_code": "vpn_connect_timeout"}

    async def target_local_status(*, timeout=6):
        nonlocal observations
        connected = False
        state = "disconnected"
        if connect_started:
            observations += 1
            connected = observations >= 2
            state = "connected" if connected else "connecting"
            states["mullvad"]["connected"] = connected
        return {
            "installed": True,
            "daemon_active": True,
            "local_control_available": True,
            "connected": connected,
            "connection_state": state,
            "error_code": None,
        }

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(main.mullvad_provider, "connect", timed_out_connect)
    monkeypatch.setattr(main.mullvad_provider, "local_status", target_local_status)
    monkeypatch.setattr(main.asyncio, "sleep", no_wait)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 200
    assert connect_calls == 1
    assert observations >= 2
    assert response.json()["status"]["connected"] is True
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_exhausted_retry_and_rollback_failure_stays_fail_closed(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    attempts = 0

    async def target_status(*, timeout=8):
        nonlocal attempts
        attempts += 1
        return transient_mullvad_account_timeout()

    async def failed_rollback(_target=None, *, timeout=40):
        return {"ok": False, "error_code": "provider_connect_failed"}

    async def no_wait(_seconds):
        return None

    monkeypatch.setattr(main.mullvad_provider, "status", target_status)
    monkeypatch.setattr(main.provider, "connect", failed_rollback)
    monkeypatch.setattr(main.asyncio, "sleep", no_wait)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 503
    assert attempts == vpn_operations.TARGET_READINESS_ATTEMPTS
    assert states["nordvpn"]["connected"] is False
    assert core.setting("vpn.provider_id") == "nordvpn"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is True


def test_nord_target_readiness_failure_remains_terminal_and_is_not_retried(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)
    attempts = 0

    async def failed_nord_status(*, timeout=8):
        nonlocal attempts
        attempts += 1
        status = provider_status(main.provider, authenticated=True, connected=False)
        status.update(available=False, error_code="provider_status_unavailable")
        status["management"] = main.provider.management_status(
            installation_state="failed",
            authentication_state="unknown",
            connection_state="disconnected",
            error_code="provider_status_unavailable",
        )
        return status

    async def unexpected_sleep(_seconds):
        pytest.fail("Nord target failure must not use Mullvad-specific retry")

    monkeypatch.setattr(main.provider, "status", failed_nord_status)
    monkeypatch.setattr(main.asyncio, "sleep", unexpected_sleep)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 503
    assert attempts == 1
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_target_connect_failure_rolls_back_without_persisting_target(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)

    async def failed_target_connect(_target=None, *, timeout=40):
        return {"ok": False, "error_code": "provider_connect_failed"}

    monkeypatch.setattr(main.provider, "connect", failed_target_connect)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider_switch_failed"}
    assert states == {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_rollback_failure_keeps_transition_fail_closed_and_canonical_state_disconnected(
    client, monkeypatch
):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)

    async def failed_target_connect(_target=None, *, timeout=40):
        return {"ok": False, "error_code": "provider_connect_failed"}

    async def failed_source_rollback(_target=None, *, timeout=40):
        return {"ok": False, "error_code": "provider_connect_failed"}

    monkeypatch.setattr(main.provider, "connect", failed_target_connect)
    monkeypatch.setattr(main.mullvad_provider, "connect", failed_source_rollback)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider_switch_failed"}
    assert states["nordvpn"]["connected"] is False
    assert states["mullvad"]["connected"] is False
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is True
    operation = vpn_operations.snapshot("provider-switch")
    assert operation["state"] == "failed"
    assert operation["last_error_code"] == "provider_switch_failed"


def test_slow_source_disconnect_is_bounded_and_restores_source(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)

    async def slow_disconnect(*, timeout=15):
        return {"ok": True, "error_code": None}

    async def bounded_wait(_provider, _expected, *, timeout):
        assert timeout == 15
        return {
            "installed": True,
            "daemon_active": True,
            "local_control_available": True,
            "connected": True,
            "connection_state": "disconnecting",
            "error_code": None,
        }

    monkeypatch.setattr(main.mullvad_provider, "disconnect", slow_disconnect)
    monkeypatch.setattr(main, "_wait_for_local_provider_state", bounded_wait)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 409
    assert response.json()["detail"] == "provider_switch_disconnect_failed"
    assert states["mullvad"]["connected"] is True
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_management_reconciliation_failure_rolls_back_switch(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": True},
    }
    configure_statuses(monkeypatch, states)
    reconciliations = []

    async def reconcile():
        reconciliations.append(len(reconciliations) + 1)
        if len(reconciliations) == 1:
            raise main.management_routing.ManagementRoutingError(
                "management_gateway_postcondition_failed"
            )

    monkeypatch.setattr(main.management_routing, "reconcile", reconcile)

    response = client.post("/api/vpn/providers/nordvpn/activate")

    assert response.status_code == 503
    assert response.json() == {"detail": "provider_switch_failed"}
    assert len(reconciliations) >= 3
    assert states["nordvpn"]["connected"] is False
    assert states["mullvad"]["connected"] is True
    assert core.setting("vpn.provider_id") == "mullvad"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is False


def test_failed_old_disconnect_keeps_original_active_provider(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)

    async def disconnect(*, timeout):
        return {"ok": False, "error_code": "provider_disconnect_failed"}

    monkeypatch.setattr(main.provider, "disconnect", disconnect)
    response = client.post("/api/vpn/providers/mullvad/activate")
    assert response.status_code == 409
    assert response.json()["blockers"] == [
        {"code": "provider_switch_disconnect_failed", "provider": "nordvpn"}
    ]
    assert core.setting("vpn.provider_id") == "nordvpn"


def test_old_disconnect_exception_keeps_original_active_provider(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    states = {
        "nordvpn": {"authenticated": True, "connected": True},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)

    async def disconnect(*, timeout):
        raise RuntimeError("untrusted provider detail")

    monkeypatch.setattr(main.provider, "disconnect", disconnect)
    response = client.post("/api/vpn/providers/mullvad/activate")
    assert response.status_code == 409
    assert response.json()["blockers"] == [
        {"code": "provider_switch_disconnect_failed", "provider": "nordvpn"}
    ]
    assert core.setting("vpn.provider_id") == "nordvpn"


def test_external_double_connection_is_reported_and_killswitch_fails_closed(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": True},
            "mullvad": {"authenticated": True, "connected": True},
        },
    )
    catalog = client.get("/api/vpn/providers").json()
    assert {item["status"]["error_code"] for item in catalog["providers"]} == {
        "provider_connection_conflict"
    }
    facts = asyncio.run(main._exclusive_provider_facts())
    assert facts.available is False
    assert facts.protected_egress is False
    assert facts.reason == "provider_conflict"


def test_single_inactive_external_connection_is_already_reported_as_conflict(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": True},
        },
    )
    catalog = client.get("/api/vpn/providers").json()
    assert {item["status"]["error_code"] for item in catalog["providers"]} == {
        "provider_connection_conflict"
    }
    facts = asyncio.run(main._exclusive_provider_facts())
    assert facts.available is False
    assert facts.protected_egress is False
    assert facts.reason == "provider_conflict"


def test_switch_and_connect_are_serialized_so_only_one_operation_wins(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    started = asyncio.Event()
    release = asyncio.Event()

    async def nord_status(*, timeout=8):
        started.set()
        await release.wait()
        return provider_status(main.provider, authenticated=True, connected=False)

    async def mullvad_status(*, timeout=8):
        return provider_status(main.mullvad_provider, authenticated=True, connected=False)

    async def local_status(*, timeout=6):
        return {
            "installed": True,
            "daemon_active": True,
            "local_control_available": True,
            "connected": False,
            "connection_state": "disconnected",
            "error_code": None,
        }

    async def mullvad_gateway_ready():
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main.provider, "status", nord_status)
    monkeypatch.setattr(main.mullvad_provider, "status", mullvad_status)
    monkeypatch.setattr(main.provider, "local_status", local_status)
    monkeypatch.setattr(main.mullvad_provider, "local_status", local_status)
    monkeypatch.setattr(main.mullvad_provider, "prepare_activation", mullvad_gateway_ready)
    request = SimpleNamespace(state=SimpleNamespace(user={"id": 1, "username": "admin"}))

    async def race():
        switching = asyncio.create_task(main.activate_vpn_provider("mullvad", request))
        await started.wait()
        conflict = await main.connect_vpn_provider("nordvpn", main.Connect(target=None), request)
        release.set()
        switched = await switching
        return conflict, switched

    conflict, switched = asyncio.run(race())
    assert conflict.status_code == 409
    assert b'"state":"switching"' in conflict.body
    assert switched["ok"] is True
    assert core.setting("vpn.provider_id") == "mullvad"


def test_cancelled_direct_connect_releases_global_provider_claim(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": False},
        },
    )

    async def cancelled(*_args, **_kwargs):
        raise asyncio.CancelledError

    monkeypatch.setattr(main.provider, "connect", cancelled)
    request = SimpleNamespace(state=SimpleNamespace(user={"id": 1, "username": "admin"}))
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._connect_provider(main.provider, main.Connect(target=None), request))
    operation = vpn_operations.snapshot("provider:nordvpn")
    assert operation["state"] == "failed"
    assert operation["last_error_code"] == "provider_connect_cancelled"
    assert vpn_operations.active_snapshot() is None


def test_unknown_and_not_ready_provider_activation_are_safe(client, monkeypatch):
    assert client.post("/api/vpn/providers/missing/activate").json() == {
        "detail": "provider_not_found"
    }
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": False, "connected": False},
        },
    )
    response = client.post("/api/vpn/providers/mullvad/activate")
    assert response.status_code == 409
    assert response.json() == {
        "detail": "provider_not_ready",
        "ready": False,
        "provider": {
            "id": "mullvad",
            "installed": True,
            "daemon_available": True,
            "authenticated": False,
            "selected": False,
            "tunnel_connected": False,
            "ready_to_activate": False,
        },
        "active_provider_id": "nordvpn",
        "blockers": [{"code": "provider_authentication_required", "provider": "mullvad"}],
    }


def test_daemon_unavailable_activation_has_specific_machine_readable_blocker(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")

    async def nord_status(*, timeout=8):
        return provider_status(main.provider, authenticated=True, connected=False)

    async def mullvad_status(*, timeout=8):
        status = provider_status(main.mullvad_provider, authenticated=False, connected=False)
        status.update(available=False, daemon_active=False)
        status["management"] = main.mullvad_provider.management_status(
            installation_state="daemon_inactive",
            authentication_state="unavailable",
            connection_state="unknown",
            error_code="daemon_unavailable",
        )
        return status

    async def nord_local_status(*, timeout=6):
        return {
            "installed": True,
            "daemon_active": True,
            "local_control_available": True,
            "connected": False,
            "connection_state": "disconnected",
            "error_code": None,
        }

    async def mullvad_local_status(*, timeout=6):
        return {
            "installed": True,
            "daemon_active": False,
            "local_control_available": False,
            "connected": False,
            "connection_state": "unknown",
            "error_code": "daemon_unavailable",
        }

    monkeypatch.setattr(main.provider, "status", nord_status)
    monkeypatch.setattr(main.mullvad_provider, "status", mullvad_status)
    monkeypatch.setattr(main.provider, "local_status", nord_local_status)
    monkeypatch.setattr(main.mullvad_provider, "local_status", mullvad_local_status)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 409
    assert response.json()["blockers"] == [
        {"code": "provider_daemon_unavailable", "provider": "mullvad"}
    ]


def test_already_active_mullvad_activation_is_idempotent(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": False},
        },
    )
    prepared = []

    async def unexpected_prepare():
        prepared.append(True)
        return {"ok": True, "error_code": None}

    async def unexpected_transition():
        pytest.fail("same-provider activation must not enter cross-provider transition")

    monkeypatch.setattr(main.mullvad_provider, "prepare_activation", unexpected_prepare)
    monkeypatch.setattr(main.killswitch, "arm_provider_transition", unexpected_transition)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 200
    assert response.json()["active_provider_id"] == "mullvad"
    assert response.json()["already_active"] is True
    assert prepared == []


def test_runtime_monitor_never_completes_persisted_transition(client, monkeypatch):
    core.set_setting(main.killswitch.SETTING_TRANSITION, True)
    reconciled = []
    sleep_calls = 0

    async def sleep(_seconds):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise asyncio.CancelledError

    async def exclusive_facts():
        pytest.fail("a persisted transition must not use stale provider facts")

    async def reconcile(facts):
        reconciled.append(facts)
        return SimpleNamespace(state="enabled_transition", reason="provider_transition")

    async def complete_transition(_facts):
        pytest.fail("only the transaction owner may release the transition")

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(main, "_exclusive_provider_facts", exclusive_facts)
    monkeypatch.setattr(main.killswitch, "reconcile", reconcile)
    monkeypatch.setattr(main.killswitch, "complete_provider_transition", complete_transition)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._monitor_killswitch())

    assert len(reconciled) == 1
    assert reconciled[0].reason == "provider_transition"
    assert core.setting(main.killswitch.SETTING_TRANSITION) is True


def test_runtime_monitor_does_not_poll_remote_provider_status_during_switch(client, monkeypatch):
    core.set_setting(main.killswitch.SETTING_TRANSITION, True)
    reconciled = []
    sleep_calls = 0

    async def sleep(_seconds):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1:
            raise asyncio.CancelledError

    async def remote_facts_must_not_run():
        pytest.fail("runtime monitor must not poll remote provider status during handoff")

    async def reconcile(facts):
        reconciled.append(facts)
        return SimpleNamespace(state="enabled_transition", reason="provider_transition")

    monkeypatch.setattr(main.asyncio, "sleep", sleep)
    monkeypatch.setattr(main, "_exclusive_provider_facts", remote_facts_must_not_run)
    monkeypatch.setattr(main.vpn_operations, "active_snapshot", lambda: {"state": "switching"})
    monkeypatch.setattr(main.killswitch, "reconcile", reconcile)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main._monitor_killswitch())

    assert len(reconciled) == 1
    assert reconciled[0].reason == "provider_transition"


def test_gateway_preflight_failure_keeps_original_active_provider(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": False},
        },
    )

    async def not_ready():
        return {"ok": False, "error_code": "gateway_settings_failed"}

    monkeypatch.setattr(main.mullvad_provider, "prepare_activation", not_ready)
    response = client.post("/api/vpn/providers/mullvad/activate")
    assert response.status_code == 409
    assert response.json()["blockers"] == [
        {"code": "provider_gateway_configuration_failed", "provider": "mullvad"}
    ]
    assert core.setting("vpn.provider_id") == "nordvpn"


def test_switch_to_disconnected_mullvad_keeps_killswitch_fail_closed(client, monkeypatch):
    core.set_setting("vpn.provider_id", "nordvpn")
    core.set_setting(main.killswitch.SETTING_CONFIGURED, True)
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": False},
        },
    )
    reconciled = []

    async def reconcile(facts):
        reconciled.append(facts)
        return {"ok": True}

    monkeypatch.setattr(main.killswitch, "reconcile", reconcile)

    response = client.post("/api/vpn/providers/mullvad/activate")

    assert response.status_code == 200
    assert core.setting("vpn.provider_id") == "mullvad"
    assert len(reconciled) == 1
    assert reconciled[0].available is False
    assert reconciled[0].protected_egress is False


@pytest.mark.parametrize(
    ("previous_id", "target_id"),
    [("nordvpn", "mullvad"), ("mullvad", "nordvpn")],
)
def test_provider_switch_reconciles_management_routes_before_and_after(
    client, monkeypatch, previous_id, target_id
):
    core.set_setting("vpn.provider_id", previous_id)
    configure_statuses(
        monkeypatch,
        {
            "nordvpn": {"authenticated": True, "connected": False},
            "mullvad": {"authenticated": True, "connected": False},
        },
    )
    reconciled = []

    async def reconcile():
        reconciled.append(core.setting("vpn.provider_id"))

    async def prepare_provider_transition():
        reconciled.append(core.setting("vpn.provider_id"))

    monkeypatch.setattr(main.management_routing, "reconcile", reconcile)
    monkeypatch.setattr(
        main.management_routing,
        "prepare_provider_transition",
        prepare_provider_transition,
    )

    response = client.post(f"/api/vpn/providers/{target_id}/activate")

    assert response.status_code == 200
    assert reconciled == [previous_id, target_id]


@pytest.mark.parametrize(
    ("operation", "provider_ok"), [("connect", True), ("reconnect", True), ("connect", False)]
)
def test_connect_reconnect_and_provider_failure_reconcile_management_routes(
    client, monkeypatch, operation, provider_ok
):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)
    reconciled = []

    async def reconcile():
        reconciled.append(operation)

    async def prepare_provider_transition():
        reconciled.append(operation)

    async def provider_operation(_target, *, timeout):
        if provider_ok:
            states["mullvad"]["connected"] = True
        return {"ok": provider_ok, "error_code": None if provider_ok else "provider_connect_failed"}

    monkeypatch.setattr(main.management_routing, "reconcile", reconcile)
    monkeypatch.setattr(
        main.management_routing,
        "prepare_provider_transition",
        prepare_provider_transition,
    )
    monkeypatch.setattr(main.mullvad_provider, operation, provider_operation)

    response = client.post(
        f"/api/vpn/providers/mullvad/{operation}",
        json={} if operation == "reconnect" else {"target": None},
    )

    assert response.status_code == 200
    assert reconciled == [operation, operation]


def test_slow_provider_connect_reconciles_transition_while_command_is_running(monkeypatch):
    prepared = []
    reconciled = []

    async def prepare_provider_transition():
        prepared.append(len(prepared) + 1)

    async def reconcile():
        reconciled.append(True)

    async def slow_operation():
        await asyncio.sleep(0.3)
        return {"ok": True}

    monkeypatch.setattr(
        main.management_routing,
        "prepare_provider_transition",
        prepare_provider_transition,
    )
    monkeypatch.setattr(main.management_routing, "reconcile", reconcile)

    result = asyncio.run(main._run_with_management_routing(slow_operation))

    assert result == {"ok": True}
    assert prepared == [1, 2]
    assert reconciled == [True]


def test_physical_gateway_postcondition_is_a_hard_provider_connect_failure(client, monkeypatch):
    core.set_setting("vpn.provider_id", "mullvad")
    states = {
        "nordvpn": {"authenticated": True, "connected": False},
        "mullvad": {"authenticated": True, "connected": False},
    }
    configure_statuses(monkeypatch, states)

    async def prepare_provider_transition():
        return main.management_routing.ReconcileResult((), 0, 0)

    async def fail_gateway_postcondition():
        raise main.management_routing.ManagementRoutingError(
            "management_gateway_postcondition_failed"
        )

    async def connect(_target, *, timeout):
        states["mullvad"]["connected"] = True
        return {"ok": True, "error_code": None}

    async def disconnect(*, timeout):
        states["mullvad"]["connected"] = False
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(
        main.management_routing,
        "prepare_provider_transition",
        prepare_provider_transition,
    )
    monkeypatch.setattr(main.management_routing, "reconcile", fail_gateway_postcondition)
    monkeypatch.setattr(main.mullvad_provider, "connect", connect)
    monkeypatch.setattr(main.mullvad_provider, "disconnect", disconnect)

    response = client.post("/api/vpn/providers/mullvad/connect", json={"target": None})

    assert response.status_code == 503
    assert response.json() == {"detail": "management_routing_failed"}
    operation = main.vpn_operations.snapshot(connection_id="provider:mullvad")
    assert operation["state"] == "failed"
    assert operation["last_error_code"] == "management_routing_failed"
    assert states["mullvad"]["connected"] is False
