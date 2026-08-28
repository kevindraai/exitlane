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
        "management": provider.management_status(
            installation_state="available",
            authentication_state=authentication,
            connection_state=connection,
        ),
    }


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

    async def mullvad_gateway_ready():
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main.provider, "status", nord_status)
    monkeypatch.setattr(main.mullvad_provider, "status", mullvad_status)
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
def test_invalid_legacy_active_provider_setting_falls_back_to_nordvpn(
    client, stored_provider_id
):
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
    assert response.json() == {"detail": "provider_switch_disconnect_failed"}
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
    assert response.json() == {"detail": "provider_switch_disconnect_failed"}
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


def test_single_inactive_external_connection_is_already_reported_as_conflict(
    client, monkeypatch
):
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

    async def mullvad_gateway_ready():
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main.provider, "status", nord_status)
    monkeypatch.setattr(main.mullvad_provider, "status", mullvad_status)
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
    assert response.json() == {"detail": "provider_not_ready"}


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
    assert response.json() == {"detail": "provider_not_ready"}
    assert core.setting("vpn.provider_id") == "nordvpn"
