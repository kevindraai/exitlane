import logging
import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main

PASSWORD = "correct horse battery staple"
ACCOUNT_SENTINEL = "1234123412341234"


def status(provider, authenticated):
    authentication = "signed_in" if authenticated else "signed_out"
    return {
        "installed": True,
        "available": True,
        "authenticated": authenticated,
        "connected": False,
        "state": "disconnected",
        "management": provider.management_status(
            installation_state="available",
            authentication_state=authentication,
            connection_state="disconnected",
        ),
    }


@pytest.fixture
def onboarding(tmp_path, monkeypatch):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", database)
    monkeypatch.setattr(main, "WG_DIR", data / "wireguard")
    authenticated = {"nordvpn": False, "mullvad": False}

    async def nord_status(*, timeout=8):
        return status(main.provider, authenticated["nordvpn"])

    async def mullvad_status(*, timeout=8):
        return status(main.mullvad_provider, authenticated["mullvad"])

    async def nord_authenticate(credential):
        assert credential == "n" * 24
        authenticated["nordvpn"] = True
        return {"ok": True}

    async def mullvad_authenticate(credential):
        assert credential == ACCOUNT_SENTINEL
        authenticated["mullvad"] = True
        return {"ok": True}

    async def mullvad_gateway_ready():
        return {"ok": True, "error_code": None}

    monkeypatch.setattr(main.provider, "status", nord_status)
    monkeypatch.setattr(main.mullvad_provider, "status", mullvad_status)
    monkeypatch.setattr(main.provider, "authenticate", nord_authenticate)
    monkeypatch.setattr(main.mullvad_provider, "authenticate", mullvad_authenticate)
    monkeypatch.setattr(main.mullvad_provider, "prepare_activation", mullvad_gateway_ready)

    with TestClient(main.app) as client:
        digest, salt = core.hash_password(PASSWORD)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
                ("admin", digest, salt),
            )
        core.set_settings(
            {
                "setup_complete": False,
                "setup_system_complete": True,
                "setup_current_step": 3,
            }
        )
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": PASSWORD},
        )
        assert response.status_code == 200
        yield client, authenticated


def select_providers(client, *provider_ids):
    return client.post("/api/setup/providers", json={"provider_ids": list(provider_ids)})


def test_no_provider_flow_keeps_direct_route_deferred(onboarding):
    client, _authenticated = onboarding
    response = select_providers(client)
    assert response.status_code == 200
    assert response.json()["provider_deferred"] is True
    state = client.get("/api/setup/state").json()
    assert state["selected_provider_ids"] == []
    assert state["steps"]["provider"] is True
    assert state["provider_deferred"] is True
    assert state["current_step"] == 4


def test_nord_only_flow_auto_activates_after_authentication(onboarding):
    client, _authenticated = onboarding
    assert select_providers(client, "nordvpn").status_code == 200
    before = client.get("/api/setup/state").json()
    assert before["pending_provider_ids"] == ["nordvpn"]
    assert before["steps"]["provider"] is False

    response = client.post(
        "/api/vpn/providers/nordvpn/authenticate",
        json={"credential": "n" * 24},
    )
    assert response.status_code == 200
    state = client.get("/api/setup/state").json()
    assert state["authenticated_provider_ids"] == ["nordvpn"]
    assert state["active_provider_id"] == "nordvpn"
    assert state["steps"]["provider"] is True
    assert state["current_step"] == 4


def test_mullvad_only_flow_uses_generic_credential_and_clears_secret(onboarding):
    client, _authenticated = onboarding
    assert select_providers(client, "mullvad").status_code == 200
    response = client.post(
        "/api/vpn/providers/mullvad/authenticate",
        json={"credential": ACCOUNT_SENTINEL},
    )
    assert response.status_code == 200
    assert ACCOUNT_SENTINEL not in response.text
    state = client.get("/api/setup/state").json()
    assert state["active_provider_id"] == "mullvad"
    assert state["steps"]["provider"] is True
    with sqlite3.connect(core.DB) as connection:
        event_rows = connection.execute(
            "SELECT code, metadata_json FROM events ORDER BY id"
        ).fetchall()
    assert ACCOUNT_SENTINEL not in repr(event_rows)


def test_mullvad_rejects_the_legacy_nord_token_payload_alias(onboarding):
    client, authenticated = onboarding
    assert select_providers(client, "mullvad").status_code == 200
    response = client.post(
        "/api/vpn/providers/mullvad/authenticate",
        json={"token": ACCOUNT_SENTINEL},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid_credential_payload"}
    assert authenticated["mullvad"] is False


def test_provider_authentication_exception_is_sanitized(
    onboarding, monkeypatch, caplog
):
    client, _authenticated = onboarding
    assert select_providers(client, "mullvad").status_code == 200

    async def failed(_credential):
        raise RuntimeError(f"untrusted provider output {ACCOUNT_SENTINEL}")

    monkeypatch.setattr(main.mullvad_provider, "authenticate", failed)
    with caplog.at_level(logging.WARNING):
        response = client.post(
            "/api/vpn/providers/mullvad/authenticate",
            json={"credential": ACCOUNT_SENTINEL},
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "provider_error"}
    assert ACCOUNT_SENTINEL not in response.text
    assert ACCOUNT_SENTINEL not in caplog.text


def test_none_choice_is_rejected_after_a_provider_was_authenticated(onboarding):
    client, _authenticated = onboarding
    assert select_providers(client, "mullvad").status_code == 200
    assert client.post(
        "/api/vpn/providers/mullvad/authenticate",
        json={"credential": ACCOUNT_SENTINEL},
    ).status_code == 200

    response = select_providers(client)
    assert response.status_code == 409
    assert response.json() == {"detail": "provider_already_authenticated"}
    assert client.get("/api/setup/state").json()["selected_provider_ids"] == ["mullvad"]


def test_both_provider_flow_is_sequential_and_requires_explicit_active_choice(onboarding):
    client, _authenticated = onboarding
    response = select_providers(client, "nordvpn", "mullvad")
    assert response.status_code == 200
    # Registry order is deterministic; tests consume IDs rather than relying on
    # the catalog's first item for provider identity.
    assert response.json()["selected_provider_ids"] == ["mullvad", "nordvpn"]

    assert (
        client.post(
            "/api/vpn/providers/mullvad/authenticate",
            json={"credential": ACCOUNT_SENTINEL},
        ).status_code
        == 200
    )
    after_first = client.get("/api/setup/state").json()
    assert after_first["pending_provider_ids"] == ["nordvpn"]
    assert after_first["steps"]["provider"] is False

    assert (
        client.post(
            "/api/vpn/providers/nordvpn/authenticate",
            json={"credential": "n" * 24},
        ).status_code
        == 200
    )
    both_ready = client.get("/api/setup/state").json()
    assert set(both_ready["authenticated_provider_ids"]) == {"nordvpn", "mullvad"}
    assert both_ready["active_provider_selection_required"] is True
    assert both_ready["steps"]["provider"] is False

    activated = client.post("/api/vpn/providers/mullvad/activate")
    assert activated.status_code == 200
    complete = client.get("/api/setup/state").json()
    assert complete["active_provider_id"] == "mullvad"
    assert complete["active_provider_selection_required"] is False
    assert complete["steps"]["provider"] is True


def test_one_ready_provider_and_one_skipped_completes_setup(onboarding):
    client, _authenticated = onboarding
    assert select_providers(client, "nordvpn", "mullvad").status_code == 200
    assert (
        client.post(
            "/api/vpn/providers/mullvad/authenticate",
            json={"credential": ACCOUNT_SENTINEL},
        ).status_code
        == 200
    )
    skipped = client.post("/api/setup/providers/nordvpn/skip")
    assert skipped.status_code == 200
    state = client.get("/api/setup/state").json()
    assert state["skipped_provider_ids"] == ["nordvpn"]
    assert state["active_provider_id"] == "mullvad"
    assert state["steps"]["provider"] is True


def test_provider_selection_rejects_duplicates_and_unknown_ids(onboarding):
    client, _authenticated = onboarding
    for provider_ids in (["mullvad", "mullvad"], ["unknown"]):
        response = client.post("/api/setup/providers", json={"provider_ids": provider_ids})
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid_provider_selection"}


def test_provider_neutral_first_run_route_allowlist_is_method_bounded():
    allowed = {
        ("GET", "/api/vpn/providers"),
        ("GET", "/api/vpn/providers/mullvad"),
        ("GET", "/api/vpn/providers/mullvad/status"),
        ("GET", "/api/vpn/providers/mullvad/installation"),
        ("POST", "/api/vpn/providers/mullvad/installation"),
        ("POST", "/api/vpn/providers/mullvad/authenticate"),
        ("POST", "/api/vpn/providers/mullvad/activate"),
        ("POST", "/api/setup/providers/mullvad/skip"),
    }
    for method, path in allowed:
        assert main.is_setup_provider_api_route(method, path)
    for method, path in (
        ("DELETE", "/api/vpn/providers/mullvad"),
        ("POST", "/api/vpn/providers/mullvad/status"),
        ("GET", "/api/vpn/providers/mullvad/authenticate"),
        ("POST", "/api/vpn/providers/mullvad/connect"),
        ("POST", "/api/setup/providers/mullvad/skip/extra"),
    ):
        assert not main.is_setup_provider_api_route(method, path)
