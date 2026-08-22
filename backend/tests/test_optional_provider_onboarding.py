import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main


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
        digest, salt = core.hash_password("correct horse battery staple")
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        yield test_client


def login(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200


def signed_out_provider(monkeypatch):
    async def status(*, timeout=8):
        return {"installed": False, "authenticated": False, "connected": False}

    monkeypatch.setattr(main.provider, "status", status)


def test_provider_must_be_authenticated_or_explicitly_deferred(client, monkeypatch):
    signed_out_provider(monkeypatch)
    core.set_setting("setup_system_complete", True)
    core.set_setting("wireguard_configured", True)

    state = client.get("/api/setup/state").json()
    assert state["provider_authenticated"] is False
    assert state["provider_deferred"] is False
    assert state["steps"]["provider"] is False
    assert state["current_step"] == 3

    login(client)
    blocked = client.post("/api/setup/complete")
    assert blocked.status_code == 409
    assert "provider" in blocked.json()["detail"]


def test_authenticated_admin_can_defer_and_complete_provider_optional_setup(client, monkeypatch):
    signed_out_provider(monkeypatch)
    core.set_setting("setup_system_complete", True)

    assert client.post("/api/setup/provider/defer").status_code == 401
    login(client)
    response = client.post("/api/setup/provider/defer")

    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "provider_deferred": True,
        "current_step": 4,
    }
    state = client.get("/api/setup/state").json()
    assert state["provider_authenticated"] is False
    assert state["provider_deferred"] is True
    assert state["steps"]["provider"] is True
    assert state["current_step"] == 4

    core.set_setting("wireguard_configured", True)
    assert client.post("/api/setup/complete").status_code == 200
    assert core.setting("setup_complete") is True
    assert client.post("/api/setup/provider/defer").status_code == 409


def test_defer_requires_completed_system_and_rejects_authenticated_provider(client, monkeypatch):
    signed_out_provider(monkeypatch)
    login(client)
    assert client.post("/api/setup/provider/defer").status_code == 409

    core.set_setting("setup_system_complete", True)

    async def authenticated(*, timeout=8):
        return {"installed": True, "authenticated": True, "connected": False}

    monkeypatch.setattr(main.provider, "status", authenticated)
    response = client.post("/api/setup/provider/defer")
    assert response.status_code == 409
    assert response.json() == {"detail": "provider_already_authenticated"}


def test_successful_provider_authentication_clears_deferred_choice(client, monkeypatch):
    signed_out_provider(monkeypatch)
    core.set_setting("setup_system_complete", True)
    login(client)
    assert client.post("/api/setup/provider/defer").status_code == 200

    async def accepted(credential):
        assert credential == "x" * 24
        return {"ok": True}

    monkeypatch.setattr(main.provider, "authenticate", accepted)
    response = client.post(
        "/api/vpn/providers/nordvpn/authenticate",
        json={"token": "x" * 24},
    )

    assert response.status_code == 200
    assert core.setting("setup_provider_deferred") is False
    assert core.setting("setup_provider_complete") is True
    assert core.setting("setup_current_step") == 4
