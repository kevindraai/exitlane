import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.providers.base import Provider, ProviderMetadata
from exitlane.providers.registry import ProviderNotFound, ProviderRegistry


class StubProvider(Provider):
    id = "stub"
    display_name = "Stub VPN"
    metadata = ProviderMetadata(
        id=id,
        display_name=display_name,
        short_name="Stub",
        description="Test provider",
        icon="provider-stub",
    )

    async def status(self, *, timeout=8):
        return {"installed": True, "authenticated": True, "connected": False}

    async def connect(self, target=None, *, timeout=45):
        return {"ok": True}

    async def disconnect(self, *, timeout=15):
        return {"ok": True}


def test_registry_lookup_is_deterministic_and_rejects_duplicates():
    provider = StubProvider()
    registry = ProviderRegistry([provider], default_id=provider.id)
    assert registry.get("stub") is provider
    assert registry.all() == (provider,)
    with pytest.raises(ProviderNotFound):
        registry.get("missing")
    with pytest.raises(ValueError, match="already registered"):
        registry.register(StubProvider())


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
        core.set_setting("setup_complete", True)
        assert (
            test_client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct horse battery staple"},
            ).status_code
            == 200
        )
        yield test_client


def test_provider_catalog_exposes_safe_metadata_and_capabilities(client, monkeypatch):
    async def status(*, timeout=8):
        return {
            "installed": True,
            "authenticated": True,
            "connected": False,
            "management": main.provider.management_status(
                installation_state="installed",
                authentication_state="signed_in",
                connection_state="disconnected",
            ),
        }

    monkeypatch.setattr(main.provider, "status", status)
    catalog = client.get("/api/vpn/providers")
    assert catalog.status_code == 200
    item = catalog.json()["providers"][0]
    assert item["id"] == "nordvpn"
    assert item["icon"] == "shield-check"
    assert not {"token", "credential", "secret", "password"} & item.keys()
    assert item["status"]["management"]["authentication"]["state"] == "signed_in"
    assert item["status"]["management"]["connection"]["state"] == "disconnected"
    assert item["status"]["observed_at"]
    assert item["status"]["latency_ms"] is None

    detail = client.get("/api/vpn/providers/nordvpn/status")
    assert detail.status_code == 200
    assert detail.json()["provider"]["id"] == "nordvpn"
    capabilities = detail.json()["status"]["management"]["capabilities"]
    assert capabilities["can_select_country"] is True
    assert capabilities["can_manage_provider_killswitch"] is False


def test_unknown_provider_is_safe_and_legacy_status_remains_available(client, monkeypatch):
    assert client.get("/api/vpn/providers/missing").json() == {"detail": "provider_not_found"}

    async def status(*, timeout=8):
        return {"installed": True, "authenticated": False, "connected": False}

    monkeypatch.setattr(main.provider, "status", status)
    assert client.get("/api/vpn/status").status_code == 200
    assert client.get("/api/providers/nordvpn/status").status_code == 200


def test_generic_wizard_authentication_selects_and_completes_provider_step(client, monkeypatch):
    async def signed_out(*, timeout=8):
        return {"installed": True, "authenticated": False, "connected": False}

    async def accepted(credential):
        assert credential == "x" * 24
        return {"ok": True}

    monkeypatch.setattr(main.provider, "status", signed_out)
    monkeypatch.setattr(main.provider, "authenticate", accepted)
    core.set_setting("setup_complete", False)
    response = client.post(
        "/api/vpn/providers/nordvpn/authenticate",
        json={"token": "x" * 24},
    )
    assert response.status_code == 200
    assert core.setting("vpn.provider_id") == "nordvpn"
    assert core.setting("setup_provider_complete") is True
    assert core.setting("setup_current_step") == 4
