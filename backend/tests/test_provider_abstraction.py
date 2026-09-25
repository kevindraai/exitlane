import asyncio
import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.providers.base import Provider, ProviderMetadata
from exitlane.providers.registry import ProviderNotFound, ProviderRegistry
from exitlane.services import vpn_selection


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
                installation_state="available",
                authentication_state="signed_in",
                connection_state="disconnected",
            ),
        }

    monkeypatch.setattr(main.provider, "status", status)
    catalog = client.get("/api/vpn/providers")
    assert catalog.status_code == 200
    items = {item["id"]: item for item in catalog.json()["providers"]}
    assert set(items) == {"nordvpn", "mullvad"}
    item = items["nordvpn"]
    assert item["id"] == "nordvpn"
    assert item["icon"] == "shield-check"
    assert item["logo"] == "/assets/providers/nordvpn.svg"
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


def test_provider_status_uses_only_server_specific_latency(client, monkeypatch):
    async def connected(*, timeout=8):
        return {
            "installed": True,
            "authenticated": True,
            "connected": True,
            "server": "nl1234.nordvpn.com",
        }

    monkeypatch.setattr(main.provider, "status", connected)
    monkeypatch.setattr(
        main,
        "server_latency",
        lambda server, *, provider_id="nordvpn": (
            {"latency_ms": 19, "latency_measured_at": "measured"}
            if provider_id == "nordvpn" and server == "nl1234.nordvpn.com"
            else {"latency_ms": None, "latency_measured_at": None}
        ),
    )
    status = client.get("/api/vpn/providers/nordvpn/status").json()["status"]
    assert status["latency_ms"] == 19
    assert status["server"] == "nl1234.nordvpn.com"


def test_connected_provider_status_measures_exact_server_once_during_polling(client, monkeypatch):
    calls = []
    release = asyncio.Event()

    async def connected(*, timeout=8):
        return {
            "installed": True,
            "authenticated": True,
            "connected": True,
            "country": "France",
            "server": " FR825.NORDVPN.COM. ",
        }

    async def measure(hostname):
        calls.append(hostname)
        await release.wait()
        return {"latency_ms": 27, "status": "reachable", "method": "tcp"}

    monkeypatch.setattr(main.provider, "status", connected)
    monkeypatch.setattr(vpn_selection, "tcp_latency", measure)

    async def poll():
        first = asyncio.create_task(main._fresh_vpn_status())
        second = asyncio.create_task(main._fresh_vpn_status())
        await asyncio.sleep(0)
        release.set()
        return await asyncio.gather(first, second)

    snapshots = asyncio.run(poll())
    cached = asyncio.run(main._fresh_vpn_status())

    assert calls == ["fr825.nordvpn.com"]
    assert [item["latency_ms"] for item in snapshots] == [27, 27]
    assert all(item["connected"] is True for item in snapshots)
    assert cached["latency_ms"] == 27
    assert cached["server"] == "fr825.nordvpn.com"


def test_failed_active_latency_probe_preserves_connected_status(client, monkeypatch):
    async def connected(*, timeout=8):
        return {
            "installed": True,
            "authenticated": True,
            "connected": True,
            "country": "France",
            "server": "fr900.nordvpn.com",
        }

    async def fail(_hostname):
        raise OSError("probe unavailable")

    monkeypatch.setattr(main.provider, "status", connected)
    monkeypatch.setattr(vpn_selection, "tcp_latency", fail)

    snapshot = asyncio.run(main._fresh_vpn_status())

    assert snapshot["connected"] is True
    assert snapshot["server"] == "fr900.nordvpn.com"
    assert snapshot["latency_ms"] is None


def test_system_actions_are_allowlisted_post_actions(client, monkeypatch):
    scheduled = []
    monkeypatch.setattr(
        main,
        "schedule_system_action",
        lambda action, actor: scheduled.append((action, actor["username"])),
    )

    for action in ("restart", "reboot", "shutdown"):
        response = client.post(f"/api/system/actions/{action}")
        assert response.status_code == 202
        assert response.json() == {"accepted": True, "action": action}
    assert scheduled == [
        ("restart", "admin"),
        ("reboot", "admin"),
        ("shutdown", "admin"),
    ]
    assert client.get("/api/system/actions/restart").status_code == 405
    assert client.post("/api/system/actions/arbitrary").status_code == 404


def test_system_action_process_uses_fixed_argv_without_shell(monkeypatch):
    calls = []

    async def capture(*argv, **options):
        calls.append((argv, options))

    monkeypatch.setattr(main.asyncio, "create_subprocess_exec", capture)

    async def run_actions():
        for action in ("restart", "reboot", "shutdown"):
            await main._run_system_action(action, {"username": "admin"})

    asyncio.run(run_actions())
    assert [call[0] for call in calls] == [
        ("/usr/bin/systemctl", "restart", "exitlane.service"),
        ("/usr/bin/systemctl", "reboot"),
        ("/usr/bin/systemctl", "poweroff"),
    ]
    assert all("shell" not in call[1] for call in calls)


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
