import asyncio
import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.services.dashboard import SystemStatus

PASSWORD = "correct horse battery staple"


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
        yield test_client


def login(client):
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": PASSWORD},
    )


class Result:
    def __init__(self, configured):
        self.configured = configured
        self.tunnel_available = True
        self.reason = "tunnel_available"

    def as_dict(self):
        return {
            "configured": self.configured,
            "effective": self.configured,
            "state": "enabled_protected" if self.configured else "disabled",
            "tunnel_available": True,
            "protected_sources": ["wg0"],
            "last_transition": None,
        }


def test_killswitch_change_requires_session_and_csrf_and_is_audited(client, monkeypatch):
    events = []
    calls = []

    async def network_facts():
        return object()

    async def enable(_facts):
        calls.append("enable")
        return Result(True)

    monkeypatch.setattr(main.provider, "network_facts", network_facts)
    monkeypatch.setattr(main.killswitch, "enable", enable)
    monkeypatch.setattr(
        main,
        "record_event",
        lambda event, **_options: events.append(event),
    )

    path = "/api/vpn/killswitch/enable"
    assert client.post(path).status_code == 401
    assert client.get("/api/vpn/killswitch").status_code == 401
    assert login(client).status_code == 200
    assert client.post(path, headers={"Origin": "https://attacker.example"}).status_code == 403
    response = client.post(path)

    assert response.status_code == 200
    assert response.json()["configured"] is True
    assert calls == ["enable"]
    assert "network.killswitch_enabled" in events


def test_authenticated_status_reflects_runtime_result(client, monkeypatch):
    async def network_facts():
        return object()

    async def status(_facts):
        return Result(False)

    monkeypatch.setattr(main.provider, "network_facts", network_facts)
    monkeypatch.setattr(main.killswitch, "status", status)

    assert login(client).status_code == 200
    response = client.get("/api/vpn/killswitch")
    assert response.status_code == 200
    assert response.json()["configured"] is False
    assert response.json()["state"] == "disabled"


def test_killswitch_failure_keeps_safe_error_and_audit_category(client, monkeypatch):
    events = []

    async def network_facts():
        return object()

    async def enable(_facts):
        raise main.killswitch.KillswitchError("firewall_apply_failed")

    monkeypatch.setattr(main.provider, "network_facts", network_facts)
    monkeypatch.setattr(main.killswitch, "enable", enable)
    monkeypatch.setattr(
        main,
        "record_event",
        lambda event, **options: events.append((event, options.get("metadata"))),
    )

    assert login(client).status_code == 200
    response = client.post("/api/vpn/killswitch/enable")
    assert response.status_code == 503
    assert response.json() == {"detail": "firewall_apply_failed"}
    assert events[-1] == (
        "network.killswitch_error",
        {"reason": "firewall_apply_failed"},
    )


def test_dashboard_and_vpn_page_use_same_runtime_killswitch_source(monkeypatch):
    calls = []

    async def runtime_status():
        calls.append("status")
        return Result(True).as_dict()

    async def provider_status():
        return {"installed": True, "authenticated": False, "connected": False}

    async def wireguard_status():
        return {"configured": False, "active": False, "connected": False, "peers": []}

    async def system_status(_path):
        return SystemStatus(
            hostname="exitlane",
            cpu_percent=1,
            memory_percent=2,
            memory_used_bytes=2,
            memory_total_bytes=100,
            disk_percent=3,
            disk_used_bytes=3,
            disk_total_bytes=100,
            uptime_seconds=4,
            load_average=(0.1, 0.2, 0.3),
        )

    monkeypatch.setattr(main, "_current_killswitch_status", runtime_status)
    monkeypatch.setattr(main.provider, "status", provider_status)
    monkeypatch.setattr(main, "wireguard_status", wireguard_status)
    monkeypatch.setattr(main, "system_status", system_status)

    security_status = asyncio.run(main.get_killswitch_status())
    dashboard_status = asyncio.run(main.dashboard())

    assert security_status["state"] == "enabled_protected"
    assert dashboard_status.killswitch.state == security_status["state"]
    assert dashboard_status.killswitch.configured is True
    assert calls == ["status", "status"]
