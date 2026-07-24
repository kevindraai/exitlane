import asyncio
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.providers import nordvpn
from exitlane.providers.base import InstallationState

ROOT = Path(__file__).parents[2]
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


@pytest.mark.parametrize(
    ("supported", "installed", "unit_output", "daemon_rc", "expected"),
    [
        (True, False, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", 3, "not_installed"),
        (True, True, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", 3, "daemon_inactive"),
        (True, True, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", 0, "available"),
        (False, False, "", 3, "unsupported"),
        (True, False, "ActiveState=activating\nResult=success\nExecMainStatus=0\n", 3, "installing"),
        (True, False, "ActiveState=failed\nResult=exit-code\nExecMainStatus=66\n", 3, "failed"),
        (True, False, "ActiveState=failed\nResult=timeout\nExecMainStatus=0\n", 3, "failed"),
    ],
)
def test_installation_states(
    monkeypatch, supported, installed, unit_output, daemon_rc, expected
):
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: supported)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn" if installed else None)

    async def fake_command(*arguments, **_options):
        if arguments[:2] == ("systemctl", "show"):
            return 0, unit_output, ""
        if arguments[:2] == ("systemctl", "is-active"):
            return daemon_rc, "active" if daemon_rc == 0 else "inactive", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)
    result = asyncio.run(nordvpn.provider.installation_status())
    assert result["state"] == expected
    if unit_output.startswith("ActiveState=failed\nResult=timeout"):
        assert result["error_code"] == "helper_timeout"


def test_installation_api_requires_admin_and_csrf_and_returns_202(client, monkeypatch):
    async def status():
        return {"state": InstallationState.NOT_INSTALLED, "phase": "not_installed", "error_code": None}

    async def started():
        return {"ok": True, "state": InstallationState.INSTALLING}

    monkeypatch.setattr(main.provider, "installation_status", status)
    monkeypatch.setattr(main.provider, "start_installation", started)
    path = "/api/vpn/providers/nordvpn/installation"
    assert client.get(path).status_code == 401
    assert client.post(path).status_code == 401
    assert login(client).status_code == 200
    assert client.post(path, headers={"Origin": "https://attacker.example"}).status_code == 403
    response = client.post(path)
    assert response.status_code == 202
    assert response.json()["state"] == "installing"


def test_duplicate_installation_returns_stable_409(client, monkeypatch):
    async def duplicate():
        return {"ok": False, "error_code": "installation_in_progress"}

    monkeypatch.setattr(main.provider, "start_installation", duplicate)
    assert login(client).status_code == 200
    response = client.post("/api/vpn/providers/nordvpn/installation")
    assert response.status_code == 409
    assert response.json() == {"detail": "installation_in_progress"}


def test_installer_places_fixed_helper_and_unit_without_installing_nordvpn():
    installer = (ROOT / "installer/install-debian.sh").read_text(encoding="utf-8")
    helper = (ROOT / "installer/install-nordvpn.sh").read_text(encoding="utf-8")
    unit = (ROOT / "systemd/exitlane-provider-install-nordvpn.service").read_text(
        encoding="utf-8"
    )
    assert 'install -o root -g root -m 0755 "${NORDVPN_HELPER_SOURCE}"' in installer
    assert 'install -o root -g root -m 0644' in installer
    assert "apt-get install -y -qq nordvpn" not in installer
    assert "ExecStart=/usr/local/libexec/exitlane-install-nordvpn" in unit
    assert "bash -c" not in helper
    assert "eval " not in helper
    assert '[[ "$#" -eq 0 ]]' in helper
    assert 'VERSION_ID:-}" == "13"' in helper
    assert "https://repo.nordvpn.com/" in helper
    assert "command -v nordvpn" in helper
    assert "systemctl enable --now nordvpnd" in helper
    assert helper.index("if command -v nordvpn") < helper.index("curl --fail")


def test_helper_has_stable_exit_codes_and_no_secret_inputs():
    helper = (ROOT / "installer/install-nordvpn.sh").read_text(encoding="utf-8")
    for code in ("64", "65", "66", "67", "68", "77"):
        assert f"die {code} " in helper
    assert "--token" not in helper
    assert "PASSWORD" not in helper
    assert "TOKEN" not in helper
