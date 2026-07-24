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
        (
            True,
            False,
            "ActiveState=inactive\nResult=success\nExecMainStatus=0\n",
            3,
            "not_installed",
        ),
        (
            True,
            True,
            "ActiveState=inactive\nResult=success\nExecMainStatus=0\n",
            3,
            "daemon_inactive",
        ),
        (True, True, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", 0, "available"),
        (False, False, "", 3, "unsupported"),
        (
            True,
            False,
            "ActiveState=activating\nResult=success\nExecMainStatus=0\n",
            3,
            "installing",
        ),
        (True, False, "ActiveState=failed\nResult=exit-code\nExecMainStatus=66\n", 3, "failed"),
        (True, False, "ActiveState=failed\nResult=timeout\nExecMainStatus=0\n", 3, "failed"),
    ],
)
def test_installation_states(monkeypatch, supported, installed, unit_output, daemon_rc, expected):
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: supported)
    monkeypatch.setattr(
        nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn" if installed else None
    )

    async def fake_command(*arguments, **_options):
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, unit_output, ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return daemon_rc, "active" if daemon_rc == 0 else "inactive", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 0, "Status: Disconnected\n", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)
    result = asyncio.run(nordvpn.provider.installation_status())
    assert result["state"] == expected
    if unit_output.startswith("ActiveState=failed\nResult=timeout"):
        assert result["error_code"] == "helper_timeout"


def test_installation_api_requires_admin_and_csrf_and_returns_202(client, monkeypatch):
    async def status():
        return {
            "state": InstallationState.NOT_INSTALLED,
            "phase": "not_installed",
            "error_code": None,
        }

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
    unit = (ROOT / "systemd/exitlane-provider-install-nordvpn.service").read_text(encoding="utf-8")
    assert 'install -o root -g root -m 0755 "${NORDVPN_HELPER_SOURCE}"' in installer
    assert "install -o root -g root -m 0644" in installer
    assert "apt-get install -y -qq nordvpn" not in installer
    assert "ExecStart=/usr/local/libexec/exitlane-install-nordvpn" in unit
    assert "bash -c" not in helper
    assert "eval " not in helper
    assert '[[ "$#" -eq 0 ]]' in helper
    assert 'VERSION_ID:-}" == "13"' in helper
    release_url = next(
        line.split("=", 1)[1].strip('"')
        for line in helper.splitlines()
        if line.startswith("readonly RELEASE_URL=")
    )
    assert release_url == (
        "https://repo.nordvpn.com/deb/nordvpn/debian/pool/main/n/"
        "nordvpn-release/nordvpn-release_1.0.0_all.deb"
    )
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


def test_helper_cleanup_is_nounset_safe_and_preserves_success():
    helper = (ROOT / "installer/install-nordvpn.sh").read_text(encoding="utf-8")
    assert helper.index('work_dir=""') < helper.index("trap cleanup EXIT")
    assert '[[ -n "${work_dir:-}" && -d "${work_dir}" ]]' in helper
    assert 'rm -rf -- "${work_dir}"' in helper
    assert "local exit_code=$?" in helper
    assert 'exit "${exit_code}"' in helper
    assert "warning: provider_installation_cleanup_failed" in helper


def test_helper_performs_explicit_final_availability_validation():
    helper = (ROOT / "installer/install-nordvpn.sh").read_text(encoding="utf-8")
    validation = helper[helper.index("validate_installation()") : helper.index("main()")]
    assert "command -v nordvpn" in validation
    assert "--property=LoadState" in validation
    assert "systemctl is-active --quiet nordvpnd" in validation
    assert "nordvpn status" in validation
    assert "provider_installation_validation_failed" in validation
    assert "provider_daemon_failed" in validation


def test_failed_helper_start_reconciles_to_available(client, monkeypatch):
    statuses = iter(
        [
            {"state": InstallationState.NOT_INSTALLED},
            {"state": InstallationState.AVAILABLE, "phase": "validating", "error_code": None},
        ]
    )

    async def status():
        return next(statuses)

    async def failed_start():
        return {"ok": False, "error_code": "installation_start_failed"}

    monkeypatch.setattr(main.provider, "installation_status", status)
    monkeypatch.setattr(main.provider, "start_installation", failed_start)
    assert login(client).status_code == 200
    response = client.post("/api/vpn/providers/nordvpn/installation")
    assert response.status_code == 202
    assert response.json()["ok"] is True
    assert response.json()["state"] == "available"


def test_stale_failed_unit_is_ignored_when_provider_is_available(monkeypatch):
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    async def fake_command(*arguments, **_options):
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=failed\nResult=exit-code\nExecMainStatus=68\n", ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return 0, "active\n", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 0, "Status: Disconnected\n", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)
    result = asyncio.run(nordvpn.provider.installation_status())
    assert result == {
        "state": InstallationState.AVAILABLE,
        "phase": "validating",
        "error_code": None,
    }


def test_final_provider_validation_failure_has_stable_code(monkeypatch):
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    async def fake_command(*arguments, **_options):
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=failed\nResult=exit-code\nExecMainStatus=68\n", ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return 0, "active\n", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 1, "", "uncontrolled provider output"
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)
    result = asyncio.run(nordvpn.provider.installation_status())
    assert result["state"] == InstallationState.FAILED
    assert result["error_code"] == "provider_installation_validation_failed"
