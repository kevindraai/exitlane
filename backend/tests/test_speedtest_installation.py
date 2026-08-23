import asyncio
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main
from exitlane.services import connection_diagnostics, speedtest_installation

ROOT = Path(__file__).parents[2]
PASSWORD = "correct horse battery staple"
INSTALLATION_PATH = "/api/diagnostics/speedtest/installation"


@pytest.fixture(autouse=True)
def reset_speedtest_operation(tmp_path, monkeypatch):
    monkeypatch.setattr(
        speedtest_installation, "INSTALL_PHASE_FILE", tmp_path / "installation.phase"
    )
    speedtest_installation.reset_for_tests()
    yield
    speedtest_installation.reset_for_tests()


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
    return client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})


def test_installation_endpoints_require_authentication_and_protect_origin(client):
    assert client.get(INSTALLATION_PATH).status_code == 401
    assert client.post(INSTALLATION_PATH).status_code == 401
    assert login(client).status_code == 200
    assert (
        client.post(
            INSTALLATION_PATH,
            headers={"Origin": "https://attacker.example"},
            json={},
        ).status_code
        == 403
    )


def test_installation_confirmation_is_stable_and_accepted_returns_202(client, monkeypatch):
    response = speedtest_installation._response(
        status="running",
        phase="checking_system",
        supported_runtime=True,
        can_install=False,
        installation_in_progress=True,
    )

    async def start():
        return response

    monkeypatch.setattr(speedtest_installation, "start_installation", start)
    assert login(client).status_code == 200
    rejected = client.post(INSTALLATION_PATH, json={"confirm_package_change": True})
    assert rejected.status_code == 422
    assert rejected.json() == {"detail": "speedtest_installation_confirmation_required"}
    accepted = client.post(
        INSTALLATION_PATH,
        json={
            "confirm_package_change": True,
            "confirm_personal_noncommercial": True,
            "accept_license": True,
            "accept_gdpr": True,
        },
    )
    assert accepted.status_code == 202
    assert accepted.json() == response


def test_public_snapshot_is_redacted_and_allowlisted(monkeypatch):
    monkeypatch.setattr(speedtest_installation, "_supports_managed_installation", lambda: True)

    async def unavailable():
        return False, "speedtest_tool_unavailable"

    async def fake_command(*arguments, **_options):
        assert arguments[:2] == ("systemctl", "show")
        return 0, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", "secret output"

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", unavailable)
    monkeypatch.setattr(speedtest_installation, "command", fake_command)
    response = asyncio.run(speedtest_installation.status())
    assert response["status"] == "warning"
    assert response["error_code"] == "speedtest_tool_unavailable"
    assert response["can_install"] is True
    assert set(response) == {
        "tool",
        "status",
        "phase",
        "steps",
        "error_code",
        "started_at",
        "available",
        "supported_runtime",
        "can_install",
        "installation_in_progress",
        "requires_terms_confirmation",
    }
    assert "secret" not in repr(response)
    for step in response["steps"]:
        assert set(step) == {"phase", "status", "error_code"}


def test_unsupported_runtime_has_no_install_capability(monkeypatch):
    monkeypatch.setattr(speedtest_installation, "_supports_managed_installation", lambda: False)

    async def unavailable():
        return False, "speedtest_tool_unavailable"

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", unavailable)
    response = asyncio.run(speedtest_installation.status())
    assert response["status"] == "warning"
    assert response["phase"] == "unsupported"
    assert response["supported_runtime"] is False
    assert response["can_install"] is False


@pytest.mark.parametrize("value", ("pending", "running", "passed", "warning", "failed"))
def test_public_status_vocabulary_is_allowlisted(value):
    response = speedtest_installation._response(
        status=value,
        phase="failed" if value == "failed" else "checking_system",
        error_code="installation_failed" if value == "failed" else None,
        supported_runtime=True,
        can_install=False,
        installation_in_progress=value in {"pending", "running"},
        failed_phase="checking_system" if value == "failed" else None,
    )
    assert response["status"] == value


def test_reloaded_phase_is_reconciled_to_running(monkeypatch):
    speedtest_installation.INSTALL_PHASE_FILE.write_text("verifying_package\n", encoding="utf-8")
    monkeypatch.setattr(speedtest_installation, "_supports_managed_installation", lambda: True)

    async def unavailable():
        return False, "speedtest_tool_unavailable"

    async def fake_command(*arguments, **_options):
        assert arguments[:2] == ("systemctl", "show")
        return 0, "ActiveState=activating\nResult=success\nExecMainStatus=0\n", ""

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", unavailable)
    monkeypatch.setattr(speedtest_installation, "command", fake_command)
    response = asyncio.run(speedtest_installation.status())
    assert response["status"] == "running"
    assert response["phase"] == "verifying_package"
    assert response["installation_in_progress"] is True


def test_single_flight_starts_systemd_once_and_never_executes_speedtest(monkeypatch):
    starts = []
    monkeypatch.setattr(speedtest_installation, "_supports_managed_installation", lambda: True)

    async def unavailable():
        return False, "speedtest_tool_unavailable"

    async def fake_command(*arguments, **_options):
        if arguments[:2] == ("systemctl", "show"):
            return 0, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", ""
        if arguments[:2] == ("systemctl", "reset-failed"):
            return 0, "", ""
        if arguments[:3] == ("systemctl", "start", "--no-block"):
            starts.append(arguments)
            return 0, "", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", unavailable)
    monkeypatch.setattr(speedtest_installation, "command", fake_command)

    async def exercise():
        return await asyncio.gather(
            speedtest_installation.start_installation(),
            speedtest_installation.start_installation(),
        )

    first, second = asyncio.run(exercise())
    assert len(starts) == 1
    assert first["installation_in_progress"] is True
    assert second["installation_in_progress"] is True
    assert all(command[0] == "systemctl" for command in starts)


def test_speedtest_action_detects_missing_tool_without_terms(monkeypatch):
    async def unavailable():
        return False, "speedtest_tool_unavailable"

    async def snapshot():
        return {
            "supported_runtime": True,
            "can_install": True,
            "requires_terms_confirmation": True,
        }

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", unavailable)
    monkeypatch.setattr(speedtest_installation, "status", snapshot)
    response = asyncio.run(connection_diagnostics.speedtest())
    assert response == {
        "status": "warning",
        "code": "speedtest_tool_unavailable",
        "detail": {
            "available": False,
            "supported_runtime": True,
            "can_install": True,
            "requires_terms_confirmation": True,
        },
    }


def test_speedtest_action_requires_visible_terms_and_bandwidth_before_fixed_argv(monkeypatch):
    calls = []

    async def available():
        return True, ""

    async def fake_command(*arguments, **_options):
        calls.append(arguments)
        return (
            0,
            json.dumps(
                {
                    "ping": {"latency": 12.3},
                    "download": {"bandwidth": 12500000},
                    "upload": {"bandwidth": 2500000},
                }
            ),
            "",
        )

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", available)
    monkeypatch.setattr(connection_diagnostics, "command", fake_command)
    missing = asyncio.run(connection_diagnostics.speedtest())
    assert missing["code"] == "speedtest_terms_confirmation_required"
    assert calls == []
    passed = asyncio.run(
        connection_diagnostics.speedtest(
            confirm_personal_noncommercial=True,
            accept_license=True,
            accept_gdpr=True,
            confirm_bandwidth=True,
        )
    )
    assert passed["status"] == "passed"
    assert calls == [
        (
            "/usr/bin/speedtest",
            "--accept-license",
            "--accept-gdpr",
            "--format=json",
        )
    ]


def test_speedtest_action_serializes_measurements(monkeypatch):
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = []

    async def available():
        return True, ""

    async def fake_command(*arguments, **_options):
        calls.append(arguments)
        entered.set()
        await release.wait()
        return 1, "", ""

    monkeypatch.setattr(speedtest_installation, "_official_cli_state", available)
    monkeypatch.setattr(connection_diagnostics, "command", fake_command)

    async def exercise():
        first = asyncio.create_task(
            connection_diagnostics.speedtest(
                confirm_personal_noncommercial=True,
                accept_license=True,
                accept_gdpr=True,
                confirm_bandwidth=True,
            )
        )
        await entered.wait()
        second = await connection_diagnostics.speedtest(
            confirm_personal_noncommercial=True,
            accept_license=True,
            accept_gdpr=True,
            confirm_bandwidth=True,
        )
        release.set()
        return await first, second

    first, second = asyncio.run(exercise())
    assert first["code"] == "speedtest_failed"
    assert second == {"status": "warning", "code": "speedtest_action_in_progress", "detail": {}}
    assert len(calls) == 1


def test_installer_and_helpers_have_pinned_artifact_shared_lock_and_recovery_contract():
    installer = (ROOT / "installer/install-debian.sh").read_text(encoding="utf-8")
    helper = (ROOT / "installer/install-speedtest.sh").read_text(encoding="utf-8")
    nordvpn_helper = (ROOT / "installer/install-nordvpn.sh").read_text(encoding="utf-8")
    unit = (ROOT / "systemd/exitlane-speedtest-install.service").read_text(encoding="utf-8")
    assert "speedtest_1.2.0.84-1.ea6b6773cf_amd64.deb" in helper
    assert ".deb/download.deb?distro_version_id=221" in helper
    assert "35e084567a6388631fb10cf01e5e0d6b57a67d34ede2b72ba111b3d9164c8b94" in helper
    assert "curl --fail --silent --show-error --location" in helper
    assert "--proto '=https' --tlsv1.2" in helper
    assert "timeout --signal=TERM" in helper
    assert "apt-get install -y -qq --no-install-recommends" in helper
    assert "curl |" not in helper
    assert "apt-key" not in helper
    assert "sources.list" not in helper
    assert 'PACKAGE_OPERATION_LOCK="/run/lock/exitlane-package-operation.lock"' in helper
    assert 'PACKAGE_OPERATION_LOCK="/run/lock/exitlane-package-operation.lock"' in nordvpn_helper
    assert 'flock -n "${PACKAGE_LOCK_FD}"' in helper
    assert 'flock -n "${PACKAGE_LOCK_FD}"' in nordvpn_helper
    assert "dpkg-query --listfiles" in helper
    assert "speedtest --accept-license" not in helper
    assert "write_phase" in helper and 'mv -f -- "${temporary_file}"' in helper
    assert "ExecStart=/usr/local/libexec/exitlane-install-speedtest" in unit
    assert "RuntimeDirectory=exitlane-speedtest-install" in unit
    assert "SPEEDTEST_INSTALL_SERVICE_TARGET" in installer
    assert '"${SPEEDTEST_INSTALL_SERVICE_TARGET}"' in installer
    assert '"${SPEEDTEST_HELPER_TARGET}"' in installer
    assert "install_speedtest_helper" in installer
