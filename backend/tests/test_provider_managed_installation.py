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


@pytest.fixture(autouse=True)
def reset_installation_operation(tmp_path, monkeypatch):
    monkeypatch.setattr(nordvpn, "INSTALL_PHASE_FILE", tmp_path / "installation.phase")
    monkeypatch.setattr(nordvpn, "_gateway_defaults_task", None)
    monkeypatch.setattr(nordvpn, "_installation_monitor_task", None)
    monkeypatch.setattr(nordvpn, "_installation_status_lock", None)
    monkeypatch.setattr(nordvpn, "_installation_started_at", None)
    monkeypatch.setattr(nordvpn, "_installation_starting", False)


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
        (True, True, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", 0, "installing"),
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
    if expected in {InstallationState.NOT_INSTALLED, InstallationState.DAEMON_INACTIVE}:
        assert result["operation_state"] == "not_started"
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


def test_successful_start_creates_server_side_monitor(monkeypatch):
    monitored = asyncio.Event()

    async def status():
        return {"state": InstallationState.NOT_INSTALLED}

    async def fake_command(*arguments, **_options):
        if arguments[:2] == ("systemctl", "reset-failed"):
            return 0, "", ""
        if arguments[:2] == ("systemctl", "start"):
            return 0, "", ""
        raise AssertionError(arguments)

    async def monitor():
        monitored.set()

    monkeypatch.setattr(nordvpn.provider, "installation_status", status)
    monkeypatch.setattr(nordvpn.provider, "_monitor_installation", monitor)
    monkeypatch.setattr(nordvpn, "command", fake_command)

    async def run():
        result = await nordvpn.provider.start_installation()
        await asyncio.wait_for(monitored.wait(), timeout=1)
        return result

    result = asyncio.run(run())
    assert result["ok"] is True
    assert result["state"] == InstallationState.INSTALLING
    assert result["phase"] == "checking_system"
    assert result["installation_in_progress"] is True


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
    validation = helper[helper.index("provider_ready()") : helper.index("main()")]
    assert "command -v nordvpn" in validation
    assert "--property=LoadState" in validation
    assert "systemctl is-active --quiet nordvpnd" in validation
    assert "nordvpn status" in validation
    assert "provider_readiness_timeout" in validation
    assert "PROVIDER_READY_ATTEMPTS" in validation


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
        if arguments == ("nordvpn", "settings"):
            return 0, "Routing: disabled\n", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)

    async def defaults():
        return [{"setting": "routing", "ok": True}]

    monkeypatch.setattr(nordvpn.provider, "defaults", defaults)

    async def reconcile():
        first = await nordvpn.provider.installation_status()
        await asyncio.sleep(0)
        validating = await nordvpn.provider.installation_status()
        completed = await nordvpn.provider.installation_status()
        return first, validating, completed

    first, validating, completed = asyncio.run(reconcile())
    assert first["phase"] == "applying_gateway_settings"
    assert validating["phase"] == "validating_installation"
    assert completed["state"] == InstallationState.AVAILABLE
    assert completed["phase"] == "completed"


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


def test_installation_phase_order_and_step_transitions_are_allowlisted():
    assert nordvpn.INSTALL_PHASES == (
        "checking_system",
        "preparing_repository",
        "verifying_repository",
        "refreshing_packages",
        "installing_client",
        "starting_daemon",
        "waiting_for_provider",
        "applying_gateway_settings",
        "validating_installation",
    )
    for active_index, phase in enumerate(nordvpn.INSTALL_PHASES):
        response = nordvpn._installation_response(phase=phase)
        assert response["phase"] in nordvpn.INSTALL_RESPONSE_PHASES
        assert [step["status"] for step in response["steps"]] == [
            "completed"
            if index < active_index
            else "active"
            if index == active_index
            else "pending"
            for index in range(len(nordvpn.INSTALL_PHASES))
        ]
        assert set(response) == {
            "state",
            "phase",
            "steps",
            "started_at",
            "error_code",
            "installation_in_progress",
            "provider_available",
            "operation_state",
            "retry_action",
        }
        assert "output" not in repr(response).casefold()
        assert "token" not in repr(response).casefold()


def test_definitive_failure_marks_only_current_step():
    response = nordvpn._installation_response(
        phase="failed",
        failed_phase="refreshing_packages",
        error_code="repository_failed",
    )
    statuses = [step["status"] for step in response["steps"]]
    assert statuses.count("failed") == 1
    assert statuses[:3] == ["completed", "completed", "completed"]
    assert statuses[3] == "failed"
    assert set(statuses[4:]) == {"pending"}
    assert response["operation_state"] == "failed"
    assert response["retry_action"] == "restart_installation"


@pytest.mark.parametrize(
    ("phase", "retry_action"),
    [
        ("refreshing_packages", "restart_installation"),
        ("waiting_for_provider", "recheck_provider"),
        ("applying_gateway_settings", "reapply_gateway_settings"),
        ("validating_installation", "revalidate_installation"),
    ],
)
def test_retry_action_is_phase_aware(phase, retry_action):
    response = nordvpn._installation_response(
        phase="failed",
        failed_phase=phase,
        error_code="installation_failed",
    )
    assert response["retry_action"] == retry_action


def test_active_systemd_operation_uses_persisted_phase(monkeypatch):
    nordvpn.INSTALL_PHASE_FILE.write_text("refreshing_packages\n", encoding="utf-8")
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: None)

    async def fake_command(*arguments, **_options):
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=activating\nResult=success\nExecMainStatus=0\n", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)
    status = asyncio.run(nordvpn.provider.installation_status())
    assert status["phase"] == "refreshing_packages"
    assert status["installation_in_progress"] is True
    assert status["provider_available"] is False


def test_signed_out_provider_is_ready_before_gateway_configuration(monkeypatch):
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")
    calls = []

    async def fake_command(*arguments, **_options):
        calls.append(arguments)
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return 0, "active\n", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 1, "", "You are not logged in."
        raise AssertionError(arguments)

    async def defaults():
        assert ("nordvpn", "status") in calls
        return [{"setting": "routing", "ok": True}]

    monkeypatch.setattr(nordvpn, "command", fake_command)
    monkeypatch.setattr(nordvpn.provider, "defaults", defaults)

    async def run():
        applying = await nordvpn.provider.installation_status()
        await asyncio.sleep(0)
        validating = await nordvpn.provider.installation_status()
        completed = await nordvpn.provider.installation_status()
        return applying, validating, completed

    applying, validating, completed = asyncio.run(run())
    assert applying["phase"] == "applying_gateway_settings"
    assert applying["provider_available"] is True
    assert validating["phase"] == "validating_installation"
    assert completed["phase"] == "completed"
    assert all(step["status"] == "completed" for step in completed["steps"])


def test_gateway_failure_is_distinct_and_persisted(monkeypatch):
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    async def fake_command(*arguments, **_options):
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=inactive\nResult=success\nExecMainStatus=0\n", ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return 0, "active\n", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 0, "Status: Disconnected\n", ""
        if arguments == ("nordvpn", "settings"):
            return 0, "Routing: disabled\n", ""
        raise AssertionError(arguments)

    async def defaults():
        return [{"setting": "routing", "ok": False}]

    monkeypatch.setattr(nordvpn, "command", fake_command)
    monkeypatch.setattr(nordvpn.provider, "defaults", defaults)

    async def run():
        await nordvpn.provider.installation_status()
        await asyncio.sleep(0)
        failed = await nordvpn.provider.installation_status()
        persisted = await nordvpn.provider.installation_status()
        return failed, persisted

    failed, persisted = asyncio.run(run())
    for status in (failed, persisted):
        assert status["phase"] == "failed"
        assert status["error_code"] == "gateway_settings_failed"
        assert [step["status"] for step in status["steps"]].count("failed") == 1


def test_stale_gateway_failure_reconciles_when_managed_settings_are_valid(monkeypatch):
    nordvpn.INSTALL_PHASE_FILE.write_text(
        "failed|applying_gateway_settings|gateway_settings_failed\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")

    async def fake_command(*arguments, **_options):
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=inactive\nResult=failed\nExecMainStatus=1\n", ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return 0, "active\n", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 1, "", "You are not logged in."
        if arguments == ("nordvpn", "settings"):
            return (
                0,
                """Technology: NORDLYNX
Routing: enabled
LAN Discovery: enabled
Firewall: true
Kill Switch: off
User Consent: disabled
Auto-connect: false""",
                "",
            )
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)
    status = asyncio.run(nordvpn.provider.installation_status())
    assert status["phase"] == "validating_installation"
    assert status["provider_available"] is True
    assert status["error_code"] is None


def test_gateway_retry_does_not_restart_package_installer(monkeypatch):
    nordvpn.INSTALL_PHASE_FILE.write_text(
        "failed|applying_gateway_settings|gateway_settings_failed\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(nordvpn, "_supports_managed_installation", lambda: True)
    monkeypatch.setattr(nordvpn.shutil, "which", lambda _name: "/usr/bin/nordvpn")
    commands = []
    configured = False

    async def fake_command(*arguments, **_options):
        nonlocal configured
        commands.append(arguments)
        if arguments[:3] == ("systemctl", "show", nordvpn.INSTALL_UNIT):
            return 0, "ActiveState=inactive\nResult=failed\nExecMainStatus=1\n", ""
        if arguments[:3] == ("systemctl", "show", "nordvpnd"):
            return 0, "loaded\n", ""
        if arguments[:2] == ("systemctl", "is-active"):
            return 0, "active\n", ""
        if arguments[:2] == ("nordvpn", "status"):
            return 0, "Status: Disconnected\n", ""
        if arguments == ("nordvpn", "settings"):
            state = "disabled" if configured else "enabled"
            return (
                0,
                f"""Technology: NORDLYNX
Routing: enabled
LAN Discovery: enabled
Firewall: enabled
Kill Switch: disabled
User Consent: disabled
Auto-connect: {state}""",
                "",
            )
        if arguments == ("nordvpn", "set", "autoconnect", "off"):
            configured = True
            return 0, "", ""
        raise AssertionError(arguments)

    monkeypatch.setattr(nordvpn, "command", fake_command)

    async def run():
        result = await nordvpn.provider.start_installation()
        await asyncio.sleep(0)
        return result

    result = asyncio.run(run())
    assert result["phase"] == "applying_gateway_settings"
    assert ("nordvpn", "set", "autoconnect", "off") in commands
    assert not any(arguments[:3] == ("systemctl", "start", "--no-block") for arguments in commands)


def test_helper_reports_every_installation_phase_and_retries_readiness():
    helper = (ROOT / "installer/install-nordvpn.sh").read_text(encoding="utf-8")
    for phase in nordvpn.INSTALL_PHASES[:7]:
        assert phase in helper
    assert "systemctl enable --now nordvpnd" in helper
    assert "systemctl is-active --quiet nordvpnd" in helper
    assert "nordvpn status" in helper
    assert 'sleep "${PROVIDER_READY_DELAY}"' in helper
    assert "nordvpn.service" not in helper
