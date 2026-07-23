import sqlite3
import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exitlane import cli, core, main
from exitlane.providers import nordvpn


PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a new administrator password"
ROOT = Path(__file__).parents[2]


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
                "INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        core.set_setting("setup_complete", True)
        yield test_client


def login(client):
    return client.post(
        "/api/auth/login", json={"username": "admin", "password": PASSWORD}
    )


def test_password_change_replaces_hash_revokes_sessions_and_records_event(client):
    assert login(client).status_code == 200
    response = client.post(
        "/api/auth/password",
        json={
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirmation": NEW_PASSWORD,
        },
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True, "reauthentication_required": True}
    with sqlite3.connect(main.DB) as connection:
        password_hash, salt = connection.execute(
            "SELECT password_hash, salt FROM users WHERE username='admin'"
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        event = connection.execute(
            "SELECT metadata_json FROM events WHERE code='auth.password_changed'"
        ).fetchone()
    assert core.verify_password(NEW_PASSWORD, password_hash, salt)
    assert PASSWORD not in password_hash
    assert event == ("{}",)


def test_password_change_validation_and_authentication(client):
    payload = {
        "current_password": PASSWORD,
        "new_password": NEW_PASSWORD,
        "confirmation": NEW_PASSWORD,
    }
    assert client.post("/api/auth/password", json=payload).status_code == 401
    assert login(client).status_code == 200
    for patch, status, detail in (
        ({"current_password": "wrong"}, 401, "invalid_credentials"),
        ({"confirmation": "different password"}, 422, "password_mismatch"),
        ({"new_password": PASSWORD, "confirmation": PASSWORD}, 422, "password_unchanged"),
    ):
        response = client.post("/api/auth/password", json=payload | patch)
        assert response.status_code == status
        assert response.json()["detail"] == detail
    assert client.post(
        "/api/auth/password",
        json=payload | {"new_password": "short", "confirmation": "short"},
    ).status_code == 422
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM events WHERE code='auth.password_changed'"
        ).fetchone()[0] == 0


def test_password_change_rate_limit(client):
    assert login(client).status_code == 200
    payload = {
        "current_password": "wrong",
        "new_password": NEW_PASSWORD,
        "confirmation": NEW_PASSWORD,
    }
    for _ in range(main.PASSWORD_CHANGE_ATTEMPTS):
        assert client.post("/api/auth/password", json=payload).status_code == 401
    assert client.post("/api/auth/password", json=payload).status_code == 429


def test_cli_reset_password_is_interactive_revokes_sessions_and_has_safe_output(
    client, capsys
):
    assert login(client).status_code == 200
    answers = iter([NEW_PASSWORD, NEW_PASSWORD])
    result = cli.reset_password(
        password_reader=lambda _prompt: next(answers), effective_user_id=0
    )
    captured = capsys.readouterr()
    assert result == 0
    assert NEW_PASSWORD not in captured.out + captured.err
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        row = connection.execute(
            "SELECT password_hash, salt FROM users WHERE username='admin'"
        ).fetchone()
        assert connection.execute(
            "SELECT metadata_json FROM events WHERE code='auth.password_reset'"
        ).fetchone() == ("{}",)
    assert core.verify_password(NEW_PASSWORD, *row)


def test_cli_reset_rejects_mismatch_policy_and_insufficient_privilege(client, capsys):
    for answers, user_id, expected in (
        ((NEW_PASSWORD, "different password"), 0, 2),
        (("short", "short"), 0, 2),
        ((NEW_PASSWORD, NEW_PASSWORD), 1000, 77),
    ):
        values = iter(answers)
        assert cli.reset_password(
            password_reader=lambda _prompt: next(values), effective_user_id=user_id
        ) == expected
        captured = capsys.readouterr()
        assert NEW_PASSWORD not in captured.out + captured.err


def test_token_update_is_authenticated_sanitized_and_audited(client, monkeypatch):
    token = "a" * 32

    async def accepted(value):
        assert value == token
        return {"ok": True, "stdout": f"accepted {token}", "stderr": ""}

    monkeypatch.setattr(main.provider, "login_token", accepted)
    assert client.post("/api/providers/nordvpn/token", json={"token": token}).status_code == 401
    assert login(client).status_code == 200
    response = client.post("/api/providers/nordvpn/token", json={"token": token})
    assert response.status_code == 200
    assert token not in response.text
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT metadata_json FROM events WHERE code='provider.token_updated'"
        ).fetchone() == ("{}",)


def test_invalid_token_is_not_audited_or_reflected(client, monkeypatch):
    token = "b" * 32

    async def rejected(_value):
        return {"ok": False, "error": "invalid_token", "stderr": token}

    monkeypatch.setattr(main.provider, "login_token", rejected)
    assert login(client).status_code == 200
    response = client.post("/api/providers/nordvpn/token", json={"token": token})
    assert response.status_code == 422
    assert token not in response.text
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM events WHERE code='provider.token_updated'"
        ).fetchone()[0] == 0


def test_nordvpn_token_login_has_bounded_explicit_subprocess_mitigations(monkeypatch, caplog):
    marker = "dummy-token-never-log-1234567890"
    captured = {}

    async def safe_command(*arguments, **options):
        captured["arguments"] = arguments
        captured["options"] = options
        return 1, "", "upstream rejected credentials"

    monkeypatch.setattr(nordvpn, "command", safe_command)
    result = asyncio.run(nordvpn.provider.login_token(marker))
    assert captured["arguments"] == ("nordvpn", "login", "--token", marker)
    assert captured["options"]["timeout"] == nordvpn.TOKEN_LOGIN_TIMEOUT_SECONDS
    assert marker not in captured["options"]["environment"].values()
    assert "environment" in captured["options"]
    assert result["error"] == "invalid_token"
    assert marker not in str(result)
    assert marker not in caplog.text


def test_nordvpn_token_timeout_is_safely_classified(monkeypatch):
    async def timed_out(*_arguments, **_options):
        return 124, "", "timeout"

    monkeypatch.setattr(nordvpn, "command", timed_out)
    result = asyncio.run(
        nordvpn.provider.login_token("dummy-timeout-token-123456789")
    )
    assert result["ok"] is False
    assert result["error"] == "timeout"


def test_core_subprocess_uses_exec_argv_and_explicit_environment(monkeypatch):
    captured = {}

    class Process:
        returncode = 0

        async def communicate(self, _input):
            return b"", b""

    async def create(*arguments, **options):
        captured["arguments"] = arguments
        captured["options"] = options
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    environment = {"PATH": "/usr/bin"}
    assert asyncio.run(
        core.command("fixed-command", "fixed-argument", timeout=1, environment=environment)
    ) == (0, "", "")
    assert captured["arguments"] == ("fixed-command", "fixed-argument")
    assert captured["options"]["env"] == environment
    assert "shell" not in captured["options"]


def test_debian_installer_installs_root_owned_cli_entrypoint():
    project = (ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8")
    installer = (ROOT / "installer" / "install-debian.sh").read_text(encoding="utf-8")
    assert 'exitlane-cli = "exitlane.cli:main"' in project
    assert 'CLI_TARGET="/usr/local/sbin/exitlane-cli"' in installer
    assert 'install -m 0755 "${VENV_DIR}/bin/exitlane-cli" "${CLI_TARGET}"' in installer
    assert installer.index("create_virtual_environment") < installer.index("install_cli")
