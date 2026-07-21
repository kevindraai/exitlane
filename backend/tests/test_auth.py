import hashlib
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

import exitlane.core as core
import exitlane.main as main


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
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        yield test_client


def complete_setup():
    core.set_setting("setup_complete", True)


def login(client):
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )


def test_correct_login_returns_safe_user_and_secure_cookie_attributes(client):
    response = login(client)
    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "user": {"username": "admin"}}
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    assert f"Max-Age={main.SESSION_MAX_AGE_SECONDS}" in cookie
    assert ("Secure" in cookie) is main.SESSION_COOKIE_SECURE
    assert "password" not in cookie.lower()

    token = client.cookies.get(main.SESSION_COOKIE)
    with sqlite3.connect(main.DB) as connection:
        stored_hash = connection.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert token not in stored_hash
    assert stored_hash == hashlib.sha256(token.encode()).hexdigest()

    session = client.get("/api/auth/session").json()
    assert session == {"authenticated": True, "user": {"username": "admin"}}


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("admin", "wrong password"),
        ("does-not-exist", "wrong password"),
    ],
)
def test_invalid_credentials_use_same_generic_error(client, username, password):
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}


def test_logout_invalidates_session(client):
    assert login(client).status_code == 200
    response = client.post("/api/auth/logout")
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=0" in cookie
    assert "expires=" in cookie.lower()
    assert ("Secure" in cookie) is main.SESSION_COOKIE_SECURE
    assert client.get("/api/auth/session").json() == {
        "authenticated": False,
        "user": None,
    }


def test_missing_and_expired_session(client):
    assert client.get("/api/auth/session").json()["authenticated"] is False
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert login(client).status_code == 200
    token = client.cookies.get(main.SESSION_COOKIE)
    with sqlite3.connect(main.DB) as connection:
        connection.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (int(time.time()) - 1, hashlib.sha256(token.encode()).hexdigest()),
        )
    assert client.get("/api/auth/session").json()["authenticated"] is False


def test_protected_route_without_login_after_setup(client):
    complete_setup()
    response = client.get("/api/config/public")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_protected_post_without_login_has_no_information_leak(client):
    complete_setup()
    response = client.post(
        "/api/notifications/webhook",
        json={"name": "test", "url": "https://example.com/hook"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_wizard_route_without_login_before_setup(client):
    response = client.get("/api/config/public")
    assert response.status_code == 200


def test_protected_route_with_login_after_setup(client):
    complete_setup()
    assert login(client).status_code == 200
    response = client.get("/api/config/public")
    assert response.status_code == 200


def test_manipulated_session_token_is_rejected(client):
    complete_setup()
    assert login(client).status_code == 200
    token = client.cookies.get(main.SESSION_COOKIE)
    replacement = "A" if token[-1] != "A" else "B"
    client.cookies.set(main.SESSION_COOKIE, token[:-1] + replacement)
    assert client.get("/api/auth/session").json()["authenticated"] is False
    response = client.get("/api/config/public")
    assert response.status_code == 401


def test_two_sessions_are_independently_valid(client):
    assert login(client).status_code == 200
    first_token = client.cookies.get(main.SESSION_COOKIE)
    client.cookies.clear()
    assert login(client).status_code == 200
    second_token = client.cookies.get(main.SESSION_COOKIE)
    assert first_token != second_token

    with sqlite3.connect(main.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 2

    for token in (first_token, second_token):
        client.cookies.set(main.SESSION_COOKIE, token)
        assert client.get("/api/auth/session").json()["authenticated"] is True


def test_password_change_and_user_delete_invalidate_sessions(client):
    assert login(client).status_code == 200
    with sqlite3.connect(main.DB) as connection:
        digest, salt = core.hash_password("a newly changed password")
        connection.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (digest, salt, "admin"),
        )
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0

    client.cookies.clear()
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a newly changed password"},
    )
    assert response.status_code == 200
    with sqlite3.connect(main.DB) as connection:
        connection.execute("DELETE FROM users WHERE username = ?", ("admin",))
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_static_shell_is_public_but_docs_and_trailing_slash_are_not(client):
    complete_setup()
    assert client.get("/").status_code == 200
    assert client.get("/assets/locales/en.json").status_code == 200
    assert client.get("/docs").status_code == 401
    assert client.get("/api/config/public/").status_code == 401


def test_cross_origin_write_is_rejected(client):
    response = client.post(
        "/api/auth/login",
        headers={"Origin": "https://attacker.example"},
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Request origin not allowed"}


def test_same_origin_write_and_configurable_secure_cookie(client, monkeypatch):
    monkeypatch.setattr(main, "SESSION_COOKIE_SECURE", True)
    response = client.post(
        "/api/auth/login",
        headers={"Origin": "http://testserver"},
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]


def test_session_schema_is_added_to_existing_database(tmp_path, monkeypatch):
    data = tmp_path / "existing-data"
    data.mkdir()
    database = data / "exitlane.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE users(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT
            );
            CREATE TABLE webhooks(
                id INTEGER PRIMARY KEY,
                name TEXT,
                url TEXT,
                enabled INTEGER DEFAULT 1
            );
            """
        )

    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    core.init()

    with sqlite3.connect(database) as connection:
        objects = {
            (row[0], row[1])
            for row in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name LIKE '%session%'"
            )
        }
    assert ("table", "sessions") in objects
    assert ("index", "sessions_user_id_idx") in objects
    assert ("index", "sessions_expires_at_idx") in objects
    assert ("trigger", "delete_user_sessions") in objects
    assert ("trigger", "invalidate_sessions_after_password_change") in objects
