import hashlib
import ipaddress
import sqlite3
import time

import pytest
import pyotp
from fastapi.testclient import TestClient

import exitlane.core as core
import exitlane.main as main
import exitlane.proxy as proxy
from exitlane.services import auth_security


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
    assert session == {
        "authenticated": True,
        "user": {"username": "admin"},
        "setup_complete": False,
    }


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
    assert response.json() == {"detail": "invalid_credentials"}


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
        "setup_complete": False,
    }


def test_auth_events_are_protected_and_do_not_enumerate_username(client):
    client.post("/api/auth/login", json={"username": "does-not-exist", "password": "wrong password"})
    complete_setup()
    assert client.get("/api/events").status_code == 401
    assert login(client).status_code == 200
    page = client.get("/api/events?category=auth&limit=1").json()
    assert page["items"][0]["code"] == "auth.login_succeeded"
    with sqlite3.connect(main.DB) as connection:
        failure = connection.execute(
            "SELECT actor_username, metadata_json FROM events WHERE code='auth.login_failed'"
        ).fetchone()
    assert failure == (None, '{"reason": "invalid_credentials"}')


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


def test_session_exposes_setup_completion_without_requiring_setup_request(client):
    complete_setup()
    session = client.get("/api/auth/session").json()
    assert session["authenticated"] is False
    assert session["setup_complete"] is True


def test_protected_route_without_login_after_setup(client):
    complete_setup()
    response = client.get("/api/config/public")
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


def test_dashboard_endpoint_requires_session_after_setup(client):
    complete_setup()
    response = client.get("/api/dashboard")
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
    assert response.json() == {"detail": "invalid_origin"}


def test_login_request_phase_tracing_distinguishes_security_and_credentials(
    client, monkeypatch, caplog
):
    verified = []
    sessions = []
    phases = []
    original_verify = main.verify_password
    original_create_session = main.auth_security.create_session

    def traced_verify(*args):
        verified.append(True)
        return original_verify(*args)

    def traced_session(*args):
        sessions.append(True)
        return original_create_session(*args)

    monkeypatch.setattr(main, "verify_password", traced_verify)
    monkeypatch.setattr(main.auth_security, "create_session", traced_session)
    monkeypatch.setattr(
        main, "observe_auth_phase", lambda _request, phase: phases.append(phase)
    )
    payload = {"username": "admin", "password": "wrong password"}

    rejected = client.post(
        "/api/auth/login",
        headers={
            "Origin": "https://exitlane.example.internal",
            "Host": "172.16.130.171:8787",
            "X-Forwarded-Proto": "https",
        },
        json=payload,
    )
    assert rejected.status_code == 403
    assert rejected.json() == {"detail": "invalid_origin"}
    assert verified == []
    assert sessions == []
    assert phases == []
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM events WHERE code='auth.login_failed'"
        ).fetchone()[0] == 0
    assert "reason=invalid_origin" in caplog.text
    assert "exitlane.example.internal" not in caplog.text
    assert "X-Forwarded" not in caplog.text

    credential_failure = client.post("/api/auth/login", json=payload)
    assert credential_failure.status_code == 401
    assert credential_failure.json() == {"detail": "invalid_credentials"}
    assert len(verified) == 1
    assert sessions == []
    assert phases == ["login_handler", "credential_validation"]
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM events WHERE code='auth.login_failed'"
        ).fetchone()[0] == 1

    success = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert success.status_code == 200
    assert len(verified) == 2
    assert len(sessions) == 1
    assert phases[-3:] == [
        "login_handler", "credential_validation", "session_creation"
    ]


def test_body_model_and_rate_limit_phases_are_explicit(client, monkeypatch):
    phases = []
    monkeypatch.setattr(
        main, "observe_auth_phase", lambda _request, phase: phases.append(phase)
    )
    monkeypatch.setattr(main, "MAX_REQUEST_BODY_BYTES", 1024)
    oversized = client.post(
        "/api/auth/login",
        content=b"x" * 1025,
        headers={"Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    assert phases == []

    invalid_model = client.post(
        "/api/auth/login",
        json={"username": [], "password": "dummy-validation-secret"},
    )
    assert invalid_model.status_code == 422
    assert invalid_model.json() == {"detail": "invalid_request"}
    assert "dummy-validation-secret" not in invalid_model.text
    assert phases == []

    payload = {"username": "admin", "password": "wrong password"}
    for _ in range(main.LOGIN_ATTEMPTS):
        assert client.post("/api/auth/login", json=payload).status_code == 401
    phases.clear()
    limited = client.post("/api/auth/login", json=payload)
    assert limited.status_code == 429
    assert limited.json() == {"detail": "too_many_attempts"}
    assert phases == ["login_handler"]


def test_trusted_https_proxy_login_uses_public_origin_secure_cookie_and_session(
    client, monkeypatch
):
    monkeypatch.setattr(
        proxy, "TRUSTED_PROXIES", (ipaddress.ip_network("0.0.0.0/32"),)
    )
    monkeypatch.setattr(proxy, "PUBLIC_URL", "https://ExitLane.Example.Internal/")
    headers = {
        "Origin": "https://exitlane.example.internal:443/",
        "Host": "exitlane.example.internal",
        "X-Forwarded-For": "198.51.100.25",
        "X-Forwarded-Proto": "https",
    }
    response = client.post(
        "/api/auth/login",
        headers=headers,
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]
    token = response.cookies.get(main.SESSION_COOKIE)
    protected = client.get(
        "/api/settings",
        headers={**headers, "Cookie": f"{main.SESSION_COOKIE}={token}"},
    )
    assert protected.status_code == 200


def test_trusted_proxy_wrong_password_reaches_credentials_and_records_failure(
    client, monkeypatch
):
    monkeypatch.setattr(
        proxy, "TRUSTED_PROXIES", (ipaddress.ip_network("0.0.0.0/32"),)
    )
    monkeypatch.setattr(proxy, "PUBLIC_URL", "https://exitlane.example.internal")
    calls = []
    original_verify = main.verify_password

    def traced_verify(*args):
        calls.append(True)
        return original_verify(*args)

    monkeypatch.setattr(main, "verify_password", traced_verify)
    response = client.post(
        "/api/auth/login",
        headers={
            "Origin": "https://EXITLANE.EXAMPLE.INTERNAL:443/",
            "Host": "exitlane.example.internal",
            "X-Forwarded-For": "198.51.100.25",
            "X-Forwarded-Proto": "https",
        },
        json={"username": "admin", "password": "wrong password"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "invalid_credentials"}
    assert calls == [True]
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM events WHERE code='auth.login_failed'"
        ).fetchone()[0] == 1


def test_trusted_https_proxy_mfa_challenge_and_session_cookies_are_secure(
    client, monkeypatch
):
    secret = pyotp.random_base32()
    with sqlite3.connect(main.DB) as connection:
        connection.execute(
            "UPDATE users SET mfa_enabled=1, encrypted_totp_secret=? WHERE username='admin'",
            (auth_security.encrypt_secret(secret),),
        )
    monkeypatch.setattr(
        proxy, "TRUSTED_PROXIES", (ipaddress.ip_network("0.0.0.0/32"),)
    )
    monkeypatch.setattr(proxy, "PUBLIC_URL", "https://exitlane.example.internal")
    headers = {
        "Origin": "https://exitlane.example.internal",
        "Host": "exitlane.example.internal",
        "X-Forwarded-For": "198.51.100.25",
        "X-Forwarded-Proto": "https",
    }
    first_factor = client.post(
        "/api/auth/login",
        headers=headers,
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert first_factor.json() == {"authenticated": False, "mfa_required": True}
    assert "Secure" in first_factor.headers["set-cookie"]
    challenge = first_factor.cookies.get(main.MFA_CHALLENGE_COOKIE)
    verified = client.post(
        "/api/auth/mfa",
        headers={
            **headers,
            "Cookie": f"{main.MFA_CHALLENGE_COOKIE}={challenge}",
        },
        json={"code": pyotp.TOTP(secret).now(), "mode": "totp"},
    )
    assert verified.status_code == 200
    assert "Secure" in verified.headers["set-cookie"]
    assert verified.cookies.get(main.SESSION_COOKIE)


def test_invalid_or_conflicting_proxy_origin_stops_before_model_and_credentials(
    client, monkeypatch
):
    monkeypatch.setattr(
        proxy, "TRUSTED_PROXIES", (ipaddress.ip_network("0.0.0.0/32"),)
    )
    monkeypatch.setattr(proxy, "PUBLIC_URL", "https://exitlane.example.internal")

    def must_not_verify(*_args):
        raise AssertionError("credential validation must not run")

    monkeypatch.setattr(main, "verify_password", must_not_verify)
    for headers, detail in (
        (
            {
                "Origin": "https://other.example",
                "X-Forwarded-Proto": "https",
            },
            "invalid_origin",
        ),
        (
            {
                "Origin": "https://exitlane.example.internal",
                "X-Forwarded-Proto": "https,http",
            },
            "deployment_origin_mismatch",
        ),
    ):
        response = client.post(
            "/api/auth/login",
            headers=headers,
            content=b'{"not":"validated"}',
        )
        assert response.status_code == 403
        assert response.json() == {"detail": detail}
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM events WHERE code='auth.login_failed'"
        ).fetchone()[0] == 0


def test_origin_normalization_is_exact_and_normalizes_only_default_ports():
    assert proxy.normalized_origin("https://EXAMPLE.test/") == (
        "https", "example.test", 443
    )
    assert proxy.normalized_origin("https://example.test:443") == (
        "https", "example.test", 443
    )
    assert proxy.normalized_origin("http://example.test:80/") == (
        "http", "example.test", 80
    )
    assert proxy.normalized_origin("https://example.test:444") != proxy.normalized_origin(
        "https://example.test"
    )
    assert proxy.normalized_origin("https://example.test.evil") != proxy.normalized_origin(
        "https://example.test"
    )
    assert proxy.normalized_origin("https://user@example.test") is None


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "http://testserver.evil.example"},
        {"Origin": "http://user@testserver"},
        {"Origin": "ftp://testserver"},
        {"Referer": "http://attacker.example/path"},
        {"Origin": "https://attacker.example", "Referer": "http://testserver/"},
    ],
)
def test_malformed_or_cross_site_sources_are_rejected(client, headers):
    response = client.post(
        "/api/auth/login",
        headers=headers,
        json={"username": "admin", "password": "correct horse battery staple"},
    )
    assert response.status_code == 403


def test_valid_referer_and_non_browser_client_follow_documented_policy(client):
    payload = {"username": "admin", "password": "correct horse battery staple"}
    assert client.post("/api/auth/login", headers={"Referer": "http://testserver/"}, json=payload).status_code == 200
    client.cookies.clear()
    assert client.post("/api/auth/login", json=payload).status_code == 200


def test_oversized_body_is_rejected_before_route_processing(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_REQUEST_BODY_BYTES", 1024)
    response = client.post(
        "/api/auth/login",
        content=b"x" * 1025,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


@pytest.mark.parametrize("path", ["/", "/api/health", "/api/auth/session", "/missing"])
def test_security_headers_cover_html_api_and_errors(client, path):
    response = client.get(path)
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cross-origin-embedder-policy"] == "require-corp"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert response.headers["permissions-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert "server" not in response.headers


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
