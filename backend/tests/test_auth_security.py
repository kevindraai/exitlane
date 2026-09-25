import ipaddress
import sqlite3
import time

import pyotp
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from exitlane import core, main, proxy
from exitlane.services import auth_security
from exitlane.services.network_security import NetworkSecurityConfig


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
                "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
                ("admin", digest, salt),
            )
        yield test_client


def login(client):
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct horse battery staple"},
    )


def test_mfa_enrollment_recovery_login_and_digest_only_storage(client):
    assert login(client).status_code == 200
    start = client.post(
        "/api/auth/mfa/enrollment",
        json={"current_password": "correct horse battery staple"},
    )
    assert start.status_code == 200
    assert start.headers["cache-control"].startswith("no-store")
    enrollment = start.json()
    assert 'class="mfa-qr-svg"' in enrollment["qr_svg"]
    assert 'class="mfa-qr-modules"' in enrollment["qr_svg"]
    assert 'stroke="#000"' in enrollment["qr_svg"]
    assert 'fill="#fff"' in enrollment["qr_svg"]
    assert enrollment["qr_svg"].startswith("<svg")
    with sqlite3.connect(main.DB) as connection:
        stored = connection.execute("SELECT encrypted_secret FROM mfa_enrollments").fetchone()[0]
    assert enrollment["setup_key"].encode() not in stored

    confirmation = client.post(
        "/api/auth/mfa/enrollment/confirm",
        json={
            "enrollment": enrollment["enrollment"],
            "code": pyotp.TOTP(enrollment["setup_key"]).now(),
        },
    )
    assert confirmation.status_code == 200
    recovery_codes = confirmation.json()["recovery_codes"]
    assert len(recovery_codes) == auth_security.RECOVERY_CODE_COUNT
    with sqlite3.connect(main.DB) as connection:
        serialized = " ".join(
            row[0] for row in connection.execute("SELECT code_hash FROM recovery_codes")
        )
    assert all(code not in serialized for code in recovery_codes)

    client.post("/api/auth/logout")
    first_factor = login(client)
    assert first_factor.json() == {"authenticated": False, "mfa_required": True}
    assert client.get("/api/settings").status_code == 401
    recovered = client.post("/api/auth/mfa", json={"code": recovery_codes[0], "mode": "recovery"})
    assert recovered.status_code == 200
    assert recovered.json()["recovery_code_used"] is True
    client.post("/api/auth/logout")
    login(client)
    assert (
        client.post(
            "/api/auth/mfa", json={"code": recovery_codes[0], "mode": "recovery"}
        ).status_code
        == 401
    )


def test_pending_enrollment_cancel_and_disable_remove_all_mfa_material(client):
    assert login(client).status_code == 200
    pending = client.post(
        "/api/auth/mfa/enrollment",
        json={"current_password": "correct horse battery staple"},
    ).json()
    assert client.delete("/api/auth/mfa/enrollment").json() == {"ok": True}
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM mfa_enrollments").fetchone()[0] == 0

    pending = client.post(
        "/api/auth/mfa/enrollment",
        json={"current_password": "correct horse battery staple"},
    ).json()
    confirmed = client.post(
        "/api/auth/mfa/enrollment/confirm",
        json={
            "enrollment": pending["enrollment"],
            "code": pyotp.TOTP(pending["setup_key"]).now(),
        },
    )
    assert confirmed.status_code == 200
    status = client.get("/api/auth/security").json()["mfa"]
    assert set(status) == {"enabled", "updated_at", "recovery_codes_remaining"}
    assert "recovery_codes" not in status

    client.post(
        "/api/auth/mfa/enrollment",
        json={"current_password": "correct horse battery staple"},
    )
    with sqlite3.connect(main.DB) as connection:
        connection.execute("UPDATE users SET last_totp_counter=NULL")
    disabled = client.post(
        "/api/auth/mfa/disable",
        json={
            "current_password": "correct horse battery staple",
            "code": pyotp.TOTP(pending["setup_key"]).now(),
        },
    )
    assert disabled.json() == {"ok": True, "reauthentication_required": True}
    assert "recovery_codes" not in disabled.json()
    with sqlite3.connect(main.DB) as connection:
        assert connection.execute("SELECT COUNT(*) FROM mfa_enrollments").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0
        assert connection.execute(
            "SELECT mfa_enabled,encrypted_totp_secret FROM users"
        ).fetchone() == (0, None)


def test_totp_counter_replay_is_rejected(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    core.init()
    auth_security.ensure_master_key()
    digest, salt = core.hash_password("correct horse battery staple")
    secret = pyotp.random_base32()
    now = int(time.time())
    monkeypatch.setattr(auth_security.time, "time", lambda: now)
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            """INSERT INTO users(username,password_hash,salt,mfa_enabled,encrypted_totp_secret)
               VALUES(?,?,?,?,?)""",
            ("admin", digest, salt, 1, auth_security.encrypt_secret(secret)),
        )
        user_id = connection.execute("SELECT id FROM users").fetchone()[0]
    code = pyotp.TOTP(secret).at(now)
    assert auth_security.verify_totp(user_id, code)
    assert not auth_security.verify_totp(user_id, code)


def _request(peer, headers=(), scheme="http"):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "scheme": scheme,
            "server": ("exitlane", 8787),
            "client": (peer, 1234),
            "headers": [(name.lower().encode(), value.encode()) for name, value in headers],
        }
    )


def test_forwarded_headers_require_trusted_direct_peer(monkeypatch):
    headers = (("x-forwarded-for", "198.51.100.8"), ("x-forwarded-proto", "https"))
    monkeypatch.setattr(
        proxy,
        "current_config",
        lambda: NetworkSecurityConfig("", (), "auto", frozenset()),
    )
    direct = proxy.request_security(_request("10.0.0.5", headers))
    assert direct.client_ip == "10.0.0.5"
    assert direct.scheme == "http"
    assert direct.forwarded_ignored

    monkeypatch.setattr(
        proxy,
        "current_config",
        lambda: NetworkSecurityConfig(
            "",
            (ipaddress.ip_network("10.0.0.0/24"),),
            "auto",
            frozenset(),
        ),
    )
    forwarded = proxy.request_security(_request("10.0.0.5", headers))
    assert forwarded.client_ip == "198.51.100.8"
    assert forwarded.scheme == "https"
    assert forwarded.direct_peer_trusted


def test_automatic_secure_cookie_uses_public_url_but_not_untrusted_forwarded_header(
    monkeypatch,
):
    headers = (("x-forwarded-proto", "https"),)
    monkeypatch.setattr(
        proxy,
        "_configuration",
        lambda: NetworkSecurityConfig("", (), "auto", frozenset()),
    )
    unconfigured = proxy.request_security(_request("192.0.2.10", headers))
    assert unconfigured.scheme == "http"
    assert not unconfigured.secure_cookie
    assert unconfigured.forwarded_ignored

    monkeypatch.setattr(
        proxy,
        "_configuration",
        lambda: NetworkSecurityConfig(
            "https://exitlane.example",
            (),
            "auto",
            frozenset(),
        ),
    )
    configured = proxy.request_security(_request("192.0.2.10", headers))
    assert configured.scheme == "http"
    assert configured.secure_cookie


@pytest.mark.parametrize(
    ("policy", "scheme", "expected"),
    [
        ("auto", "http", False),
        ("auto", "https", True),
        ("always", "http", True),
        ("never", "https", False),
    ],
)
def test_secure_cookie_policies_are_deterministic(policy, scheme, expected):
    state = proxy.RequestSecurity(
        client_ip="192.0.2.1",
        scheme=scheme,
        direct_peer_trusted=False,
        reverse_proxy=False,
        forwarded_ignored=False,
        cookie_policy=policy,
    )
    assert state.secure_cookie is expected


@pytest.fixture
def challenge_appliance(tmp_path, monkeypatch):
    data = tmp_path / "challenge-appliance"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    core.init()
    auth_security.ensure_master_key()
    secret = pyotp.random_base32()
    digest, salt = core.hash_password("correct horse battery staple")
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            """INSERT INTO users(username,password_hash,salt,mfa_enabled,encrypted_totp_secret)
               VALUES(?,?,?,?,?)""",
            ("admin", digest, salt, 1, auth_security.encrypt_secret(secret)),
        )
        user_id = connection.execute("SELECT id FROM users").fetchone()[0]
        recovery = auth_security.new_recovery_codes(connection, user_id, int(time.time()))
    return user_id, secret, recovery


@pytest.mark.parametrize("mode", ["totp", "recovery"])
def test_mfa_failed_attempts_persist_and_exhaust_challenge(challenge_appliance, mode):
    user_id, secret, recovery = challenge_appliance
    challenge = auth_security.start_challenge(user_id, "127.0.0.1")
    for attempt in range(1, auth_security.MFA_MAX_ATTEMPTS + 1):
        expected = (
            "too_many_attempts" if attempt == auth_security.MFA_MAX_ATTEMPTS else "invalid_mfa_code"
        )
        with pytest.raises(auth_security.AuthSecurityError, match=f"^{expected}$"):
            auth_security.consume_challenge(challenge, "invalid-code", mode, "127.0.0.1")
        with sqlite3.connect(core.DB) as connection:
            row = connection.execute("SELECT attempts FROM mfa_challenges").fetchone()
        assert row == (None if attempt == auth_security.MFA_MAX_ATTEMPTS else (attempt,))
    valid = pyotp.TOTP(secret).now() if mode == "totp" else recovery[0]
    with pytest.raises(auth_security.AuthSecurityError, match="^mfa_challenge_expired$"):
        auth_security.consume_challenge(challenge, valid, mode, "127.0.0.1")
    # A rejected challenge must not consume a still-valid one-time credential.
    assert (
        auth_security.verify_totp(user_id, valid)
        if mode == "totp"
        else auth_security.verify_recovery(user_id, valid)
    )


@pytest.mark.parametrize("invalidity", ["expired", "wrong_ip", "already_exhausted"])
def test_invalid_mfa_challenge_deletion_commits_without_burning_recovery(
    challenge_appliance, invalidity
):
    user_id, _, recovery = challenge_appliance
    challenge = auth_security.start_challenge(user_id, "127.0.0.1")
    client_ip = "127.0.0.2" if invalidity == "wrong_ip" else "127.0.0.1"
    with sqlite3.connect(core.DB) as connection:
        if invalidity == "expired":
            connection.execute("UPDATE mfa_challenges SET expires_at=?", (int(time.time()) - 1,))
        elif invalidity == "already_exhausted":
            connection.execute(
                "UPDATE mfa_challenges SET attempts=?", (auth_security.MFA_MAX_ATTEMPTS,)
            )
    with pytest.raises(auth_security.AuthSecurityError, match="^mfa_challenge_expired$"):
        auth_security.consume_challenge(challenge, recovery[0], "recovery", client_ip)
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT count(*) FROM mfa_challenges").fetchone() == (0,)
    assert auth_security.verify_recovery(user_id, recovery[0])


def test_concurrent_mfa_challenge_consumes_only_winners_recovery_code(challenge_appliance):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    user_id, _, recovery = challenge_appliance
    challenge = auth_security.start_challenge(user_id, "127.0.0.1")
    barrier = Barrier(2)

    def attempt(code):
        barrier.wait()
        try:
            auth_security.consume_challenge(challenge, code, "recovery", "127.0.0.1")
        except auth_security.AuthSecurityError as error:
            return error.code
        return "authenticated"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, recovery[:2]))
    assert sorted(results) == ["authenticated", "mfa_challenge_expired"]
    for code, result in zip(recovery, results, strict=False):
        assert auth_security.verify_recovery(user_id, code) == (result != "authenticated")
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT count(*) FROM mfa_challenges").fetchone() == (0,)


def test_concurrent_mfa_failures_exhaust_last_attempt_once(challenge_appliance):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    user_id, _, recovery = challenge_appliance
    challenge = auth_security.start_challenge(user_id, "127.0.0.1")
    for _ in range(auth_security.MFA_MAX_ATTEMPTS - 1):
        with pytest.raises(auth_security.AuthSecurityError, match="^invalid_mfa_code$"):
            auth_security.consume_challenge(challenge, "invalid-code", "recovery", "127.0.0.1")
    barrier = Barrier(2)

    def attempt(_):
        barrier.wait()
        try:
            auth_security.consume_challenge(challenge, "invalid-code", "recovery", "127.0.0.1")
        except auth_security.AuthSecurityError as error:
            return error.code
        return "unexpected_authentication"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, range(2)))
    assert sorted(results) == ["mfa_challenge_expired", "too_many_attempts"]
    assert auth_security.verify_recovery(user_id, recovery[0])


def test_legacy_users_gain_persistent_mfa_budget_without_changing_credentials(
    tmp_path, monkeypatch
):
    data = tmp_path / "legacy-appliance"
    data.mkdir()
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            "CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT,password_hash TEXT,salt TEXT)"
        )
        connection.execute("INSERT INTO users VALUES(1,'admin','preserved-hash','preserved-salt')")
    core.init()
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute(
            "SELECT password_hash,salt,mfa_failed_attempts,mfa_failure_window_started_at FROM users"
        ).fetchone() == ("preserved-hash", "preserved-salt", 0, None)
        connection.execute(
            "UPDATE users SET mfa_failed_attempts=4,mfa_failure_window_started_at=123"
        )
    core.init()
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute(
            "SELECT mfa_failed_attempts,mfa_failure_window_started_at FROM users"
        ).fetchone() == (4, 123)
    assert core.database_schema_version() == 1


def test_native_login_and_cancel_cannot_reset_mfa_budget_across_process_restart(
    client, monkeypatch
):
    import os
    import subprocess
    import sys

    now = int(time.time())
    monkeypatch.setattr(auth_security.time, "time", lambda: now)
    secret = pyotp.random_base32()
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            "UPDATE users SET mfa_enabled=1,encrypted_totp_secret=?",
            (auth_security.encrypt_secret(secret),),
        )
    for attempt in range(1, auth_security.MFA_MAX_ATTEMPTS + 1):
        assert login(client).json()["mfa_required"]
        result = client.post("/api/auth/mfa", json={"code": "invalid-code", "mode": "totp"})
        assert result.status_code == 401
        expected = "too_many_attempts" if attempt == 5 else "invalid_mfa_code"
        assert result.json() == {"detail": expected}
        assert client.delete("/api/auth/mfa").json() == {"ok": True}
        with sqlite3.connect(core.DB) as connection:
            assert connection.execute(
                "SELECT mfa_failed_attempts,mfa_failure_window_started_at FROM users"
            ).fetchone() == (attempt, now)
    # Fresh Python process, fresh challenge and changed client IP still see the durable budget.
    script = """
from exitlane import core
from exitlane.services import auth_security as auth
core.init()
challenge = auth.start_challenge(1, '192.0.2.99')
try:
    auth.consume_challenge(challenge, 'invalid-code', 'totp', '192.0.2.99')
except auth.AuthSecurityError as error:
    assert error.code == 'too_many_attempts'
else:
    raise AssertionError('persistent MFA budget bypassed')
"""
    subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "EXITLANE_DATA_DIR": str(core.DATA)},
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("mode", ["totp", "recovery"])
def test_persistent_mfa_budget_survives_ip_expiry_and_unlocks_at_exact_deadline(
    challenge_appliance, monkeypatch, mode
):
    user_id, secret, recovery = challenge_appliance
    clock = [int(time.time())]
    monkeypatch.setattr(auth_security.time, "time", lambda: clock[0])
    started = clock[0]
    for attempt in range(1, auth_security.MFA_MAX_ATTEMPTS + 1):
        ip = f"192.0.2.{attempt}"
        challenge = auth_security.start_challenge(user_id, ip)
        expected = "too_many_attempts" if attempt == 5 else "invalid_mfa_code"
        with pytest.raises(auth_security.AuthSecurityError, match=f"^{expected}$"):
            auth_security.consume_challenge(challenge, "invalid-code", mode, ip)
        if attempt < auth_security.MFA_MAX_ATTEMPTS:
            # Neither an IP mismatch nor challenge expiry discards the user's budget.
            with pytest.raises(auth_security.AuthSecurityError, match="^mfa_challenge_expired$"):
                auth_security.consume_challenge(challenge, recovery[0], "recovery", "192.0.2.250")
            expired = auth_security.start_challenge(user_id, ip)
            with sqlite3.connect(core.DB) as connection:
                connection.execute("UPDATE mfa_challenges SET expires_at=?", (clock[0] - 1,))
            with pytest.raises(auth_security.AuthSecurityError, match="^mfa_challenge_expired$"):
                auth_security.consume_challenge(expired, recovery[0], "recovery", ip)
        clock[0] += 1
    clock[0] = started + auth_security.MFA_FAILURE_WINDOW_SECONDS - 1
    challenge = auth_security.start_challenge(user_id, "192.0.2.200")
    valid = pyotp.TOTP(secret).at(clock[0]) if mode == "totp" else recovery[0]
    with pytest.raises(auth_security.AuthSecurityError, match="^too_many_attempts$"):
        auth_security.consume_challenge(challenge, valid, mode, "192.0.2.200")
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT last_totp_counter FROM users").fetchone() == (None,)
        assert connection.execute(
            "SELECT count(*) FROM recovery_codes WHERE used_at IS NOT NULL"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT mfa_failed_attempts,mfa_failure_window_started_at FROM users"
        ).fetchone() == (5, started)
    clock[0] += 1
    challenge = auth_security.start_challenge(user_id, "192.0.2.200")
    valid = pyotp.TOTP(secret).at(clock[0]) if mode == "totp" else recovery[0]
    assert auth_security.consume_challenge(challenge, valid, mode, "192.0.2.200") == (
        user_id,
        mode == "recovery",
    )
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute(
            "SELECT mfa_failed_attempts,mfa_failure_window_started_at FROM users"
        ).fetchone() == (0, None)


def test_successful_mfa_clears_failure_window_before_deadline(challenge_appliance, monkeypatch):
    user_id, _, recovery = challenge_appliance
    now = int(time.time())
    monkeypatch.setattr(auth_security.time, "time", lambda: now)
    challenge = auth_security.start_challenge(user_id, "127.0.0.1")
    with pytest.raises(auth_security.AuthSecurityError, match="^invalid_mfa_code$"):
        auth_security.consume_challenge(challenge, "invalid-code", "recovery", "127.0.0.1")
    assert auth_security.consume_challenge(challenge, recovery[0], "recovery", "127.0.0.1") == (
        user_id,
        True,
    )
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute(
            "SELECT mfa_failed_attempts,mfa_failure_window_started_at FROM users"
        ).fetchone() == (0, None)
