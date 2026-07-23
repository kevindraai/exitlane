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
