import ipaddress
import sqlite3

import pytest
from fastapi.testclient import TestClient

from exitlane import cli, core, main
from exitlane.services import network_security


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", database)
    monkeypatch.setattr(main, "WG_DIR", data / "wireguard")
    for environment in network_security.ENVIRONMENT_KEYS.values():
        monkeypatch.delenv(environment, raising=False)
    core.init()
    return database


def test_database_configuration_is_normalized_and_applied_at_runtime(isolated_database):
    core.set_settings(
        {
            network_security.PUBLIC_URL_KEY: "https://ExitLane.Example.Internal/",
            network_security.TRUSTED_PROXIES_KEY: ["127.0.0.1", "10.20.0.4/24"],
            network_security.COOKIE_POLICY_KEY: "auto",
        }
    )
    configuration = network_security.current_config()
    assert configuration.public_url == "https://exitlane.example.internal"
    assert configuration.trusted_proxies == (
        ipaddress.ip_network("127.0.0.1/32"),
        ipaddress.ip_network("10.20.0.0/24"),
    )


def test_environment_values_override_database(isolated_database, monkeypatch):
    core.set_setting(network_security.PUBLIC_URL_KEY, "http://database.example")
    monkeypatch.setenv("EXITLANE_PUBLIC_URL", "https://Environment.Example/")
    configuration = network_security.current_config()
    assert configuration.public_url == "https://environment.example"
    assert configuration.overrides == {"public_url"}
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.update_config(
            public_url="https://different.example",
            trusted_proxies=[],
            secure_cookie_policy="auto",
        )
    assert caught.value.code == "environment_override"


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.test",
        "https://user:secret@example.test",
        "https://example.test/path",
        "https://example.test?query=yes",
        "https://example.test/#fragment",
        "https://example.test\n.invalid",
    ],
)
def test_invalid_public_urls_are_rejected(value):
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.normalize_public_url(value)
    assert caught.value.code == "invalid_public_url"


@pytest.mark.parametrize("value", ["127.0.0.1", "::1", "10.20.0.4/24"])
def test_ip_and_cidr_entries_are_accepted(value):
    assert network_security.parse_trusted_proxies(value)


@pytest.mark.parametrize("value", ["*", "proxy.local", "10.0.0.1:443", "https://10.0.0.1"])
def test_unsafe_proxy_entries_are_rejected(value):
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.parse_trusted_proxies(value)
    assert caught.value.code == "invalid_trusted_proxy"


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0"])
def test_universal_proxy_ranges_are_blocked(value):
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.parse_trusted_proxies(value)
    assert caught.value.code == "proxy_range_too_broad"


def test_broad_private_range_requires_confirmation():
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.validate_configuration("", ["10.0.0.0/8"], "auto")
    assert caught.value.code == "broad_proxy_confirmation_required"
    assert network_security.validate_configuration(
        "", ["10.0.0.0/8"], "auto", confirm_broad_trust=True
    )[1] == (ipaddress.ip_network("10.0.0.0/8"),)


@pytest.mark.parametrize(
    ("public_url", "policy"),
    [("https://example.test", "never"), ("http://example.test", "always")],
)
def test_inconsistent_cookie_policy_is_rejected(public_url, policy):
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.validate_configuration(public_url, ["127.0.0.1"], policy)
    assert caught.value.code == "inconsistent_cookie_policy"


def test_reset_cli_is_root_only_and_revokes_sessions(isolated_database, monkeypatch):
    core.set_setting(network_security.PUBLIC_URL_KEY, "http://old.example")
    with sqlite3.connect(isolated_database) as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,salt) VALUES('admin','hash','salt')"
        )
        connection.execute(
            """INSERT INTO sessions(token_hash,user_id,expires_at,public_id,created_at,
               last_seen_at,idle_expires_at) VALUES('token',1,9999999999,'id',1,1,9999999999)"""
        )
    assert (
        cli.reset_network_security(
            input_reader=lambda _prompt: "RESET NETWORK SECURITY", effective_user_id=1000
        )
        == 77
    )
    recorded = []
    monkeypatch.setattr(cli, "record_event", lambda code, **_values: recorded.append(code))
    assert (
        cli.reset_network_security(
            input_reader=lambda _prompt: "RESET NETWORK SECURITY", effective_user_id=0
        )
        == 0
    )
    assert network_security.current_config().public_url == ""
    with sqlite3.connect(isolated_database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert recorded == ["network.security_settings_reset_locally"]


def test_authenticated_update_requires_reauthentication_and_records_safe_event(
    isolated_database, monkeypatch
):
    digest, salt = core.hash_password("correct horse battery staple")
    with sqlite3.connect(isolated_database) as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
            ("admin", digest, salt),
        )
    core.set_setting("setup_complete", True)
    recorded = []
    monkeypatch.setattr(
        main, "record_event", lambda code, **values: recorded.append((code, values))
    )
    with TestClient(main.app) as client:
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct horse battery staple"},
            ).status_code
            == 200
        )
        rejected = client.put(
            "/api/deployment/security",
            json={
                "public_url": "",
                "trusted_proxies": ["127.0.0.1"],
                "secure_cookie_policy": "auto",
                "current_password": "wrong",
            },
        )
        assert rejected.status_code == 401
        updated = client.put(
            "/api/deployment/security",
            json={
                "public_url": "",
                "trusted_proxies": ["127.0.0.1"],
                "secure_cookie_policy": "auto",
                "current_password": "correct horse battery staple",
            },
        )
    assert updated.status_code == 200
    event = next(item for item in recorded if item[0] == "network.security_settings_updated")
    assert event[1]["metadata"] == {
        "fields": ["trusted_proxies"],
        "public_scheme": "none",
        "trusted_proxy_count": 1,
    }
    assert "password" not in str(event)


def test_update_requires_totp_when_mfa_is_enabled(isolated_database, monkeypatch):
    digest, salt = core.hash_password("correct horse battery staple")
    with sqlite3.connect(isolated_database) as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
            ("admin", digest, salt),
        )
    core.set_setting("setup_complete", True)
    monkeypatch.setattr(
        main.auth_security,
        "mfa_status",
        lambda _user_id: {"enabled": True, "recovery_codes_remaining": 0},
    )
    verified = []
    monkeypatch.setattr(
        main.auth_security,
        "verify_totp",
        lambda user_id, code: verified.append((user_id, code)) or code == "123456",
    )
    with TestClient(main.app) as client:
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "correct horse battery staple"},
            ).status_code
            == 200
        )
        with sqlite3.connect(isolated_database) as connection:
            connection.execute("UPDATE users SET mfa_enabled=1")
        payload = {
            "public_url": "",
            "trusted_proxies": [],
            "secure_cookie_policy": "auto",
            "current_password": "correct horse battery staple",
        }
        assert client.put("/api/deployment/security", json=payload).status_code == 401
        assert (
            client.put("/api/deployment/security", json={**payload, "code": "123456"}).status_code
            == 200
        )
    assert verified == [(1, "123456")]


def test_database_proxy_configuration_is_used_for_next_request(
    isolated_database,
):
    digest, salt = core.hash_password("correct horse battery staple")
    with sqlite3.connect(isolated_database) as connection:
        connection.execute(
            "INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)",
            ("admin", digest, salt),
        )
    core.set_setting("setup_complete", True)
    core.set_settings(
        {
            network_security.PUBLIC_URL_KEY: "https://exitlane.example.test",
            network_security.TRUSTED_PROXIES_KEY: ["0.0.0.0/32"],
            network_security.COOKIE_POLICY_KEY: "auto",
        }
    )
    with TestClient(main.app) as client:
        response = client.post(
            "/api/auth/login",
            headers={
                "Origin": "https://exitlane.example.test",
                "X-Forwarded-For": "192.0.2.20",
                "X-Forwarded-Proto": "https",
            },
            json={"username": "admin", "password": "correct horse battery staple"},
        )
    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]
