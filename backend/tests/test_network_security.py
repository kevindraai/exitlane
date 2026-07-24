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
    monkeypatch.delenv(network_security.LEGACY_SECURE_COOKIE_ENVIRONMENT, raising=False)
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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTP://ExitLane.Example:80/", "http://exitlane.example"),
        ("https://ExitLane.Example:443/", "https://exitlane.example"),
        ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
    ],
)
def test_http_and_https_public_urls_are_normalized(value, expected):
    assert network_security.normalize_public_url(value) == expected


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
def test_explicit_cookie_policies_are_accepted_and_reported(public_url, policy):
    assert network_security.validate_configuration(public_url, ["127.0.0.1"], policy)[2] == policy


def test_sources_follow_environment_database_default_precedence(isolated_database, monkeypatch):
    defaults = network_security.current_config()
    assert defaults.sources == {
        "public_url": "default",
        "trusted_proxies": "default",
        "secure_cookie_policy": "default",
    }
    core.set_settings(
        {
            network_security.PUBLIC_URL_KEY: "http://database.example",
            network_security.TRUSTED_PROXIES_KEY: ["192.0.2.10", "192.0.2.10"],
        }
    )
    monkeypatch.setenv("EXITLANE_SECURE_COOKIES", "always")
    configured = network_security.current_config()
    assert configured.public_url == "http://database.example"
    assert [str(value) for value in configured.trusted_proxies] == ["192.0.2.10/32"]
    assert configured.secure_cookie_policy == "always"
    assert configured.sources == {
        "public_url": "database",
        "trusted_proxies": "database",
        "secure_cookie_policy": "environment",
    }


@pytest.mark.parametrize(
    ("environment", "locked_field"),
    [
        ("EXITLANE_PUBLIC_URL", "public_url"),
        ("EXITLANE_TRUSTED_PROXIES", "trusted_proxies"),
        ("EXITLANE_SECURE_COOKIES", "secure_cookie_policy"),
    ],
)
def test_each_environment_override_locks_only_its_own_field(
    isolated_database, monkeypatch, environment, locked_field
):
    values = {
        "EXITLANE_PUBLIC_URL": "http://environment.example",
        "EXITLANE_TRUSTED_PROXIES": "192.0.2.1",
        "EXITLANE_SECURE_COOKIES": "always",
    }
    monkeypatch.setenv(environment, values[environment])
    configuration = network_security.current_config().as_public_dict()
    assert configuration["environment_overrides"] == {
        field: field == locked_field for field in network_security.ENVIRONMENT_KEYS
    }


def test_public_url_override_does_not_prevent_proxy_database_update(isolated_database, monkeypatch):
    monkeypatch.setenv("EXITLANE_PUBLIC_URL", "https://environment.example")
    updated, changed = network_security.update_config(
        public_url="https://environment.example",
        trusted_proxies=["192.0.2.10"],
        secure_cookie_policy="auto",
    )
    assert changed == ["trusted_proxies"]
    assert updated.sources["public_url"] == "environment"
    assert updated.sources["trusted_proxies"] == "database"
    assert updated.overrides == {"public_url"}


def test_proxy_lines_are_normalized_atomically_and_report_original_line(
    isolated_database,
):
    normalized = network_security.parse_trusted_proxies(
        " 192.0.2.1 \n\n2001:db8::1\n192.0.2.1\n10.20.30.40/24"
    )
    assert [str(value) for value in normalized] == [
        "192.0.2.1/32",
        "2001:db8::1/128",
        "10.20.30.0/24",
    ]
    core.set_setting(network_security.TRUSTED_PROXIES_KEY, ["192.0.2.20"])
    with pytest.raises(network_security.NetworkSecurityError) as caught:
        network_security.update_config(
            public_url="",
            trusted_proxies=["192.0.2.30", "", "not-an-address"],
            secure_cookie_policy="auto",
        )
    assert caught.value.code == "invalid_trusted_proxy"
    assert caught.value.line == 3
    assert caught.value.value == "not-an-address"
    assert core.setting(network_security.TRUSTED_PROXIES_KEY) == ["192.0.2.20"]


def test_transactional_storage_failure_preserves_all_values(isolated_database, monkeypatch):
    core.set_settings(
        {
            network_security.PUBLIC_URL_KEY: "http://before.example",
            network_security.TRUSTED_PROXIES_KEY: ["192.0.2.1"],
            network_security.COOKIE_POLICY_KEY: "auto",
        }
    )

    def fail_storage(_values):
        raise core.SettingsStorageError("failed")

    monkeypatch.setattr(core, "set_settings", fail_storage)
    with pytest.raises(core.SettingsStorageError):
        network_security.update_config(
            public_url="http://after.example",
            trusted_proxies=["192.0.2.2"],
            secure_cookie_policy="always",
        )
    assert network_security.current_config().public_url == "http://before.example"
    assert [str(value) for value in network_security.current_config().trusted_proxies] == [
        "192.0.2.1/32"
    ]


def test_cli_update_and_reset_share_service_and_preserve_environment_override(
    isolated_database, monkeypatch, capsys
):
    monkeypatch.setenv("EXITLANE_SECURE_COOKIES", "always")
    recorded = []
    monkeypatch.setattr(cli, "record_event", lambda code, **values: recorded.append((code, values)))
    assert (
        cli.set_proxy_config(
            public_url="http://cli.example/",
            trusted_proxies=["192.0.2.10", "2001:db8::1"],
            secure_cookie_policy="disabled",
            effective_user_id=0,
        )
        == 0
    )
    configured = network_security.current_config()
    assert configured.public_url == "http://cli.example"
    assert configured.secure_cookie_policy == "always"
    assert core.setting(network_security.COOKIE_POLICY_KEY, None) is None
    assert "EXITLANE_SECURE_COOKIES" in capsys.readouterr().err
    assert recorded[0][0] == "network.security_settings_updated"
    network_security.reset_database_config()
    reset = network_security.current_config()
    assert reset.public_url == ""
    assert reset.sources["public_url"] == "default"
    assert reset.secure_cookie_policy == "always"
    assert reset.sources["secure_cookie_policy"] == "environment"


def test_cli_environment_only_attempt_does_not_create_shadow_database_values(
    isolated_database, monkeypatch, capsys
):
    monkeypatch.setenv("EXITLANE_PUBLIC_URL", "http://environment.example")
    assert (
        cli.set_proxy_config(
            public_url="http://ignored.example",
            effective_user_id=0,
        )
        == 0
    )
    assert core.stored_settings(network_security.CONFIGURATION_KEYS) == {}
    assert network_security.current_config().public_url == "http://environment.example"
    assert "EXITLANE_PUBLIC_URL" in capsys.readouterr().err


def test_cli_validation_error_reports_code_and_line_without_echoing_input(
    isolated_database, capsys
):
    untrusted_value = "potential-secret.invalid"
    assert (
        cli.set_proxy_config(
            trusted_proxies=["192.0.2.10", "", untrusted_value],
            effective_user_id=0,
        )
        == 2
    )
    output = capsys.readouterr()
    assert output.err.splitlines() == [
        "Proxy configuration rejected: invalid_trusted_proxy on line 3."
    ]
    assert untrusted_value not in output.out
    assert untrusted_value not in output.err


def test_proxy_cli_command_family_routes_status_set_clear_and_reset(
    isolated_database, monkeypatch, capsys
):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "record_event", lambda *_args, **_values: None)
    assert (
        cli.main(
            [
                "proxy",
                "set",
                "--public-url",
                "http://cli.example/",
                "--trusted-proxy",
                "192.0.2.10",
                "--secure-cookies",
                "automatic",
            ]
        )
        == 0
    )
    assert cli.main(["proxy", "status"]) == 0
    status_lines = capsys.readouterr().out.splitlines()
    assert "Public URL: http://cli.example [source: database]" in status_lines
    assert cli.main(["proxy", "clear-public-url"]) == 0
    assert network_security.current_config().public_url == ""
    assert cli.main(["proxy", "clear-trusted-proxies"]) == 0
    assert network_security.current_config().trusted_proxies == ()
    called = []
    monkeypatch.setattr(cli, "reset_network_security", lambda: called.append(True) or 0)
    assert cli.main(["proxy", "reset"]) == 0
    assert called == [True]


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
        invalid_proxy = client.put(
            "/api/deployment/security",
            json={
                "public_url": "",
                "trusted_proxies": ["192.0.2.1", "", "not-a-proxy"],
                "secure_cookie_policy": "auto",
                "current_password": "correct horse battery staple",
            },
        )
        assert invalid_proxy.status_code == 422
        assert invalid_proxy.json()["detail"] == {
            "code": "invalid_trusted_proxy",
            "field": "trusted_proxies",
            "line": 3,
            "value": "not-a-proxy",
        }

        def reject_storage(_values):
            raise core.SettingsStorageError("failed")

        with monkeypatch.context() as storage_failure:
            storage_failure.setattr(core, "set_settings", reject_storage)
            failed_storage = client.put(
                "/api/deployment/security",
                json={
                    "public_url": "",
                    "trusted_proxies": ["192.0.2.1"],
                    "secure_cookie_policy": "auto",
                    "current_password": "correct horse battery staple",
                },
            )
        assert failed_storage.status_code == 500
        assert failed_storage.json()["detail"]["code"] == "settings_storage_failed"
        assert core.setting(network_security.TRUSTED_PROXIES_KEY, None) is None
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
    assert updated.json()["configuration"]["sources"] == {
        "public_url": "database",
        "trusted_proxies": "database",
        "secure_cookie_policy": "database",
    }
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
