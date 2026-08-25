import asyncio
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from exitlane import core, main, settings
from exitlane.html import render_index
from exitlane.services import timezone as timezone_service

PASSWORD = "correct horse battery staple"
STATIC_DIR = Path(__file__).parents[1] / "exitlane" / "static"
REAL_SET_SYSTEM_TIMEZONE = timezone_service.set_system_timezone


@pytest.fixture
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", database)
    monkeypatch.setattr(main, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(settings, "system_hostname", lambda: "exitlane-host")
    timezone_state = {"value": "Europe/Amsterdam"}

    def read_timezone():
        return timezone_state["value"]

    async def set_timezone(value):
        previous = timezone_state["value"]
        timezone_state["value"] = value
        return timezone_service.TimezoneChange(
            previous=previous,
            current=value,
            changed=previous != value,
        )

    monkeypatch.setattr(timezone_service, "read_system_timezone", read_timezone)
    monkeypatch.setattr(timezone_service, "set_system_timezone", set_timezone)

    with TestClient(main.app) as test_client:
        digest, salt = core.hash_password(PASSWORD)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        core.set_setting("setup_complete", True)
        test_client.app.state.test_timezone_state = timezone_state
        yield test_client


def login(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert response.status_code == 200


def valid_update(**overrides):
    general = {
        "timezone": "Europe/London",
        "provider_refresh_interval_seconds": 15,
    }
    general.update(overrides)
    return {"general": general}


def test_system_timezone_prefers_etc_timezone(tmp_path):
    timezone_file = tmp_path / "timezone"
    timezone_file.write_text("Europe/London\n", encoding="utf-8")
    assert (
        timezone_service.read_system_timezone(timezone_file, tmp_path / "missing")
        == "Europe/London"
    )


def test_system_timezone_falls_back_to_localtime_symlink(tmp_path):
    timezone_file = tmp_path / "timezone"
    timezone_file.write_text("Invalid/Timezone\n", encoding="utf-8")
    zone = tmp_path / "zoneinfo" / "Europe" / "Amsterdam"
    zone.parent.mkdir(parents=True)
    zone.touch()
    localtime = tmp_path / "localtime"
    localtime.symlink_to(zone)
    assert timezone_service.read_system_timezone(timezone_file, localtime) == "Europe/Amsterdam"


def test_timezone_service_uses_fixed_timedatectl_argv_and_verifies_result():
    observed = []
    values = iter(["Europe/Amsterdam", "Europe/London"])

    async def command(*arguments, **options):
        observed.append((arguments, options))
        return 0, "", ""

    result = asyncio.run(
        timezone_service.set_system_timezone(
            "Europe/London",
            command_runner=command,
            timezone_reader=lambda: next(values),
        )
    )
    assert observed == [
        (
            ("/usr/bin/timedatectl", "set-timezone", "Europe/London"),
            {"timeout": 30},
        )
    ]
    assert result.changed is True


def test_timezone_service_maps_unavailable_native_command_to_stable_failure():
    async def unavailable(*_arguments, **_options):
        raise PermissionError("injected inaccessible path")

    with pytest.raises(
        timezone_service.TimezoneOperationError,
        match="system_timezone_change_failed",
    ):
        asyncio.run(
            timezone_service.set_system_timezone(
                "Europe/London",
                command_runner=unavailable,
                timezone_reader=lambda: "Europe/Amsterdam",
            )
        )


def test_timezone_service_rolls_back_mutation_when_verification_fails():
    observed = []
    timezone_state = {"value": "Europe/Amsterdam"}

    async def command(*arguments, **options):
        observed.append((arguments, options))
        requested_timezone = arguments[-1]
        timezone_state["value"] = (
            "Europe/Paris" if requested_timezone == "Europe/London" else requested_timezone
        )
        return 0, "", ""

    with pytest.raises(
        timezone_service.TimezoneOperationError,
        match="system_timezone_verification_failed",
    ):
        asyncio.run(
            timezone_service.set_system_timezone(
                "Europe/London",
                command_runner=command,
                timezone_reader=lambda: timezone_state["value"],
            )
        )

    assert observed == [
        (
            ("/usr/bin/timedatectl", "set-timezone", "Europe/London"),
            {"timeout": 30},
        ),
        (
            ("/usr/bin/timedatectl", "set-timezone", "Europe/Amsterdam"),
            {"timeout": 30},
        ),
    ]
    assert timezone_state["value"] == "Europe/Amsterdam"


@pytest.mark.parametrize("rollback_result", [(1, "", "failed"), PermissionError("denied")])
def test_timezone_service_reports_failed_verification_rollback(rollback_result):
    reported_timezones = iter(["Europe/Amsterdam", "Europe/Paris"])
    calls = 0

    async def command(*_arguments, **_options):
        nonlocal calls
        calls += 1
        if calls == 1:
            return 0, "", ""
        if isinstance(rollback_result, Exception):
            raise rollback_result
        return rollback_result

    with pytest.raises(
        timezone_service.TimezoneOperationError,
        match="system_timezone_rollback_failed",
    ):
        asyncio.run(
            timezone_service.set_system_timezone(
                "Europe/London",
                command_runner=command,
                timezone_reader=lambda: next(reported_timezones),
            )
        )


@pytest.mark.parametrize(
    "value",
    ["../../etc/passwd", "/etc/localtime", "Europe/Amsterdam;id", "Not/A_Zone"],
)
def test_timezone_service_rejects_paths_and_shell_input_without_command(value):
    async def command(*_arguments, **_options):
        raise AssertionError("invalid input reached timedatectl")

    with pytest.raises(timezone_service.TimezoneOperationError, match="invalid_timezone"):
        asyncio.run(
            timezone_service.set_system_timezone(
                value,
                command_runner=command,
                timezone_reader=lambda: "UTC",
            )
        )


def test_product_name_is_fixed_and_header_has_no_preferences_or_instance_name():
    html = render_index()
    javascript = (STATIC_DIR / "js" / "settings.js").read_text(encoding="utf-8")
    assert "<strong>\n      Exitlane\n     </strong>" in html
    header = html.split("</header>", 1)[0]
    assert "language-trigger" not in header
    assert "color-scheme-trigger" not in header
    assert "display_name" not in html + javascript
    assert "instance_name" not in html + javascript


def test_get_settings_as_authenticated_user(client):
    login(client)
    response = client.get("/api/settings")
    assert response.status_code == 200
    body = response.json()
    assert body["general"] == {
        "timezone": "Europe/Amsterdam",
        "provider_refresh_interval_seconds": settings.PROVIDER_REFRESH_INTERVAL_SECONDS,
    }
    assert body["system"]["hostname"] == "exitlane-host"
    assert body["about"]["product"] == "Exitlane"
    assert body["about"]["release_channel"] == "release candidate"
    assert "Europe/London" in body["timezones"]
    assert body["timezones"] == sorted(body["timezones"])
    assert len(body["timezones"]) == len(set(body["timezones"]))
    assert "localtime" not in body["timezones"]
    assert "Factory" not in body["timezones"]


def test_settings_requires_session(client):
    assert client.get("/api/settings").status_code == 401


def test_unknown_fields_are_rejected(client):
    login(client)
    payload = valid_update()
    payload["general"]["surprise"] = True
    assert client.put("/api/settings", json=payload).status_code == 422


def test_unknown_root_field_is_rejected(client):
    login(client)
    payload = valid_update()
    payload["internal"] = True
    assert client.put("/api/settings", json=payload).status_code == 422


@pytest.mark.parametrize("field", ["display_name", "instance_name"])
def test_removed_name_fields_are_rejected(client, field):
    login(client)
    response = client.put("/api/settings", json={"general": {field: "Legacy appliance"}})
    assert response.status_code == 422


def test_invalid_timezone_is_rejected(client):
    login(client)
    assert (
        client.put(
            "/api/settings", json=valid_update(timezone="Moon/Sea_of_Tranquility")
        ).status_code
        == 422
    )


@pytest.mark.parametrize("interval", [1, 301, 2.5, "5", None])
def test_invalid_polling_intervals_are_rejected(client, interval):
    login(client)
    response = client.put(
        "/api/settings",
        json={"general": {"provider_refresh_interval_seconds": interval}},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("interval", [2, 300])
def test_polling_interval_boundaries_are_accepted(client, interval):
    login(client)
    response = client.put(
        "/api/settings",
        json={"general": {"provider_refresh_interval_seconds": interval}},
    )
    assert response.status_code == 200
    assert response.json()["general"]["provider_refresh_interval_seconds"] == interval


def test_partial_update_preserves_unspecified_values(client):
    login(client)
    assert client.put("/api/settings", json=valid_update()).status_code == 200
    response = client.put("/api/settings", json={"general": {"timezone": "Europe/Amsterdam"}})
    assert response.status_code == 200
    assert response.json()["general"] == {
        "timezone": "Europe/Amsterdam",
        "provider_refresh_interval_seconds": 15,
    }


def test_invalid_combination_does_not_partially_update(client):
    login(client)
    response = client.put(
        "/api/settings",
        json={
            "general": {
                "timezone": "Invalid/Timezone",
                "provider_refresh_interval_seconds": 20,
            }
        },
    )
    assert response.status_code == 422
    assert (
        client.get("/api/settings").json()["general"]["provider_refresh_interval_seconds"]
        == settings.PROVIDER_REFRESH_INTERVAL_SECONDS
    )


def test_successful_update_is_persistent_after_reinitialisation(client):
    login(client)
    response = client.put("/api/settings", json=valid_update())
    assert response.status_code == 200
    assert response.json()["general"] == valid_update()["general"]

    core.init()
    assert client.get("/api/settings").json()["general"] == valid_update()["general"]
    assert client.app.state.test_timezone_state["value"] == "Europe/London"


def test_timezone_change_failure_does_not_persist_setting(client, monkeypatch):
    login(client)

    async def fail(_value):
        raise timezone_service.TimezoneOperationError("system_timezone_change_failed")

    monkeypatch.setattr(timezone_service, "set_system_timezone", fail)
    response = client.put(
        "/api/settings",
        json={"general": {"timezone": "Europe/London"}},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "system_timezone_change_failed",
        "field": "timezone",
    }
    assert core.setting(settings.TIMEZONE_KEY, None) is None


def test_storage_failure_rolls_system_timezone_back_without_partial_settings(client):
    login(client)
    with sqlite3.connect(main.DB) as connection:
        connection.executescript(
            f"""
            CREATE TRIGGER reject_timezone_api_update
            BEFORE INSERT ON settings
            WHEN NEW.key = '{settings.TIMEZONE_KEY}'
            BEGIN
                SELECT RAISE(ABORT, 'test failure');
            END;
            """
        )

    response = client.put(
        "/api/settings",
        json={
            "general": {
                "timezone": "Europe/London",
                "provider_refresh_interval_seconds": 20,
            }
        },
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "settings_storage_failed"
    assert client.app.state.test_timezone_state["value"] == "Europe/Amsterdam"
    assert core.setting(settings.TIMEZONE_KEY, None) is None
    assert core.setting(settings.POLLING_INTERVAL_KEY, None) is None


def test_concurrent_timezone_updates_serialize_native_and_database_transaction(client, monkeypatch):
    timezone_state = client.app.state.test_timezone_state
    command_calls = []

    async def scenario():
        first_command_started = asyncio.Event()
        release_first_command = asyncio.Event()
        monkeypatch.setattr(settings, "_SETTINGS_UPDATE_LOCK", asyncio.Lock())

        async def command(*arguments, **_options):
            requested = arguments[-1]
            command_calls.append(requested)
            if requested == "Europe/London":
                first_command_started.set()
                await release_first_command.wait()
            timezone_state["value"] = requested
            return 0, "", ""

        async def set_timezone(value):
            return await REAL_SET_SYSTEM_TIMEZONE(
                value,
                command_runner=command,
                timezone_reader=lambda: timezone_state["value"],
            )

        monkeypatch.setattr(timezone_service, "set_system_timezone", set_timezone)
        london = asyncio.create_task(
            settings.update_settings(settings.SettingsUpdate(general={"timezone": "Europe/London"}))
        )
        await first_command_started.wait()
        paris = asyncio.create_task(
            settings.update_settings(settings.SettingsUpdate(general={"timezone": "Europe/Paris"}))
        )
        await asyncio.sleep(0)
        assert command_calls == ["Europe/London"]
        release_first_command.set()
        await asyncio.gather(london, paris)

    asyncio.run(scenario())

    assert command_calls == ["Europe/London", "Europe/Paris"]
    assert timezone_state["value"] == "Europe/Paris"
    assert core.setting(settings.TIMEZONE_KEY, None) == "Europe/Paris"
    assert settings.timezone_consistency()["consistent"] is True


def test_startup_reconciliation_converges_valid_explicit_setting(client):
    core.set_setting(settings.TIMEZONE_KEY, "Europe/London")
    change = asyncio.run(settings.reconcile_timezone())
    assert change == timezone_service.TimezoneChange(
        previous="Europe/Amsterdam",
        current="Europe/London",
        changed=True,
    )
    assert client.app.state.test_timezone_state["value"] == "Europe/London"
    assert settings.timezone_consistency()["consistent"] is True


def test_startup_reconciliation_is_noop_when_timezones_match(client):
    core.set_setting(settings.TIMEZONE_KEY, "Europe/Amsterdam")
    assert asyncio.run(settings.reconcile_timezone()) is None


def test_startup_reconciliation_reports_invalid_stored_timezone(client):
    core.set_setting(settings.TIMEZONE_KEY, "Moon/Sea_of_Tranquility")
    with pytest.raises(
        timezone_service.TimezoneOperationError,
        match="invalid_stored_timezone",
    ):
        asyncio.run(settings.reconcile_timezone())
    assert settings.timezone_consistency() == {
        "configured": True,
        "consistent": False,
        "error": "invalid_stored_timezone",
    }


def test_missing_database_values_use_existing_defaults(client):
    login(client)
    with sqlite3.connect(main.DB) as connection:
        connection.execute(
            "DELETE FROM settings WHERE key IN (?, ?)",
            (
                settings.TIMEZONE_KEY,
                settings.POLLING_INTERVAL_KEY,
            ),
        )
    body = client.get("/api/settings").json()
    assert body["general"]["timezone"] == "Europe/Amsterdam"


def test_legacy_name_settings_are_ignored(client):
    login(client)
    core.set_setting("display_name", "Old display name")
    core.set_setting("instance_name", "Old instance name")
    body = client.get("/api/settings").json()
    serialized = str(body).lower()
    assert "display_name" not in serialized
    assert "instance_name" not in serialized
    assert "old display name" not in serialized
    assert "old instance name" not in serialized


def test_browser_preferences_are_not_stored_in_sqlite(client):
    login(client)
    assert (
        client.put("/api/settings", json={"general": {"timezone": "Europe/London"}}).status_code
        == 200
    )
    with sqlite3.connect(main.DB) as connection:
        keys = {row[0] for row in connection.execute("SELECT key FROM settings")}
    assert "language" not in keys
    assert "color_scheme" not in keys
    assert "theme" not in keys


def test_setup_admin_payload_and_hostname_placement_are_unchanged():
    wizard = (STATIC_DIR / "js" / "wizard.js").read_text(encoding="utf-8")
    html = render_index()
    admin_payload = wizard.split('postJson("/api/setup/admin"', 1)[1].split(");", 1)[0]
    assert "username" in admin_payload
    assert "password" in admin_payload
    assert "language" not in admin_payload
    assert "color" not in admin_payload
    assert html.count('id="settings-hostname"') == 1
    general = html.split('data-settings-page="general"', 1)[1]
    about = html.split('data-i18n="settings.about.eyebrow"', 1)[1]
    assert 'id="settings-hostname"' in general
    assert 'id="settings-hostname"' not in about


def test_corrupt_database_setting_uses_default(client):
    login(client)
    with sqlite3.connect(main.DB) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
            (settings.TIMEZONE_KEY, "not-json"),
        )
        connection.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
            (settings.POLLING_INTERVAL_KEY, '"not-an-integer"'),
        )
    body = client.get("/api/settings").json()
    assert body["general"]["timezone"] == "Europe/Amsterdam"
    assert (
        body["general"]["provider_refresh_interval_seconds"]
        == settings.PROVIDER_REFRESH_INTERVAL_SECONDS
    )


def test_set_settings_rolls_back_complete_transaction(client):
    with sqlite3.connect(main.DB) as connection:
        connection.executescript(
            f"""
            CREATE TRIGGER reject_timezone_update
            BEFORE INSERT ON settings
            WHEN NEW.key = '{settings.TIMEZONE_KEY}'
            BEGIN
                SELECT RAISE(ABORT, 'test failure');
            END;
            """
        )
    with pytest.raises(core.SettingsStorageError):
        core.set_settings(
            {
                settings.POLLING_INTERVAL_KEY: 20,
                settings.TIMEZONE_KEY: "Europe/London",
            }
        )
    assert core.setting(settings.POLLING_INTERVAL_KEY, None) is None


def test_read_only_values_cannot_be_changed(client):
    login(client)
    payload = valid_update()
    payload["system"] = {"hostname": "changed", "session_duration_seconds": 60}
    assert client.put("/api/settings", json=payload).status_code == 422


def test_response_contains_no_secrets(client):
    login(client)
    body = client.get("/api/settings").text.lower()
    for forbidden in ("password_hash", "session_token", "provider_token", "private_key"):
        assert forbidden not in body


def test_response_has_expected_changeability_metadata(client):
    login(client)
    metadata = client.get("/api/settings").json()["metadata"]
    assert metadata == {
        "runtime_editable": [
            "general.timezone",
            "general.provider_refresh_interval_seconds",
        ],
        "environment_only": ["system.session_duration_seconds"],
        "restart_required": [],
    }


def test_put_settings_rejects_cross_origin(client):
    login(client)
    response = client.put(
        "/api/settings",
        headers={"Origin": "https://attacker.example"},
        json=valid_update(),
    )
    assert response.status_code == 403
