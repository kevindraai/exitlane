import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import exitlane.core as core
import exitlane.main as main
from exitlane.html import render_index
import exitlane.settings as settings

PASSWORD = "correct horse battery staple"
STATIC_DIR = Path(__file__).parents[1] / "exitlane" / "static"


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
    monkeypatch.setattr(settings, "system_timezone", lambda: "Europe/Amsterdam")

    with TestClient(main.app) as test_client:
        digest, salt = core.hash_password(PASSWORD)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                ("admin", digest, salt),
            )
        core.set_setting("setup_complete", True)
        yield test_client


def login(client):
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": PASSWORD}
    )
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
    assert settings.system_timezone(timezone_file, tmp_path / "missing") == "Europe/London"


def test_system_timezone_falls_back_to_localtime_symlink(tmp_path):
    timezone_file = tmp_path / "timezone"
    timezone_file.write_text("Invalid/Timezone\n", encoding="utf-8")
    zone = tmp_path / "zoneinfo" / "Europe" / "Amsterdam"
    zone.parent.mkdir(parents=True)
    zone.touch()
    localtime = tmp_path / "localtime"
    localtime.symlink_to(zone)
    assert settings.system_timezone(timezone_file, localtime) == "Europe/Amsterdam"


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
    response = client.put(
        "/api/settings", json={"general": {field: "Legacy appliance"}}
    )
    assert response.status_code == 422


def test_invalid_timezone_is_rejected(client):
    login(client)
    assert client.put(
        "/api/settings", json=valid_update(timezone="Moon/Sea_of_Tranquility")
    ).status_code == 422


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
    response = client.put(
        "/api/settings", json={"general": {"timezone": "Europe/Amsterdam"}}
    )
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
    assert client.put(
        "/api/settings", json={"general": {"timezone": "Europe/London"}}
    ).status_code == 200
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
    about = html.split('data-i18n="settings.about.eyebrow"', 1)[1]
    assert 'id="settings-hostname"' in about


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
        "restart_required": ["general.timezone"],
    }


def test_put_settings_rejects_cross_origin(client):
    login(client)
    response = client.put(
        "/api/settings",
        headers={"Origin": "https://attacker.example"},
        json=valid_update(),
    )
    assert response.status_code == 403
