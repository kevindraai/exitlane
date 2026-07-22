import json
import sqlite3
from datetime import UTC, datetime, timedelta

import exitlane.core as core
import exitlane.events as events
import exitlane.main as main


def database(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    core.init()
    return core.DB


def test_init_migrates_idempotently_and_creates_event_indexes(tmp_path, monkeypatch):
    db = database(tmp_path, monkeypatch)
    core.init()
    with sqlite3.connect(db) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(events)")}
    assert "events" in tables
    assert {"events_created_at_idx", "events_category_idx", "events_level_idx", "events_code_idx"} <= indexes


def test_record_validates_metadata_and_preserves_actor_snapshot(tmp_path, monkeypatch):
    db = database(tmp_path, monkeypatch)
    with sqlite3.connect(db) as connection:
        user_id = connection.execute(
            "INSERT INTO users(username, password_hash, salt) VALUES ('admin', 'hash', 'salt')"
        ).lastrowid
    assert events.record_event("auth.login_succeeded", actor={"id": user_id, "username": "admin"})
    assert not events.record_event("provider.connected", metadata={"token": "secret"})
    assert not events.record_event("made.up")
    with sqlite3.connect(db) as connection:
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    item = events.list_events().items[0]
    assert item.actor.username == "admin"


def test_provider_connection_events_accept_safe_technical_metadata(tmp_path, monkeypatch):
    database(tmp_path, monkeypatch)
    assert events.record_event(
        "provider.connect_started",
        metadata={"target": "Nederland", "country_code": "NL", "cli_action": "connect_country"},
    )
    assert events.record_event(
        "provider.connected",
        metadata={
            "country": "Netherlands",
            "city": "Amsterdam",
            "server": "nl925.nordvpn.com",
            "country_code": "NL",
            "cli_action": "connect_country",
            "exit_code": "0",
        },
    )
    items = events.list_events().items
    assert items[0].metadata["server"] == "nl925.nordvpn.com"
    assert items[1].metadata["target"] == "Nederland"


def test_corrupt_metadata_does_not_break_page(tmp_path, monkeypatch):
    db = database(tmp_path, monkeypatch)
    assert events.record_event("system.started")
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE events SET metadata_json = ?", ("not-json",))
    assert events.list_events().items[0].metadata == {}


def test_cursor_filters_and_retention(tmp_path, monkeypatch):
    db = database(tmp_path, monkeypatch)
    old = datetime.now(UTC) - timedelta(days=100)
    assert events.record_event("system.started", now=old)
    for _ in range(4):
        assert events.record_event("auth.login_failed", metadata={"reason": "invalid_credentials"})
    with sqlite3.connect(db) as connection:
        events.cleanup_events(connection, now=datetime.now(UTC), max_count=3, max_days=90)
    first = events.list_events(limit=2, category="auth", level="warning")
    second = events.list_events(limit=2, cursor=first.next_cursor)
    assert len(first.items) == 2 and first.has_more
    assert len(second.items) == 1
    assert not ({item.id for item in first.items} & {item.id for item in second.items})
    assert all(json.dumps(item.metadata) != "null" for item in first.items)


def test_wireguard_polling_records_only_transitions(monkeypatch):
    recorded = []
    monkeypatch.setattr(main, "record_event", lambda code, **values: recorded.append((code, values)))
    monkeypatch.setattr(main, "_wireguard_observed_state", None)
    values = {"configured": True, "active": True, "handshake": False, "interface": "wg0", "client": "router"}
    main.observe_wireguard_state(**values)
    main.observe_wireguard_state(**values)
    main.observe_wireguard_state(**(values | {"handshake": True}))
    main.observe_wireguard_state(**(values | {"handshake": True}))
    main.observe_wireguard_state(**(values | {"active": False, "handshake": False}))
    assert [code for code, _ in recorded] == [
        "wireguard.handshake_received",
        "wireguard.interface_inactive",
    ]
