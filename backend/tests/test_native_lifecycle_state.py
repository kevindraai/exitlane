from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
from pathlib import Path

import pytest

from exitlane import core

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/qualification/native_lifecycle_state.py"
spec = importlib.util.spec_from_file_location("native_lifecycle_state", SCRIPT)
state = importlib.util.module_from_spec(spec)
spec.loader.exec_module(state)


@pytest.fixture
def appliance(tmp_path):
    for name in ("etc/exitlane/wireguard", "opt/exitlane/backend/exitlane", "etc/default"):
        (tmp_path / name).mkdir(parents=True)
    for name, content, mode in (
        ("etc/exitlane/secret.key", b"k" * 32, 0o600),
        ("etc/default/exitlane", b"EXITLANE_DATA_DIR=/etc/exitlane\n", 0o600),
        ("etc/exitlane/wireguard/wg-qa.conf", b"synthetic private ingress observation", 0o600),
        ("opt/exitlane/backend/exitlane/__init__.py", b'__version__ = "0.3.0-rc.4"\n', 0o644),
        ("etc/exitlane/installed-version", b"0.3.0-rc.4\n", 0o600),
        ("etc/systemd/system/exitlane.service", b"synthetic unit", 0o644),
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
    database = tmp_path / state.DATABASE
    core.init_database(database)
    database.chmod(0o600)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO users(id, username, password_hash, salt) VALUES(1, 'private-user', 'private-verifier', 'private-salt')"
        )
        connection.execute("INSERT INTO settings VALUES('language', 'nl')")
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at,public_id,last_seen_at,idle_expires_at) VALUES('private-cookie-digest',1,9999999999,'public-id',100,200)"
        )
        connection.execute(
            "INSERT INTO events(id,created_at,level,category,code) VALUES(1,'date','info','system','initial')"
        )
    return tmp_path


def sql(root, statement):
    with sqlite3.connect(root / state.DATABASE) as connection:
        connection.execute(statement)


def test_snapshots_contain_no_plaintext_database_or_file_values(appliance):
    result = state.capture(appliance)
    assert state.compare(result, state.capture(appliance), "preserved") == []
    serialized = json.dumps(result)
    for secret in (
        "private-user",
        "private-verifier",
        "private-salt",
        "private-cookie-digest",
        "synthetic private ingress observation",
        "EXITLANE_DATA_DIR",
    ):
        assert secret not in serialized
    assert result["database"]["tables"]["users"]["columns"]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE users SET password_hash='changed'",
        "UPDATE users SET encrypted_totp_secret=x'010203'",
        "UPDATE users SET mfa_failed_attempts=1",
        "UPDATE sessions SET revoked_at=123",
        "UPDATE settings SET value='en'",
        "INSERT INTO recovery_codes VALUES(1,1,'secret-hash',100,NULL)",
        "INSERT INTO vpn_latency_cache VALUES('proton','NL','synthetic.invalid',10,'reachable','date')",
    ],
)
def test_preservation_detects_security_and_state_changes(appliance, statement):
    before = state.capture(appliance)
    sql(appliance, statement)
    assert "snapshot_database_rows_mismatch" in state.compare(before, state.capture(appliance))


def test_provider_ciphertext_change_is_detected_without_decryption_claim(appliance):
    # Opaque ciphertext stand-ins exercise only fingerprint equality, not provider validity.
    sql(appliance, "INSERT INTO provider_secrets VALUES('proton',x'010203',100)")
    before = state.capture(appliance)
    sql(appliance, "UPDATE provider_secrets SET encrypted_payload=x'040506'")
    assert state.compare(before, state.capture(appliance)) == ["snapshot_database_rows_mismatch"]


def test_only_explicit_session_bookkeeping_and_appended_events_are_allowed(appliance):
    before = state.capture(appliance)
    sql(appliance, "UPDATE sessions SET last_seen_at=101,idle_expires_at=201")
    sql(
        appliance,
        "INSERT INTO events(id,created_at,level,category,code) VALUES(2,'date','info','system','next')",
    )
    after = state.capture(appliance)
    assert (
        before["database"]["tables"]["sessions"]["complete_rows"]
        != after["database"]["tables"]["sessions"]["complete_rows"]
    )
    assert state.compare(before, after) == []
    sql(appliance, "UPDATE events SET code='altered' WHERE id=1")
    assert state.compare(before, state.capture(appliance)) == ["snapshot_events_changed"]


def test_inserting_events_before_prior_rows_is_not_append_only(appliance):
    before = state.capture(appliance)
    sql(
        appliance,
        "INSERT INTO events(id,created_at,level,category,code) VALUES(0,'date','info','system','before')",
    )
    assert state.compare(before, state.capture(appliance)) == ["snapshot_events_changed"]


@pytest.mark.parametrize(
    "name", ["etc/exitlane/secret.key", "etc/exitlane/wireguard/wg-qa.conf", "etc/default/exitlane"]
)
def test_state_file_content_and_modes_are_preserved(appliance, name):
    before = state.capture(appliance)
    path = appliance / name
    path.chmod(0o644 if path.stat().st_mode & 0o777 == 0o600 else 0o600)
    assert state.compare(before, state.capture(appliance))
    path.chmod(0o600)
    path.write_bytes(b"x" * 32 if name.endswith("secret.key") else b"changed")
    assert state.compare(before, state.capture(appliance))


@pytest.mark.parametrize(
    "name",
    [
        "etc/systemd/system/exitlane.service",
        "opt/exitlane/backend/exitlane/__init__.py",
        "etc/exitlane/installed-version",
    ],
)
def test_rollback_checks_code_units_modes_and_version(appliance, name):
    before = state.capture(appliance)
    (appliance / name).write_bytes(b"candidate")
    after = state.capture(appliance)
    assert state.compare(before, after, "preserved") == []
    assert state.compare(before, after, "rollback")


def test_restore_requires_all_security_sessions_revoked(appliance):
    sql(appliance, "INSERT INTO mfa_challenges VALUES('challenge',1,1,99999,0,'local')")
    sql(appliance, "INSERT INTO mfa_enrollments VALUES('enrollment',1,'session',x'0102',1,99999)")
    before = state.capture(appliance)
    assert "snapshot_revocation_incomplete" in state.compare(before, before, "restore")
    for table in state.REVOKED_TABLES:
        sql(appliance, f'DELETE FROM "{table}"')
    assert state.compare(before, state.capture(appliance), "restore") == []
    (appliance / "etc/exitlane/secret.key").write_bytes(b"z" * 32)
    assert "snapshot_state_files_mismatch" in state.compare(
        before, state.capture(appliance), "restore"
    )


@pytest.mark.parametrize(
    "name",
    [
        "etc/exitlane/secret.key",
        state.DATABASE,
        "etc/exitlane/wireguard/wg-qa.conf",
        "etc/systemd/system/exitlane.service",
    ],
)
def test_symlink_reads_refused(appliance, name):
    path = appliance / name
    path.unlink()
    path.symlink_to(appliance / "outside")
    with pytest.raises(state.SnapshotError, match="snapshot_unsafe_path"):
        state.capture(appliance)


def test_symlink_directory_and_fifo_refused_without_blocking(appliance):
    path = appliance / "etc/exitlane/wireguard/wg-qa.conf"
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(state.SnapshotError, match="snapshot_unsafe_file"):
        state.capture(appliance)
    path.unlink()
    directory = path.parent
    directory.rmdir()
    directory.symlink_to(appliance / "elsewhere", target_is_directory=True)
    with pytest.raises(state.SnapshotError, match="snapshot_unsafe_path"):
        state.capture(appliance)


def test_hardlinks_and_oversized_reads_refused(appliance, monkeypatch):
    path = appliance / "etc/exitlane/secret.key"
    os.link(path, appliance / "another-key")
    with pytest.raises(state.SnapshotError, match="snapshot_unsafe_file"):
        state.capture(appliance)
    (appliance / "another-key").unlink()
    monkeypatch.setattr(state, "MAX_DATABASE", 1)
    with pytest.raises(state.SnapshotError, match="snapshot_unsafe_database"):
        state.capture(appliance)


def test_coherent_snapshot_includes_committed_wal(appliance):
    with sqlite3.connect(appliance / state.DATABASE) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO settings VALUES('wal-test', 'private-wal-value')")
        writer.commit()
        assert (appliance / (state.DATABASE + "-wal")).exists()
        result = state.capture(appliance)
        assert len(result["database"]["tables"]["settings"]["rows"]) == 2
        assert "private-wal-value" not in json.dumps(result)


def test_missing_or_future_schema_and_bad_receipts_fail_closed(appliance):
    sql(appliance, "UPDATE schema_version SET version=2")
    with pytest.raises(state.SnapshotError, match="snapshot_database_schema_invalid"):
        state.capture(appliance)
    assert state.compare({}, {}) == ["snapshot_format_mismatch"]
    with pytest.raises(ValueError, match="snapshot_comparison_mode_invalid"):
        state.compare({}, {}, "ignore-errors")


def test_unknown_database_tables_and_columns_are_not_discarded(appliance):
    sql(appliance, "CREATE TABLE extra_state (id INTEGER PRIMARY KEY, value TEXT)")
    sql(appliance, "INSERT INTO extra_state VALUES(1,'private')")
    before = state.capture(appliance)
    sql(appliance, "UPDATE extra_state SET value='changed'")
    assert "snapshot_database_rows_mismatch" in state.compare(before, state.capture(appliance))


def test_portable_restore_compares_key_but_does_not_restore_host_defaults(appliance):
    before = state.capture(appliance)
    for table in state.REVOKED_TABLES:
        sql(appliance, f'DELETE FROM "{table}"')
    (appliance / "etc/default/exitlane").write_bytes(b"different disaster target host defaults")
    after = state.capture(appliance)
    assert state.compare(before, after, "restore") == []
    assert "snapshot_state_files_mismatch" in state.compare(before, after, "preserved")


def test_database_sidecar_symlink_is_rejected(appliance):
    (appliance / (state.DATABASE + "-wal")).symlink_to(appliance / "foreign")
    with pytest.raises(state.SnapshotError, match="snapshot_unsafe_path"):
        state.capture(appliance)


def test_invalid_snapshot_table_structure_is_rejected(appliance):
    before = state.capture(appliance)
    after = state.capture(appliance)
    after["database"]["tables"].pop("users")
    assert state.compare(before, after) == ["snapshot_format_mismatch"]
