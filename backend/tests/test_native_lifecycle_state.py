from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import time
import uuid
from datetime import UTC, datetime
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
        "INSERT INTO mfa_challenges VALUES('challenge',1,1,99999,0,'local')",
        "INSERT INTO mfa_enrollments VALUES('enrollment',1,'session',x'0102',1,99999)",
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


@pytest.fixture
def v1_upgrade(appliance, monkeypatch):
    database = appliance / state.DATABASE
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE settings SET value=? WHERE key='language'", (json.dumps("nl"),))
        connection.execute("DROP TABLE wireguard_peers")
        connection.execute("DROP TABLE wireguard_ingress_profile")
        for key, value in (
            ("wireguard_configured", True),
            ("wireguard_interface", "wg-qa"),
            ("wireguard_client_name", "qualification-router"),
        ):
            connection.execute("INSERT INTO settings VALUES(?,?)", (key, json.dumps(value)))
    (appliance / "etc/exitlane/installed-version").write_text("1.0.0\n")
    (appliance / "etc/exitlane/wireguard/wg-qa.conf").write_text(
        "[Interface]\nPrivateKey = server-private\nAddress = 10.98.240.1/24\n"
        "[Peer]\nPublicKey = client-public\nAllowedIPs = 10.98.240.2/32\n"
    )
    (appliance / "etc/exitlane/wireguard/qualification-router.conf").write_text(
        "[Interface]\nPrivateKey = client-private\nAddress = 10.98.240.2/32\n"
        "DNS = 10.98.240.1\n[Peer]\nPublicKey = server-public\n"
        "Endpoint = qa.invalid:51820\nAllowedIPs = 0.0.0.0/0\n"
    )
    monkeypatch.setattr(
        state,
        "_public_key",
        lambda value: {
            "server-private": "server-public",
            "client-private": "client-public",
        }[value],
    )
    before = state.capture(appliance)
    certificate = state.legacy_certificate(appliance, before)
    started = time.time()
    core.init_database(database)
    stamp = datetime.now(UTC).isoformat()
    peer_id = uuid.uuid4().hex
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO wireguard_peers VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                peer_id,
                "qualification-router",
                "",
                "client-public",
                "10.98.240.2",
                "qualification-router",
                "active",
                1,
                stamp,
                stamp,
                None,
            ),
        )
        connection.execute(
            "INSERT INTO wireguard_ingress_profile VALUES(?,?,?,?,?,?,?)",
            (1, "qa.invalid:51820", "10.98.240.1", "0.0.0.0/0", 25, 25, "server-public"),
        )
    return appliance, before, state.capture(appliance), certificate, started, time.time() + 1


def test_pinned_v1_upgrade_accepts_only_expected_adoption(v1_upgrade):
    _, before, after, certificate, started, finished = v1_upgrade
    assert state.compare_v1_upgrade(before, after, certificate, started, finished) == []
    assert "snapshot_database_schema_mismatch" in state.compare(before, after)
    assert "snapshot_database_schema_mismatch" in state.compare(before, after, "rollback")
    assert "snapshot_database_schema_mismatch" in state.compare(before, after, "restore")


@pytest.mark.parametrize("table", ["wireguard_peers", "wireguard_ingress_profile"])
def test_upgrade_rejects_missing_or_extra_rows(v1_upgrade, table):
    root, before, _, certificate, started, finished = v1_upgrade
    with sqlite3.connect(root / state.DATABASE) as connection:
        connection.execute(f"DELETE FROM {table}")
    assert state.compare_v1_upgrade(before, state.capture(root), certificate, started, finished)
    if table == "wireguard_ingress_profile":
        # The canonical singleton CHECK prevents a second row; its DDL is
        # independently pinned by the schema comparison.
        return
    with sqlite3.connect(root / state.DATABASE) as connection:
        connection.execute(
            "INSERT INTO wireguard_peers VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                uuid.uuid4().hex,
                "extra",
                "",
                "extra-key",
                "10.98.240.3",
                "extra",
                "active",
                0,
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
                None,
            ),
        )
        connection.execute(
            "INSERT INTO wireguard_peers VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                uuid.uuid4().hex,
                "another",
                "",
                "another-key",
                "10.98.240.4",
                "another",
                "active",
                0,
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
                None,
            ),
        )
    assert state.compare_v1_upgrade(before, state.capture(root), certificate, started, finished)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE users SET password_hash='changed'",
        "UPDATE users SET mfa_failed_attempts=1",
        "INSERT INTO recovery_codes VALUES(1,1,'new-hash',100,NULL)",
        "UPDATE settings SET value='\"en\"' WHERE key='language'",
        "UPDATE sessions SET revoked_at=123",
        "INSERT INTO provider_secrets VALUES('proton',x'0102',100)",
        "INSERT INTO vpn_latency_cache VALUES('proton','NL','qa.invalid',1,'reachable','date')",
        "UPDATE events SET code='altered' WHERE id=1",
        "DELETE FROM events WHERE id=1",
        "INSERT INTO events(id,created_at,level,category,code) VALUES(0,'date','info','system','before')",
        "UPDATE wireguard_peers SET public_key='wrong'",
        "UPDATE wireguard_peers SET name='wrong'",
        "UPDATE wireguard_peers SET description='wrong'",
        "UPDATE wireguard_peers SET tunnel_ip='10.98.240.3'",
        "UPDATE wireguard_peers SET config_name='wrong'",
        "UPDATE wireguard_peers SET status='revoked'",
        "UPDATE wireguard_peers SET is_default=0",
        "UPDATE wireguard_peers SET revoked_at='2026-01-01T00:00:00+00:00'",
        "UPDATE wireguard_ingress_profile SET dns='wrong'",
        "UPDATE wireguard_ingress_profile SET endpoint='wrong.invalid:51820'",
        "UPDATE wireguard_ingress_profile SET allowed_ips='10.0.0.0/8'",
        "UPDATE wireguard_ingress_profile SET client_keepalive=24",
        "UPDATE wireguard_ingress_profile SET server_keepalive=24",
        "UPDATE wireguard_ingress_profile SET server_public_key='wrong'",
        "UPDATE wireguard_peers SET peer_id='not-a-uuid'",
        "UPDATE wireguard_peers SET created_at='2020-01-01T00:00:00+00:00',updated_at='2020-01-01T00:00:00+00:00'",
        "UPDATE wireguard_peers SET created_at='2026-01-01T00:00:00'",
        "UPDATE wireguard_peers SET updated_at='2020-01-01T00:00:00+00:00'",
    ],
)
def test_upgrade_rejects_state_or_migration_changes(v1_upgrade, statement):
    root, before, _, certificate, started, finished = v1_upgrade
    sql(root, statement)
    assert state.compare_v1_upgrade(before, state.capture(root), certificate, started, finished)


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE VIEW unknown_view AS SELECT * FROM users",
        "CREATE TRIGGER unknown_trigger AFTER INSERT ON users BEGIN SELECT 1; END",
        "CREATE INDEX unknown_index ON users(username)",
        "ALTER TABLE users ADD COLUMN unknown_column TEXT",
        "CREATE TABLE unknown_table(id INTEGER)",
    ],
)
def test_upgrade_rejects_unknown_schema(v1_upgrade, statement):
    root, before, _, certificate, started, finished = v1_upgrade
    sql(root, statement)
    assert "snapshot_upgrade_schema_mismatch" in state.compare_v1_upgrade(
        before, state.capture(root), certificate, started, finished
    )


def test_upgrade_rejects_changed_known_ddl(v1_upgrade):
    _, before, after, certificate, started, finished = v1_upgrade
    after["database"]["objects"]["index:wireguard_default_peer_idx"]["sql"] = (
        "CREATE INDEX wireguard_default_peer_idx ON wireguard_peers(is_default)"
    )
    assert "snapshot_upgrade_schema_mismatch" in state.compare_v1_upgrade(
        before, after, certificate, started, finished
    )


def test_upgrade_requires_independent_preupgrade_binding(v1_upgrade):
    root, before, after, certificate, started, finished = v1_upgrade
    with pytest.raises(state.SnapshotError, match="snapshot_legacy_certificate_invalid"):
        state.legacy_certificate(root, before)
    assert "server-private" not in json.dumps(certificate)
    assert "client-private" not in json.dumps(certificate)
    certificate["profile"]["server_public_key"] = "changed"
    assert state.compare_v1_upgrade(before, after, certificate, started, finished)
    certificate["profile"]["server_public_key"] = "server-public"
    certificate["before"] = "0" * 64
    assert state.compare_v1_upgrade(before, after, certificate, started, finished)


@pytest.mark.parametrize(
    "name",
    [
        "etc/exitlane/secret.key",
        "etc/default/exitlane",
        "etc/exitlane/wireguard/wg-qa.conf",
        "etc/exitlane/wireguard/qualification-router.conf",
    ],
)
def test_upgrade_rejects_native_byte_changes(v1_upgrade, name):
    root, before, _, certificate, started, finished = v1_upgrade
    (root / name).write_bytes(
        b"z" * 32 if name.endswith("secret.key") else b"mutated private state"
    )
    assert state.compare_v1_upgrade(before, state.capture(root), certificate, started, finished)


def test_upgrade_rejects_recreated_peer_on_repeated_strict_comparison(v1_upgrade):
    root, _, after, _, _, _ = v1_upgrade
    sql(root, f"UPDATE wireguard_peers SET peer_id='{uuid.uuid4().hex}'")
    assert "snapshot_database_rows_mismatch" in state.compare(after, state.capture(root))
