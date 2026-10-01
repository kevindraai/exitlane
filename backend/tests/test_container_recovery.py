"""Crash-stage durable pair tests use only synthetic empty state and guard receipts."""

import asyncio
import json
import os
import sqlite3

import pytest

from exitlane import lifecycle
from exitlane.container_recovery import (
    ContainerRecoveryCoordinator,
    ContainerRecoveryError,
    RecoveryHooks,
    ingress_identities,
)
from exitlane.container_state import ContainerLayout, ContainerState, ContainerStateError


class Crash(BaseException):
    pass


class Hooks:
    def __init__(self):
        self.events = []
        self.fail_health = 0
        self.fail_quiesce = False

    async def guard(self, identities):
        self.events.append(("guard", identities))

    async def quiesce(self):
        self.events.append("quiesce")
        if self.fail_quiesce:
            raise ValueError("synthetic-private-sentinel")

    async def reset(self):
        self.events.append("reset")

    async def reconcile(self, inventory):
        self.events.append("reconcile")

    async def health(self):
        self.events.append("health")
        if self.fail_health:
            self.fail_health -= 1
            return False
        return True

    async def reopen(self):
        self.events.append("reopen")

    def bundle(self):
        return RecoveryHooks(
            self.guard, self.quiesce, self.reset, self.reconcile, self.health, self.reopen
        )


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    from exitlane import container_state

    monkeypatch.setattr(container_state, "ROOT_UID", os.geteuid())
    state = ContainerState(ContainerLayout(tmp_path / "data"))
    hooks = Hooks()
    coordinator = ContainerRecoveryCoordinator(
        state, hooks.bundle(), require_exclusive=lambda: True
    )
    asyncio.run(coordinator.startup())
    hooks.events.clear()
    return state, hooks, coordinator


def mark(state, value):
    with sqlite3.connect(state.layout.database) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
            ("synthetic_marker", json.dumps(value)),
        )


def marker(state):
    with sqlite3.connect(state.layout.database) as connection:
        value = connection.execute(
            "SELECT value FROM settings WHERE key='synthetic_marker'"
        ).fetchone()
    return json.loads(value[0]) if value else None


def backup(fixture):
    state, hooks, coordinator = fixture
    old_key = state.layout.master_key.read_bytes()
    state.layout.master_key.write_bytes(bytes(range(32)))
    state.write_manifest()
    mark(state, "candidate")
    destination = state.layout.backups / "synthetic.backup"
    asyncio.run(coordinator.backup(destination, "synthetic-passphrase"))
    state.layout.master_key.write_bytes(old_key)
    state.write_manifest()
    mark(state, "previous")
    hooks.events.clear()
    return destination


def test_init_and_portable_format_roundtrip(fixture):
    state, hooks, coordinator = fixture
    destination = backup(fixture)
    info = lifecycle.inspect_backup(destination, "synthetic-passphrase", effective_user_id=0)
    assert {item["type"] for item in info.files} == {"database", "master_key"}
    asyncio.run(
        coordinator.restore(destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE")
    )
    assert marker(state) == "candidate"
    assert hooks.events == [("guard", ()), "quiesce", "reset", "reconcile", "health", "reopen"]
    assert not coordinator.journal.exists()
    assert destination.stat().st_mode & 0o777 == 0o600


def test_wrong_passphrase_no_network_mutation(fixture):
    state, hooks, coordinator = fixture
    destination = backup(fixture)
    with pytest.raises(lifecycle.LifecycleError, match="authentication_failed"):
        asyncio.run(
            coordinator.restore(destination, "synthetic-wrong", confirmation="RESTORE EXITLANE")
        )
    assert hooks.events == []
    assert marker(state) == "previous"
    assert not coordinator.journal.exists()


def test_failure_rolls_back_pair_before_reopening(fixture):
    state, hooks, coordinator = fixture
    destination = backup(fixture)
    old_key = state.layout.master_key.read_bytes()
    hooks.fail_health = 1
    with pytest.raises(ContainerRecoveryError, match="restore_failed_rolled_back"):
        asyncio.run(
            coordinator.restore(
                destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"
            )
        )
    assert marker(state) == "previous"
    assert state.layout.master_key.read_bytes() == old_key
    assert hooks.events.count("reopen") == 1
    assert hooks.events[-3:] == ["reconcile", "health", "reopen"]


def test_failed_rollback_retains_journal_and_never_reopens(fixture):
    state, hooks, coordinator = fixture
    destination = backup(fixture)
    hooks.fail_health = 2
    with pytest.raises(ContainerRecoveryError, match="recovery_required"):
        asyncio.run(
            coordinator.restore(
                destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"
            )
        )
    assert coordinator.journal.exists()
    assert "reopen" not in hooks.events
    assert hooks.events[-1] == "quiesce"
    assert marker(state) == "previous"
    asyncio.run(coordinator.startup())
    assert hooks.events[-1] == "reopen"
    assert not coordinator.journal.exists()


@pytest.mark.parametrize(
    "phase",
    [
        "prepared",
        "snapshot_ready",
        "publishing",
        "installed",
        "validated",
        "committed",
        "published_database",
        "published_master_key",
        "published_manifest",
        "published_wireguard",
        "published_provider_egress",
    ],
)
def test_crash_receipt_reconciles_complete_pair(fixture, phase):
    state, hooks, coordinator = fixture
    destination = backup(fixture)

    def observe(current):
        if current == phase:
            raise Crash()

    coordinator.phase_observer = observe
    with pytest.raises(Crash):
        asyncio.run(
            coordinator.restore(
                destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"
            )
        )
    assert coordinator.journal.exists()
    recovered = ContainerRecoveryCoordinator(state, hooks.bundle(), require_exclusive=lambda: True)
    hooks.events.clear()
    asyncio.run(recovered.startup())
    assert marker(state) == ("candidate" if phase == "committed" else "previous")
    state.validate()
    assert hooks.events[0] == ("guard", ())
    assert hooks.events[-1] == "reopen"
    assert not recovered.journal.exists()


@pytest.mark.parametrize("stage", [
    "guard", "quiesce", "snapshot", "reset_egress", "publish", "reconcile", "health", "reopen",
])
def test_restore_logs_original_boundary_after_real_coherent_rollback(
    fixture, monkeypatch, caplog, stage
):
    from dataclasses import replace

    from exitlane.container_runtime import ContainerLifecycleError

    state, hooks, coordinator = fixture
    destination = backup(fixture)
    old_key = state.layout.master_key.read_bytes()
    failed = False
    if stage in {"snapshot", "publish"}:
        attribute = "_" + stage
        original = getattr(coordinator, attribute)

        def fail_once(*args):
            nonlocal failed
            if not failed:
                failed = True
                raise ContainerLifecycleError("container_network_command_failed")
            return original(*args)

        monkeypatch.setattr(coordinator, attribute, fail_once)
    else:
        original = getattr(coordinator.hooks, stage)

        async def fail_once(*args):
            nonlocal failed
            if not failed:
                failed = True
                raise ContainerLifecycleError("container_network_command_failed")
            return await original(*args)

        coordinator.hooks = replace(coordinator.hooks, **{stage: fail_once})
    with pytest.raises(ContainerRecoveryError, match="restore_failed_rolled_back"):
        asyncio.run(coordinator.restore(destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"))
    assert marker(state) == "previous" and state.layout.master_key.read_bytes() == old_key
    state.validate()
    assert not coordinator.journal.exists() and hooks.events[-1] == "reopen"
    records = [r for r in caplog.records if r.name == "exitlane.container_recovery"]
    assert len(records) == 1
    assert records[0].getMessage() == (
        f"container_restore_failure stage={stage} code=container_network_command_failed outcome=rollback_completed"
    )
    assert records[0].exc_info is None and records[0].stack_info is None


def test_restore_failed_rollback_logs_original_code_not_secondary_secret(fixture, caplog):
    from dataclasses import replace

    state, hooks, coordinator = fixture
    destination = backup(fixture)
    calls = 0

    async def fail_health():
        nonlocal calls
        calls += 1
        hooks.events.append("health")
        if calls == 1:
            return False
        raise ValueError("synthetic-secondary-private-sentinel")

    coordinator.hooks = replace(coordinator.hooks, health=fail_health)
    with pytest.raises(ContainerRecoveryError, match="recovery_required"):
        asyncio.run(coordinator.restore(destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"))
    assert coordinator.journal.exists() and "reopen" not in hooks.events
    assert "stage=health code=recovery_health_failed outcome=recovery_required" in caplog.text
    assert "synthetic-passphrase" not in caplog.text and str(state.layout.root) not in caplog.text
    assert "synthetic-secondary-private-sentinel" not in caplog.text


def test_restore_unknown_exception_code_and_message_are_never_logged(fixture, caplog):
    from dataclasses import replace

    state, hooks, coordinator = fixture
    destination = backup(fixture)
    count = 0

    async def fail_once():
        nonlocal count
        count += 1
        if count == 1:
            raise ContainerRecoveryError("synthetic-private-sentinel")
        await hooks.reset()

    coordinator.hooks = replace(coordinator.hooks, reset_egress=fail_once)
    with pytest.raises(ContainerRecoveryError, match="restore_failed_rolled_back"):
        asyncio.run(coordinator.restore(destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"))
    assert "stage=reset_egress code=unclassified outcome=rollback_completed" in caplog.text
    assert "synthetic-private-sentinel" not in caplog.text and str(state.layout.root) not in caplog.text


def test_wrong_passphrase_log_has_static_rejected_boundary_and_no_secret(fixture, caplog):
    _state, hooks, coordinator = fixture
    destination = backup(fixture)
    with pytest.raises(lifecycle.LifecycleError):
        asyncio.run(coordinator.restore(destination, "synthetic-wrong-private", confirmation="RESTORE EXITLANE"))
    assert hooks.events == []
    assert "stage=prepare_archive code=authentication_failed outcome=rejected" in caplog.text
    assert "synthetic-wrong-private" not in caplog.text and str(destination) not in caplog.text


def test_diagnostic_handler_failure_cannot_interrupt_rollback(fixture, monkeypatch):
    from exitlane import container_recovery

    state, hooks, coordinator = fixture
    destination = backup(fixture)
    hooks.fail_health = 1
    monkeypatch.setattr(container_recovery.LOGGER, "warning", lambda *_: (_ for _ in ()).throw(OSError()))
    with pytest.raises(ContainerRecoveryError, match="restore_failed_rolled_back"):
        asyncio.run(coordinator.restore(destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE"))
    assert not coordinator.journal.exists() and hooks.events[-1] == "reopen"
    assert marker(state) == "previous"


@pytest.mark.parametrize("phase", ["init_preparing", "init_ready"])
def test_crash_initialization_recovers_owned_empty_pair(tmp_path, monkeypatch, phase):
    from exitlane import container_state

    monkeypatch.setattr(container_state, "ROOT_UID", os.geteuid())
    state = ContainerState(ContainerLayout(tmp_path / "data"))
    hooks = Hooks()

    def observe(current):
        if phase == current:
            raise Crash()

    coordinator = ContainerRecoveryCoordinator(
        state, hooks.bundle(), require_exclusive=lambda: True, phase_observer=observe
    )
    with pytest.raises(Crash):
        asyncio.run(coordinator.startup())
    asyncio.run(
        ContainerRecoveryCoordinator(
            state, hooks.bundle(), require_exclusive=lambda: True
        ).startup()
    )
    state.validate()


@pytest.mark.parametrize("malformation", ["future", "path", "symlink", "world_readable"])
def test_hostile_journal_fails_before_network(fixture, tmp_path, malformation):
    _state, hooks, coordinator = fixture
    record = {
        "version": 1,
        "transaction": "00000000-0000-0000-0000-000000000001",
        "phase": "prepared",
        "ingress": [],
    }
    if malformation == "future":
        record["version"] = 2
    if malformation == "path":
        record["transaction"] = "../../other"
    target = coordinator.journal
    if malformation == "symlink":
        other = tmp_path / "unrelated"
        other.write_text(json.dumps(record))
        other.chmod(0o600)
        target.symlink_to(other)
    else:
        target.write_text(json.dumps(record))
        target.chmod(0o644 if malformation == "world_readable" else 0o600)
    with pytest.raises(ContainerRecoveryError):
        asyncio.run(coordinator.startup())
    assert hooks.events == []


def test_ingress_union_has_ranges_and_no_default_guess(fixture):
    state, _, _ = fixture
    assert ingress_identities(state.layout.database) == ()
    with sqlite3.connect(state.layout.database) as connection:
        for key, value in {
            "wireguard_configured": True,
            "wireguard_interface": "wg-office",
            "wireguard_subnet": "10.81.0.0/24",
        }.items():
            connection.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, json.dumps(value))
            )
    assert ingress_identities(state.layout.database)[0].subnet == "10.81.0.0/24"


def test_backup_invalid_destination_and_secret_free_error(fixture, tmp_path):
    _, hooks, coordinator = fixture
    with pytest.raises(ContainerRecoveryError, match="backup_destination_invalid") as error:
        asyncio.run(coordinator.backup(tmp_path / "outside", "synthetic-private-sentinel"))
    assert "synthetic-private-sentinel" not in str(error.value)
    assert hooks.events == []


@pytest.mark.parametrize("method", ["startup", "backup", "restore"])
def test_exclusive_lease_is_mandatory_before_mutation(fixture, method):
    state, hooks, _ = fixture
    coordinator = ContainerRecoveryCoordinator(
        state, hooks.bundle(), require_exclusive=lambda: False
    )
    if method == "startup":
        call = coordinator.startup()
    elif method == "backup":
        call = coordinator.backup(state.layout.backups / "denied", "synthetic")
    else:
        call = coordinator.restore(
            state.layout.backups / "absent", "synthetic", confirmation="RESTORE EXITLANE"
        )
    with pytest.raises(ContainerRecoveryError, match="recovery_exclusive_lease_required"):
        asyncio.run(call)
    assert hooks.events == []
    assert not coordinator.journal.exists()


def test_startup_hook_failure_is_secret_safe_and_does_not_reopen(fixture):
    _, hooks, coordinator = fixture
    hooks.fail_quiesce = True
    with pytest.raises(ContainerRecoveryError, match="recovery_required") as error:
        asyncio.run(coordinator.startup())
    assert "synthetic-private-sentinel" not in str(error.value)
    assert "reopen" not in hooks.events


def test_restore_revokes_sessions_and_transient_mfa_state(fixture):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    state, _, coordinator = fixture
    nonce = bytes(range(12))
    encrypted = nonce + AESGCM(state.layout.master_key.read_bytes()).encrypt(
        nonce, b"SYNTHETIC-ENROLLMENT", b"exitlane-totp-v1"
    )
    with sqlite3.connect(state.layout.database) as connection:
        connection.execute("INSERT INTO users(id,username) VALUES(1,'synthetic-user')")
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES('synthetic',1,1)"
        )
        connection.execute(
            "INSERT INTO mfa_challenges(token_hash,user_id,created_at,expires_at,client_ip) "
            "VALUES('synthetic',1,1,2,'192.0.2.1')"
        )
        connection.execute(
            "INSERT INTO mfa_enrollments(token_hash,user_id,session_hash,encrypted_secret,created_at,expires_at) "
            "VALUES('synthetic',1,'synthetic',?,1,2)",
            (encrypted,),
        )
    destination = state.layout.backups / "sessions.backup"
    asyncio.run(coordinator.backup(destination, "synthetic-passphrase"))
    asyncio.run(
        coordinator.restore(destination, "synthetic-passphrase", confirmation="RESTORE EXITLANE")
    )
    with sqlite3.connect(state.layout.database) as connection:
        for table in ("sessions", "mfa_challenges", "mfa_enrollments"):
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)


def test_prejournal_empty_skeleton_refuses_without_adoption_or_networking(tmp_path, monkeypatch):
    from exitlane import container_state

    monkeypatch.setattr(container_state, "ROOT_UID", os.geteuid())
    layout = ContainerLayout(tmp_path / "data")
    layout.root.mkdir(mode=0o700)
    layout.config.mkdir(mode=0o700)
    hooks = Hooks()
    coordinator = ContainerRecoveryCoordinator(
        ContainerState(layout), hooks.bundle(), require_exclusive=lambda: True
    )
    with pytest.raises(container_state.ContainerStateError):
        asyncio.run(coordinator.startup())
    assert not hooks.events
    assert not layout.database.exists() and not layout.master_key.exists()
    assert layout.config.is_dir()


def hot_rollback(state):
    import subprocess
    import sys

    with sqlite3.connect(state.layout.database) as connection:
        connection.executemany(
            "INSERT INTO settings(key,value) VALUES(?,?)",
            [(f"synthetic.hot.{index}", json.dumps("old" * 3000)) for index in range(32)],
        )
    program = """import os,sqlite3,sys,json
connection=sqlite3.connect(sys.argv[1])
connection.execute('PRAGMA cache_size=1')
connection.execute('BEGIN IMMEDIATE')
connection.execute("UPDATE settings SET value=? WHERE key LIKE 'synthetic.hot.%'",(json.dumps('new'*3000),))
os._exit(0)
"""
    subprocess.run([sys.executable, "-c", program, str(state.layout.database)], check=True)
    journal = state.layout.database.with_name(state.layout.database.name + "-journal")
    assert journal.exists()
    return journal


def test_real_sqlite_hot_rollback_recovers_only_after_guard_and_quiesce(fixture):
    state, hooks, coordinator = fixture
    journal = hot_rollback(state)
    with pytest.raises(ContainerStateError, match="sqlite_recovery_required"):
        state.validate()
    with pytest.raises(ContainerStateError, match="guard_unproven"):
        state.recover_database(guard_observed=lambda: False)
    assert journal.exists()
    asyncio.run(coordinator.startup())
    assert hooks.events[:2] == [("guard", ()), "quiesce"]
    assert not journal.exists()
    state.validate()
    with sqlite3.connect(state.layout.database) as connection:
        row = connection.execute(
            "SELECT value FROM settings WHERE key='synthetic.hot.0'"
        ).fetchone()
    assert json.loads(row[0]) == "old" * 3000


def test_wrong_key_hot_journal_refuses_before_network_mutation(fixture):
    state, hooks, coordinator = fixture
    journal = hot_rollback(state)
    state.layout.master_key.write_bytes(b"z" * 32)
    with pytest.raises(ContainerStateError, match="manifest_invalid"):
        asyncio.run(coordinator.startup())
    assert not hooks.events and journal.exists()
