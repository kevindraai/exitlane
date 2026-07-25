from __future__ import annotations

import io
import sqlite3
import tarfile
from pathlib import Path

import pytest

from exitlane import core, lifecycle


@pytest.fixture
def appliance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    data = tmp_path / "data"
    config = tmp_path / "config"
    wireguard = data / "wireguard"
    for directory in (data, config, wireguard):
        directory.mkdir(mode=0o700)
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", data / "exitlane.db")
    monkeypatch.setattr(core, "WG_DIR", wireguard)
    monkeypatch.setattr(lifecycle, "CONFIG_DIR", config)
    core.init()
    (config / "secret.key").write_bytes(b"k" * 32)
    (config / "secret.key").chmod(0o600)
    (wireguard / "wg0.conf").write_text("[Interface]\nPrivateKey = test\n", encoding="utf-8")
    (wireguard / "wg0.conf").chmod(0o600)
    core.set_setting("language", "nl")
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES('old',1,9999999999)"
        )
    return {"data": data, "config": config, "lock": tmp_path / "lifecycle.lock"}


def test_encrypted_backup_round_trip_and_session_revocation(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    info = lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )

    assert destination.read_bytes().startswith(lifecycle.MAGIC)
    assert b"PrivateKey" not in destination.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o600
    assert info.database_schema_version == lifecycle.DATABASE_SCHEMA_VERSION
    verified = lifecycle.inspect_backup(
        destination, "correct horse battery staple", effective_user_id=0
    )
    assert verified.backup_id == info.backup_id

    core.set_setting("language", "en")
    lifecycle.restore_backup(
        destination,
        "correct horse battery staple",
        confirmation="RESTORE EXITLANE",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    assert core.setting("language") == "nl"
    with sqlite3.connect(core.DB) as connection:
        assert connection.execute("SELECT count(*) FROM sessions").fetchone() == (0,)


def test_wrong_passphrase_and_ciphertext_tampering_are_indistinguishable(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    with pytest.raises(lifecycle.LifecycleError, match="authentication_failed"):
        lifecycle.inspect_backup(destination, "incorrect passphrase", effective_user_id=0)
    content = bytearray(destination.read_bytes())
    content[-20] ^= 1
    destination.write_bytes(content)
    with pytest.raises(lifecycle.LifecycleError, match="authentication_failed"):
        lifecycle.inspect_backup(destination, "correct horse battery staple", effective_user_id=0)


def test_header_tampering_is_authenticated(appliance: dict[str, Path], tmp_path: Path) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    content = bytearray(destination.read_bytes())
    header_offset = len(lifecycle.MAGIC) + 4
    marker = content.find(b"AES-256-GCM", header_offset)
    content[marker] = ord("B")
    destination.write_bytes(content)
    with pytest.raises(lifecycle.LifecycleError, match="unsupported_backup_format"):
        lifecycle.inspect_backup(destination, "correct horse battery staple", effective_user_id=0)


def test_symlink_input_and_non_root_are_rejected(
    appliance: dict[str, Path], tmp_path: Path
) -> None:
    destination = tmp_path / "appliance.elb"
    lifecycle.create_backup(
        destination,
        "correct horse battery staple",
        effective_user_id=0,
        lock_path=appliance["lock"],
    )
    link = tmp_path / "linked.elb"
    link.symlink_to(destination)
    with pytest.raises(lifecycle.LifecycleError, match="unsafe_backup_file"):
        lifecycle.inspect_backup(link, "correct horse battery staple", effective_user_id=0)
    with pytest.raises(lifecycle.LifecycleError, match="root_required"):
        lifecycle.inspect_backup(
            destination, "correct horse battery staple", effective_user_id=1000
        )


def test_malicious_archive_entry_is_rejected_before_extraction(
    appliance: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    staging = tmp_path / "staging"
    staging.mkdir()
    with pytest.raises(lifecycle.LifecycleError, match="unsafe_archive_entry"):
        lifecycle._validated_payload(output.getvalue(), staging)
    assert not (tmp_path / "escape").exists()


def test_lifecycle_lock_prevents_concurrent_actions(tmp_path: Path) -> None:
    lock = tmp_path / "lifecycle.lock"
    with (
        lifecycle.lifecycle_lock(lock),
        pytest.raises(lifecycle.LifecycleError, match="lifecycle_busy"),
        lifecycle.lifecycle_lock(lock),
    ):
        pass


def test_future_database_schema_stops_before_application_migrations(
    appliance: dict[str, Path],
) -> None:
    with sqlite3.connect(core.DB) as connection:
        connection.execute("UPDATE schema_version SET version=999 WHERE singleton=1")
    with pytest.raises(core.SettingsStorageError, match="Unsupported database schema"):
        core.init()
