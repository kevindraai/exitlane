"""Private native qualification fingerprints, never traffic or decryption evidence.

The caller owns target authorization and writer quiescence. Observations require the
standard native layout. Snapshot before authentication probes: those legitimately
consume MFA factors. Fingerprints are private evidence, not anonymous/public data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from contextlib import closing
from pathlib import Path

MAX_FILE = 16 * 1024 * 1024
MAX_DATABASE = 64 * 1024 * 1024
MAX_FILES = 10_000
MAX_ROWS = 100_000
MAX_TOTAL = 256 * 1024 * 1024
DATABASE = "etc/exitlane/exitlane.db"
STATE_FILES = ("etc/exitlane/secret.key", "etc/default/exitlane")
STATE_TREE = "etc/exitlane/wireguard"
CODE_TREE = "opt/exitlane/backend/exitlane"
VERSION_FILE = "etc/exitlane/installed-version"
INSTALL_FILES = (
    "usr/local/sbin/exitlane-cli",
    "usr/local/libexec/exitlane-install-nordvpn",
    "usr/local/libexec/exitlane-install-mullvad",
    "usr/local/libexec/exitlane-install-speedtest",
    "etc/sysctl.d/99-exitlane.conf",
    "etc/systemd/system/exitlane.service",
    "etc/systemd/system/exitlane-killswitch.service",
    "etc/systemd/system/exitlane-provider-egress.service",
    "etc/systemd/system/exitlane-management-routing.service",
    "etc/systemd/system/exitlane-provider-install-nordvpn.service",
    "etc/systemd/system/exitlane-provider-install-mullvad.service",
    "etc/systemd/system/exitlane-speedtest-install.service",
    "etc/systemd/system/wg-quick@.service.d/exitlane.conf",
    "etc/systemd/system/mullvad-early-boot-blocking.service.d/exitlane.conf",
    "etc/systemd/system/mullvad-daemon.service.d/exitlane.conf",
)
REQUIRED_TABLES = frozenset(
    {
        "schema_version",
        "settings",
        "users",
        "webhooks",
        "sessions",
        "events",
        "vpn_latency_cache",
        "recovery_codes",
        "mfa_enrollments",
        "mfa_challenges",
        "provider_secrets",
    }
)
# Authentication request bookkeeping only. No MFA budget, factor-use, revocation,
# credential, provider, settings or cache column is discarded.
SESSION_BOOKKEEPING = frozenset({"last_seen_at", "idle_expires_at"})
REVOKED_TABLES = frozenset({"sessions", "mfa_challenges", "mfa_enrollments"})
IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*\Z")


class SnapshotError(RuntimeError):
    """Only fixed error codes leave the observer; SQLite/path details stay private."""


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _value(value):
    if isinstance(value, bytes):
        return ["bytes", value.hex()]
    return [type(value).__name__, value]


def _metadata(info):
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _check_path(root, relative, *, optional=False):
    path = root
    for part in Path(relative).parts:
        if part in {"", ".", ".."}:
            raise SnapshotError("snapshot_path_invalid")
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            if optional:
                return None
            raise SnapshotError("snapshot_required_path_missing") from None
        if stat.S_ISLNK(info.st_mode):
            raise SnapshotError("snapshot_unsafe_path")
        if path != root / relative and not stat.S_ISDIR(info.st_mode):
            raise SnapshotError("snapshot_unsafe_path")
    return info


def _read_file(root, relative, *, optional=False, limit=MAX_FILE):
    info = _check_path(root, relative, optional=optional)
    if info is None:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise SnapshotError("snapshot_unsafe_file")
    descriptor = os.open(root / relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if _identity(os.fstat(descriptor)) != _identity(info):
            raise SnapshotError("snapshot_file_changed")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(limit + 1)
        if len(content) > limit or _identity(os.fstat(descriptor)) != _identity(info):
            raise SnapshotError("snapshot_file_changed")
        current = _check_path(root, relative)
        if _identity(current) != _identity(info):
            raise SnapshotError("snapshot_file_changed")
        return {
            **_metadata(info),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    finally:
        os.close(descriptor)


def _tree(root, relative):
    info = _check_path(root, relative)
    if not stat.S_ISDIR(info.st_mode):
        raise SnapshotError("snapshot_unsafe_path")
    result = {relative: {"directory": True, **_metadata(info)}}
    pending = [root / relative]
    total = 0
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            name = path.relative_to(root).as_posix()
            if any(ord(character) < 32 for character in name):
                raise SnapshotError("snapshot_path_invalid")
            entry = _check_path(root, name)
            if len(result) >= MAX_FILES:
                raise SnapshotError("snapshot_inventory_limit")
            # Installed bytecode is a generated projection, not release source.
            if relative == CODE_TREE and (
                path.name == "__pycache__" or path.suffix == ".pyc"
            ):
                if not (stat.S_ISDIR(entry.st_mode) or stat.S_ISREG(entry.st_mode)):
                    raise SnapshotError("snapshot_unsafe_path")
                continue
            if stat.S_ISDIR(entry.st_mode):
                result[name] = {"directory": True, **_metadata(entry)}
                pending.append(path)
            else:
                result[name] = _read_file(root, name)
                total += result[name]["size"]
                if total > MAX_TOTAL:
                    raise SnapshotError("snapshot_inventory_limit")
    return result


def _database(root):
    before = _check_path(root, DATABASE)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > MAX_DATABASE
    ):
        raise SnapshotError("snapshot_unsafe_database")
    for suffix in ("-wal", "-shm", "-journal"):
        info = _check_path(root, DATABASE + suffix, optional=True)
        if info is not None and (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > MAX_DATABASE
        ):
            raise SnapshotError("snapshot_unsafe_database")
    started = time.monotonic()

    page_size = 4096

    def progress(_status, remaining, total):
        if total * page_size > MAX_DATABASE or time.monotonic() - started > 10:
            raise SnapshotError("snapshot_database_limit")

    # mode=ro includes committed WAL rows. immutable=1 would silently omit them.
    uri = (root / DATABASE).as_uri() + "?mode=ro"
    with (
        closing(sqlite3.connect(uri, uri=True, timeout=2)) as source,
        closing(sqlite3.connect(":memory:")) as snapshot,
    ):
        page_size = source.execute("PRAGMA page_size").fetchone()[0]
        source.backup(snapshot, pages=128, progress=progress, sleep=0.01)
        after = _check_path(root, DATABASE)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise SnapshotError("snapshot_file_changed")
        if snapshot.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise SnapshotError("snapshot_database_invalid")
        tables = [
            row[0]
            for row in snapshot.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        if not REQUIRED_TABLES <= set(tables):
            raise SnapshotError("snapshot_database_schema_invalid")
        if snapshot.execute(
            "SELECT singleton, version FROM schema_version"
        ).fetchall() != [(1, 1)]:
            raise SnapshotError("snapshot_database_schema_invalid")
        result = {}
        row_count = 0
        for table in tables:
            if not IDENTIFIER.fullmatch(table):
                raise SnapshotError("snapshot_database_schema_invalid")
            columns = sorted(
                row[1] for row in snapshot.execute(f'PRAGMA table_info("{table}")')
            )
            if not columns or any(
                not IDENTIFIER.fullmatch(column) for column in columns
            ):
                raise SnapshotError("snapshot_database_schema_invalid")
            column_sql = ",".join(f'"{column}"' for column in columns)
            ordering = ' ORDER BY "id"' if table == "events" else ""
            rows = snapshot.execute(
                f'SELECT {column_sql} FROM "{table}"{ordering}'
            ).fetchmany(MAX_ROWS + 1)
            row_count += len(rows)
            if row_count > MAX_ROWS:
                raise SnapshotError("snapshot_database_limit")
            stable = [
                column
                for column in columns
                if table != "sessions" or column not in SESSION_BOOKKEEPING
            ]
            fingerprints = []
            complete = []
            for row in rows:
                values = dict(
                    zip(columns, (_value(value) for value in row), strict=True)
                )
                complete.append(_digest(values))
                fingerprints.append(
                    _digest({column: values[column] for column in stable})
                )
            result[table] = {
                "columns": columns,
                "rows": fingerprints if table == "events" else sorted(fingerprints),
                "complete_rows": sorted(complete),
            }
        return {"metadata": _metadata(before), "tables": result}


def capture(root: Path = Path("/")) -> dict:
    """Read an installed standard-layout native appliance; return private hashes only."""
    try:
        root = Path(root).absolute()
        if root.is_symlink() or not root.is_dir():
            raise SnapshotError("snapshot_unsafe_root")
        # Do not permit a symlink in a test/execution root's parent chain either.
        if any(parent.is_symlink() for parent in root.parents):
            raise SnapshotError("snapshot_unsafe_root")
        files = {name: _read_file(root, name) for name in STATE_FILES}
        if files[STATE_FILES[0]]["size"] != 32:
            raise SnapshotError("snapshot_key_invalid")
        return {
            "format": 1,
            "database": _database(root),
            "state_files": files,
            "wireguard": _tree(root, STATE_TREE),
            "code": _tree(root, CODE_TREE),
            "installation": {
                name: _read_file(root, name, optional=True) for name in INSTALL_FILES
            },
            "version": _read_file(root, VERSION_FILE, optional=True),
        }
    except SnapshotError:
        raise
    except (OSError, sqlite3.Error, ValueError, TypeError):
        raise SnapshotError("snapshot_read_failed") from None


def compare(before: dict, after: dict, mode: str = "preserved") -> list[str]:
    """Return fixed mismatch codes; callers must retain both private snapshots.

    Compare before post-restore login: restore must revoke *all* saved sessions,
    enrollments and challenges. A success here proves only retained bytes/rows.
    """
    if mode not in {"preserved", "rollback", "restore"}:
        raise ValueError("snapshot_comparison_mode_invalid")
    try:
        if before["format"] != 1 or after["format"] != 1:
            return ["snapshot_format_mismatch"]
        failures = []
        for field in ("state_files", "wireguard"):
            prior, current = before[field], after[field]
            if field == "state_files" and mode == "restore":
                # Portable backups exclude host defaults. The caller separately
                # compares target defaults against its own pre-restore snapshot.
                prior, current = prior[STATE_FILES[0]], current[STATE_FILES[0]]
            if prior != current:
                failures.append(f"snapshot_{field}_mismatch")
        if before["database"]["metadata"] != after["database"]["metadata"]:
            failures.append("snapshot_database_metadata_mismatch")
        old, new = before["database"]["tables"], after["database"]["tables"]
        if not REQUIRED_TABLES <= set(old) or not REQUIRED_TABLES <= set(new):
            return ["snapshot_format_mismatch"]
        if set(old) != set(new):
            failures.append("snapshot_database_schema_mismatch")
        for table in sorted(set(old) & set(new)):
            for entry in (old[table], new[table]):
                if any(
                    not isinstance(entry[name], list)
                    for name in ("columns", "rows", "complete_rows")
                ):
                    return ["snapshot_format_mismatch"]
            if old[table]["columns"] != new[table]["columns"]:
                failures.append("snapshot_database_schema_mismatch")
            if mode == "restore" and table in REVOKED_TABLES:
                if new[table]["complete_rows"]:
                    failures.append("snapshot_revocation_incomplete")
            elif table == "events":
                # Existing event content is immutable; only appended new rows are allowed.
                if old[table]["rows"] != new[table]["rows"][: len(old[table]["rows"])]:
                    failures.append("snapshot_events_changed")
            elif old[table]["rows"] != new[table]["rows"]:
                failures.append("snapshot_database_rows_mismatch")
        if mode == "rollback":
            for field in ("code", "installation", "version"):
                if before[field] != after[field]:
                    failures.append(f"snapshot_{field}_mismatch")
        return sorted(set(failures))
    except (KeyError, TypeError):
        return ["snapshot_format_mismatch"]
