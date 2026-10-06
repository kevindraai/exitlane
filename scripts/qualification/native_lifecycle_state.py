"""Private native qualification fingerprints, never traffic or decryption evidence.

The caller owns target authorization and writer quiescence. Observations require the
standard native layout. Snapshot before authentication probes: those legitimately
consume MFA factors. Fingerprints are private evidence, not anonymous/public data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import stat
import subprocess
import time
import uuid
from contextlib import closing
from datetime import UTC, datetime
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
V1_TABLES = REQUIRED_TABLES
NEW_TABLES = frozenset({"wireguard_peers", "wireguard_ingress_profile"})
# Generated from the published v1.0.0 core.init_database SQLite schema, including
# its existing triggers, indexes, autoindexes, constraints and ALTER-added columns.
V1_OBJECTS_DIGEST = "e98abaceb77e69c5e292ded22cb4427428ed2854b19f08f5ec0cba78c502f73d"
V1_OBJECTS = frozenset(
    {
        *(f"table:{name}" for name in V1_TABLES),
        "index:events_category_idx",
        "index:events_code_idx",
        "index:events_created_at_idx",
        "index:events_level_idx",
        "index:sessions_expires_at_idx",
        "index:sessions_public_id_idx",
        "index:sessions_user_id_idx",
        "index:vpn_latency_country_idx",
        "index:sqlite_autoindex_mfa_challenges_1",
        "index:sqlite_autoindex_mfa_enrollments_1",
        "index:sqlite_autoindex_provider_secrets_1",
        "index:sqlite_autoindex_recovery_codes_1",
        "index:sqlite_autoindex_sessions_1",
        "index:sqlite_autoindex_settings_1",
        "index:sqlite_autoindex_users_1",
        "index:sqlite_autoindex_vpn_latency_cache_1",
        "trigger:delete_user_sessions",
        "trigger:invalidate_sessions_after_password_change",
    }
)
NEW_OBJECTS = {
    "table:wireguard_peers": """CREATE TABLE wireguard_peers(
        peer_id TEXT PRIMARY KEY, name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '', public_key TEXT NOT NULL UNIQUE,
        tunnel_ip TEXT NOT NULL UNIQUE, config_name TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
        is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0, 1)),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT)""",
    "table:wireguard_ingress_profile": """CREATE TABLE wireguard_ingress_profile(
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1), endpoint TEXT NOT NULL,
        dns TEXT NOT NULL, allowed_ips TEXT NOT NULL,
        client_keepalive INTEGER NOT NULL, server_keepalive INTEGER NOT NULL,
        server_public_key TEXT NOT NULL)""",
    "index:wireguard_default_peer_idx": """CREATE UNIQUE INDEX wireguard_default_peer_idx
        ON wireguard_peers(is_default) WHERE is_default = 1""",
    **{
        f"index:sqlite_autoindex_wireguard_peers_{number}": None
        for number in range(1, 5)
    },
}
NEW_COLUMNS = {
    "wireguard_peers": sorted(
        (
            "peer_id",
            "name",
            "description",
            "public_key",
            "tunnel_ip",
            "config_name",
            "status",
            "is_default",
            "created_at",
            "updated_at",
            "revoked_at",
        )
    ),
    "wireguard_ingress_profile": sorted(
        (
            "singleton",
            "endpoint",
            "dns",
            "allowed_ips",
            "client_keepalive",
            "server_keepalive",
            "server_public_key",
        )
    ),
}


def _sql(sql):
    if sql is None:
        return None
    return re.sub(r"\s*([(),])\s*", r"\1", " ".join(sql.split()))


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


def _read_file(root, relative, *, optional=False, limit=MAX_FILE, with_content=False):
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
        result = {
            **_metadata(info),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        return (result, content) if with_content else result
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
        objects = {
            f"{kind}:{name}": {"table": table, "sql": sql}
            for kind, name, table, sql in snapshot.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
            )
        }
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
            if table in NEW_TABLES:
                result[table]["values"] = [
                    dict(zip(columns, row, strict=True))
                    for row in snapshot.execute(f'SELECT {column_sql} FROM "{table}"')
                ]
        return {"metadata": _metadata(before), "tables": result, "objects": objects}


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
        if before["database"]["objects"] != after["database"]["objects"]:
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


def _config(content):
    section = None
    result = {"Interface": [], "Peer": []}
    for line in content.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in {"[Interface]", "[Peer]"}:
            section = line[1:-1]
            result[section].append({})
            continue
        if section is None or "=" not in line:
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        key, value = (part.strip() for part in line.split("=", 1))
        target = result[section][-1]
        if not key or not value or key in target:
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        target[key] = value
    if len(result["Interface"]) != 1 or len(result["Peer"]) != 1:
        raise SnapshotError("snapshot_legacy_certificate_invalid")
    return result["Interface"][0], result["Peer"][0]


def _public_key(private):
    if not isinstance(private, str) or len(private) > 128:
        raise SnapshotError("snapshot_legacy_certificate_invalid")
    try:
        result = subprocess.run(
            ["/usr/bin/wg", "pubkey"],
            input=(private + "\n").encode(),
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise SnapshotError("snapshot_legacy_certificate_invalid") from None
    if result.returncode or len(result.stdout) != 45:
        raise SnapshotError("snapshot_legacy_certificate_invalid")
    return result.stdout.decode().strip()


def legacy_certificate(root: Path, before: dict) -> dict:
    """Bind pre-upgrade v1 settings and actual config bytes to one expected migration."""
    try:
        root = Path(root)
        if (
            set(before["database"]["tables"]) != V1_TABLES
            or set(before["database"]["objects"]) != V1_OBJECTS
            or _digest(before["database"]["objects"]) != V1_OBJECTS_DIGEST
            or before["version"]["sha256"] != hashlib.sha256(b"1.0.0\n").hexdigest()
        ):
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        with sqlite3.connect((root / DATABASE).as_uri() + "?mode=ro", uri=True) as db:
            live_objects = {
                f"{kind}:{name}": {"table": table, "sql": sql}
                for kind, name, table, sql in db.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
                )
            }
            rows = db.execute("SELECT key,value FROM settings").fetchall()
        if (
            live_objects != before["database"]["objects"]
            or _read_file(root, VERSION_FILE) != before["version"]
        ):
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        fingerprint = sorted(
            _digest({"key": _value(key), "value": _value(value)}) for key, value in rows
        )
        if fingerprint != before["database"]["tables"]["settings"]["rows"]:
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        settings = {key: json.loads(value) for key, value in rows}
        if settings.get("wireguard_configured") is not True:
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        interface = settings["wireguard_interface"]
        client = settings["wireguard_client_name"]
        if not isinstance(interface, str) or not re.fullmatch(
            r"[A-Za-z0-9-]{1,15}", interface
        ):
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        if not isinstance(client, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}", client
        ):
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        files = {}
        for name in (interface, client):
            relative = f"{STATE_TREE}/{name}.conf"
            metadata, content = _read_file(
                root, relative, with_content=True, limit=65536
            )
            if metadata != before["wireguard"][relative]:
                raise SnapshotError("snapshot_legacy_certificate_invalid")
            files[name] = content
        if {name for name in before["wireguard"] if name.endswith(".conf")} != {
            f"{STATE_TREE}/{interface}.conf",
            f"{STATE_TREE}/{client}.conf",
        }:
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        server, peer = _config(files[interface])
        client_interface, remote = _config(files[client])
        address = ipaddress.IPv4Interface(client_interface["Address"])
        server_address = ipaddress.IPv4Interface(server["Address"])
        if (
            address.network.prefixlen != 32
            or address.ip not in server_address.network
            or peer["AllowedIPs"] != f"{address.ip}/32"
            or peer["PublicKey"] != _public_key(client_interface["PrivateKey"])
            or remote["PublicKey"] != _public_key(server["PrivateKey"])
        ):
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        client_keepalive = int(remote.get("PersistentKeepalive", "25"))
        server_keepalive = int(peer.get("PersistentKeepalive", "25"))
        if not 0 <= client_keepalive <= 65535 or not 0 <= server_keepalive <= 65535:
            raise SnapshotError("snapshot_legacy_certificate_invalid")
        return {
            "before": _digest(before),
            "certified_at": time.time(),
            "peer": {
                "name": client,
                "description": "",
                "public_key": peer["PublicKey"],
                "tunnel_ip": str(address.ip),
                "config_name": client,
                "status": "active",
                "is_default": 1,
                "revoked_at": None,
            },
            "profile": {
                "singleton": 1,
                "endpoint": remote["Endpoint"],
                "dns": client_interface["DNS"],
                "allowed_ips": remote["AllowedIPs"],
                "client_keepalive": client_keepalive,
                "server_keepalive": server_keepalive,
                "server_public_key": remote["PublicKey"],
            },
        }
    except SnapshotError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, sqlite3.Error, OSError):
        raise SnapshotError("snapshot_legacy_certificate_invalid") from None


def compare_v1_upgrade(
    before: dict, after: dict, certificate: dict, started: float, finished: float
) -> list[str]:
    """Only the pinned, successful v1.0.0 to v1.0.1 migration may add these rows."""
    try:
        failures = []
        if certificate["before"] != _digest(before):
            return ["snapshot_upgrade_certificate_mismatch"]
        if (
            not isinstance(certificate["certified_at"], (int, float))
            or not certificate["certified_at"] <= started <= finished
        ):
            return ["snapshot_upgrade_certificate_mismatch"]
        if (
            set(before["database"]["tables"]) != V1_TABLES
            or set(after["database"]["tables"]) != V1_TABLES | NEW_TABLES
            or set(before["database"]["objects"]) != V1_OBJECTS
            or _digest(before["database"]["objects"]) != V1_OBJECTS_DIGEST
            or set(after["database"]["objects"]) != V1_OBJECTS | NEW_OBJECTS.keys()
        ):
            return ["snapshot_upgrade_schema_mismatch"]
        prior_objects = before["database"]["objects"]
        current_objects = after["database"]["objects"]
        if any(current_objects[name] != value for name, value in prior_objects.items()):
            failures.append("snapshot_upgrade_schema_mismatch")
        for name, expected in NEW_OBJECTS.items():
            current = current_objects[name]
            table = (
                name.split(":", 1)[1]
                if name.startswith("table:")
                else "wireguard_peers"
            )
            if current["table"] != table or _sql(current["sql"]) != _sql(expected):
                failures.append("snapshot_upgrade_schema_mismatch")
        for name, columns in NEW_COLUMNS.items():
            if after["database"]["tables"][name]["columns"] != columns:
                failures.append("snapshot_upgrade_schema_mismatch")
        old_only = {
            **after,
            "database": {
                **after["database"],
                "tables": {
                    name: after["database"]["tables"][name] for name in V1_TABLES
                },
                "objects": {name: current_objects[name] for name in V1_OBJECTS},
            },
        }
        failures.extend(compare(before, old_only, "preserved"))
        peer_rows = after["database"]["tables"]["wireguard_peers"]["values"]
        profile_rows = after["database"]["tables"]["wireguard_ingress_profile"][
            "values"
        ]
        if len(peer_rows) != 1 or len(profile_rows) != 1:
            failures.append("snapshot_upgrade_rows_mismatch")
        else:
            peer, profile = peer_rows[0], profile_rows[0]
            if (
                {key: peer.get(key) for key in certificate["peer"]}
                != certificate["peer"]
                or profile != certificate["profile"]
                or set(peer) != set(NEW_COLUMNS["wireguard_peers"])
            ):
                failures.append("snapshot_upgrade_rows_mismatch")
            try:
                identifier = peer["peer_id"]
                stamp = datetime.fromisoformat(peer["created_at"])
                if (
                    not isinstance(identifier, str)
                    or len(identifier) != 32
                    or uuid.UUID(hex=identifier).version != 4
                    or uuid.UUID(hex=identifier).hex != identifier
                    or peer["updated_at"] != peer["created_at"]
                    or stamp.tzinfo != UTC
                    or not started <= stamp.timestamp() <= finished
                ):
                    failures.append("snapshot_upgrade_identity_mismatch")
            except (KeyError, TypeError, ValueError):
                failures.append("snapshot_upgrade_identity_mismatch")
        return sorted(set(failures))
    except (KeyError, TypeError, ValueError):
        return ["snapshot_format_mismatch"]
