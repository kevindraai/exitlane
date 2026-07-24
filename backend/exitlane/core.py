from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
from pathlib import Path

from exitlane.config import MIN_PASSWORD_LENGTH

DATA = Path(os.getenv("EXITLANE_DATA_DIR", "/etc/exitlane"))
DB = DATA / "exitlane.db"
WG_DIR = DATA / "wireguard"


class SettingsStorageError(RuntimeError):
    """Raised when a transactional settings write cannot be completed."""


def init():
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    WG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(DB) as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT
            );
            CREATE TABLE IF NOT EXISTS webhooks(
                id INTEGER PRIMARY KEY,
                name TEXT,
                url TEXT,
                enabled INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS sessions(
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                public_id TEXT,
                created_at INTEGER,
                last_seen_at INTEGER,
                idle_expires_at INTEGER,
                revoked_at INTEGER,
                client_ip TEXT,
                user_agent_summary TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
            CREATE TRIGGER IF NOT EXISTS delete_user_sessions
            AFTER DELETE ON users
            BEGIN
                DELETE FROM sessions WHERE user_id = OLD.id;
            END;
            CREATE TRIGGER IF NOT EXISTS invalidate_sessions_after_password_change
            AFTER UPDATE OF password_hash, salt ON users
            WHEN OLD.password_hash IS NOT NEW.password_hash OR OLD.salt IS NOT NEW.salt
            BEGIN
                DELETE FROM sessions WHERE user_id = NEW.id;
            END;
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                level TEXT NOT NULL CHECK(level IN ('info', 'warning', 'error')),
                category TEXT NOT NULL,
                code TEXT NOT NULL,
                actor_user_id INTEGER,
                actor_username TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                correlation_id TEXT
            );
            CREATE INDEX IF NOT EXISTS events_created_at_idx ON events(created_at);
            CREATE INDEX IF NOT EXISTS events_category_idx ON events(category);
            CREATE INDEX IF NOT EXISTS events_level_idx ON events(level);
            CREATE INDEX IF NOT EXISTS events_code_idx ON events(code);
            CREATE TABLE IF NOT EXISTS vpn_latency_cache(
                provider TEXT NOT NULL,
                country_code TEXT NOT NULL,
                server TEXT NOT NULL,
                latency_ms INTEGER,
                status TEXT NOT NULL CHECK(status IN ('reachable', 'unreachable', 'unknown')),
                measured_at TEXT NOT NULL,
                PRIMARY KEY(provider, server)
            );
            CREATE INDEX IF NOT EXISTS vpn_latency_country_idx
                ON vpn_latency_cache(provider, country_code, measured_at);
            CREATE TABLE IF NOT EXISTS recovery_codes(
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                used_at INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS mfa_enrollments(
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                session_hash TEXT NOT NULL,
                encrypted_secret BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS mfa_challenges(
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                client_ip TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        user_columns = {row[1] for row in c.execute("PRAGMA table_info(users)")}
        for name, declaration in {
            "mfa_enabled": "INTEGER NOT NULL DEFAULT 0",
            "encrypted_totp_secret": "BLOB",  # nosec B105
            "last_totp_counter": "INTEGER",
            "mfa_enabled_at": "INTEGER",
            "mfa_updated_at": "INTEGER",
        }.items():
            if name not in user_columns:
                c.execute(f"ALTER TABLE users ADD COLUMN {name} {declaration}")
        session_columns = {row[1] for row in c.execute("PRAGMA table_info(sessions)")}
        for name, declaration in {
            "public_id": "TEXT",
            "created_at": "INTEGER",
            "last_seen_at": "INTEGER",
            "idle_expires_at": "INTEGER",
            "revoked_at": "INTEGER",
            "client_ip": "TEXT",
            "user_agent_summary": "TEXT",
        }.items():
            if name not in session_columns:
                c.execute(f"ALTER TABLE sessions ADD COLUMN {name} {declaration}")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS sessions_public_id_idx ON sessions(public_id)")
        # Legacy sessions lack the metadata needed to enforce the new idle policy.
        c.execute("DELETE FROM sessions WHERE public_id IS NULL")


def setting(key, default=None):
    with sqlite3.connect(DB) as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return default if row is None else json.loads(row[0])


def stored_settings(keys: tuple[str, ...]) -> dict[str, object]:
    """Return only explicitly stored settings from an internal key allowlist."""
    with sqlite3.connect(DB) as connection:
        rows = [
            row
            for key in keys
            if (
                row := connection.execute(
                    "SELECT key,value FROM settings WHERE key=?", (key,)
                ).fetchone()
            )
        ]
    return {key: json.loads(value) for key, value in rows}


def set_setting(key, value):
    with sqlite3.connect(DB) as c:
        c.execute(
            "INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )


def set_settings(values: dict[str, object]) -> None:
    """Persist a validated group of settings in one transaction."""
    serialized = [(key, json.dumps(value)) for key, value in values.items()]
    try:
        with sqlite3.connect(DB, timeout=5.0) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                """INSERT INTO settings(key, value) VALUES(?, ?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                serialized,
            )
    except sqlite3.DatabaseError as error:
        raise SettingsStorageError("Settings could not be stored") from error


def delete_settings(keys: tuple[str, ...]) -> None:
    """Delete a validated group of internal settings in one transaction."""
    if not keys:
        return
    try:
        with sqlite3.connect(DB, timeout=5.0) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany("DELETE FROM settings WHERE key=?", ((key,) for key in keys))
    except sqlite3.DatabaseError as error:
        raise SettingsStorageError("Settings could not be deleted") from error


def hash_password(password, salt=None):
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must have at least {MIN_PASSWORD_LENGTH} characters")
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    try:
        candidate, _ = hash_password(password, bytes.fromhex(salt))
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(candidate, password_hash)


async def command(*args, timeout=60, input_text=None, environment=None):
    try:
        p = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if input_text else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
    except FileNotFoundError:
        return 127, "", "command not found"
    try:
        out, err = await asyncio.wait_for(
            p.communicate(input_text.encode() if input_text else None), timeout
        )
    except TimeoutError:
        p.kill()
        await p.wait()
        return 124, "", "timeout"
    except asyncio.CancelledError:
        p.kill()
        await p.wait()
        raise
    return p.returncode, out.decode(errors="replace").strip(), err.decode(errors="replace").strip()
