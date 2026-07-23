from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from exitlane import core
from exitlane.config import CONFIG_DIR, SESSION_IDLE_TIMEOUT_SECONDS, SESSION_MAX_AGE_SECONDS

RECOVERY_CODE_COUNT = 10
MFA_CHALLENGE_SECONDS = 300
MFA_ENROLLMENT_SECONDS = 600
MFA_MAX_ATTEMPTS = 5


class AuthSecurityError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def master_key_path() -> Path:
    configured = os.getenv("EXITLANE_MASTER_KEY_FILE")
    if configured:
        return Path(configured)
    # Tests and explicitly embedded deployments override core.DB as one isolated state root.
    default_data = Path(os.getenv("EXITLANE_DATA_DIR", "/var/lib/exitlane"))
    if core.DB.parent != default_data:
        return core.DB.parent / "secret.key"
    return CONFIG_DIR / "secret.key"


def ensure_master_key() -> Path:
    path = master_key_path()
    if path.exists():
        if path.stat().st_mode & 0o077 or len(path.read_bytes()) != 32:
            raise RuntimeError("ExitLane master key is invalid or has unsafe permissions")
        return path
    if core.DB.exists():
        try:
            with sqlite3.connect(core.DB) as connection:
                enabled = connection.execute(
                    "SELECT COUNT(*) FROM users WHERE mfa_enabled=1"
                ).fetchone()[0]
        except sqlite3.DatabaseError:
            enabled = 0
        if enabled:
            raise RuntimeError(
                "ExitLane master key is missing while MFA is enabled; use local MFA recovery"
            )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, secrets.token_bytes(32))
    finally:
        os.close(descriptor)
    return path


def _key() -> bytes:
    try:
        key = master_key_path().read_bytes()
    except OSError as error:
        raise RuntimeError("ExitLane master key is unavailable; use local MFA recovery") from error
    if len(key) != 32:
        raise RuntimeError("ExitLane master key is invalid")
    return key


def encrypt_secret(secret: str) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_key()).encrypt(nonce, secret.encode(), b"exitlane-totp-v1")


def decrypt_secret(value: bytes) -> str:
    try:
        return AESGCM(_key()).decrypt(value[:12], value[12:], b"exitlane-totp-v1").decode()
    except Exception as error:
        raise RuntimeError("Stored MFA secret cannot be decrypted; use local MFA recovery") from error


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def summarize_user_agent(value: str) -> str:
    text = value.casefold()
    browser = next((name for marker, name in (("firefox", "Firefox"), ("edg/", "Edge"), ("chrome", "Chrome"), ("safari", "Safari")) if marker in text), "Browser")
    platform = next((name for marker, name in (("windows", "Windows"), ("android", "Android"), ("iphone", "iPhone"), ("mac os", "macOS"), ("linux", "Linux")) if marker in text), "")
    return f"{browser} on {platform}" if platform else browser


def create_session(user_id: int, client_ip: str, user_agent: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with sqlite3.connect(core.DB) as connection:
        connection.execute(
            """INSERT INTO sessions(token_hash,user_id,expires_at,public_id,created_at,last_seen_at,
               idle_expires_at,client_ip,user_agent_summary) VALUES(?,?,?,?,?,?,?,?,?)""",
            (token_hash(token), user_id, now + SESSION_MAX_AGE_SECONDS, str(uuid.uuid4()), now, now,
             now + SESSION_IDLE_TIMEOUT_SECONDS, client_ip, summarize_user_agent(user_agent)),
        )
    return token


def session_user(token: str | None) -> dict | None:
    if not token:
        return None
    now = int(time.time())
    digest = token_hash(token)
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM sessions WHERE expires_at<=? OR idle_expires_at<=? OR revoked_at IS NOT NULL",
            (now, now),
        )
        row = connection.execute(
            """SELECT users.id,users.username,sessions.public_id,sessions.last_seen_at
               FROM sessions JOIN users ON users.id=sessions.user_id
               WHERE sessions.token_hash=? AND sessions.expires_at>? AND sessions.idle_expires_at>?""",
            (digest, now, now),
        ).fetchone()
        if row and row[3] <= now - 60:
            connection.execute(
                "UPDATE sessions SET last_seen_at=?,idle_expires_at=? WHERE token_hash=?",
                (now, now + SESSION_IDLE_TIMEOUT_SECONDS, digest),
            )
    return None if row is None else {"id": row[0], "username": row[1], "session_id": row[2]}


def start_enrollment(user_id: int, session_token: str) -> tuple[str, str]:
    enrollment, secret, now = secrets.token_urlsafe(32), pyotp.random_base32(), int(time.time())
    with sqlite3.connect(core.DB) as connection:
        connection.execute("DELETE FROM mfa_enrollments WHERE user_id=?", (user_id,))
        connection.execute(
            "INSERT INTO mfa_enrollments VALUES(?,?,?,?,?,?)",
            (token_hash(enrollment), user_id, token_hash(session_token), encrypt_secret(secret), now,
             now + MFA_ENROLLMENT_SECONDS),
        )
    return enrollment, secret


def totp_counter(secret: str, code: str, now: int, last_counter: int | None) -> int | None:
    totp = pyotp.TOTP(secret)
    for offset in (-1, 0, 1):
        counter = now // 30 + offset
        if (last_counter is None or counter > last_counter) and hmac.compare_digest(totp.at(counter * 30), code.strip()):
            return counter
    return None


def _recovery_digest(code: str) -> str:
    return hmac.new(_key(), code.replace("-", "").casefold().encode(), hashlib.sha256).hexdigest()


def new_recovery_codes(connection: sqlite3.Connection, user_id: int, now: int) -> list[str]:
    codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}".upper() for _ in range(RECOVERY_CODE_COUNT)]
    connection.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
    connection.executemany(
        "INSERT INTO recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)",
        [(user_id, _recovery_digest(code), now) for code in codes],
    )
    return codes


def confirm_enrollment(user_id: int, session_token: str, enrollment: str, code: str) -> list[str]:
    now = int(time.time())
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """SELECT encrypted_secret,expires_at FROM mfa_enrollments
               WHERE token_hash=? AND user_id=? AND session_hash=?""",
            (token_hash(enrollment), user_id, token_hash(session_token)),
        ).fetchone()
        if row is None or row[1] <= now:
            raise AuthSecurityError("mfa_enrollment_expired")
        counter = totp_counter(decrypt_secret(row[0]), code, now, None)
        if counter is None:
            raise AuthSecurityError("invalid_mfa_code")
        connection.execute(
            """UPDATE users SET mfa_enabled=1,encrypted_totp_secret=?,last_totp_counter=?,
               mfa_enabled_at=?,mfa_updated_at=? WHERE id=?""",
            (row[0], counter, now, now, user_id),
        )
        codes = new_recovery_codes(connection, user_id, now)
        connection.execute("DELETE FROM mfa_enrollments WHERE user_id=?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, token_hash(session_token)))
    return codes


def verify_totp(user_id: int, code: str) -> bool:
    now = int(time.time())
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT encrypted_totp_secret,last_totp_counter FROM users WHERE id=? AND mfa_enabled=1", (user_id,)
        ).fetchone()
        if row is None:
            return False
        counter = totp_counter(decrypt_secret(row[0]), code, now, row[1])
        if counter is None:
            return False
        return connection.execute(
            "UPDATE users SET last_totp_counter=? WHERE id=? AND (last_totp_counter IS NULL OR last_totp_counter<?)",
            (counter, user_id, counter),
        ).rowcount == 1


def verify_recovery(user_id: int, code: str) -> bool:
    now = int(time.time())
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (user_id, _recovery_digest(code)),
        ).fetchone()
        return bool(row and connection.execute(
            "UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL", (now, row[0])
        ).rowcount == 1)


def start_challenge(user_id: int, client_ip: str) -> str:
    challenge, now = secrets.token_urlsafe(32), int(time.time())
    with sqlite3.connect(core.DB) as connection:
        connection.execute("DELETE FROM mfa_challenges WHERE user_id=?", (user_id,))
        connection.execute(
            "INSERT INTO mfa_challenges VALUES(?,?,?,?,?,?)",
            (token_hash(challenge), user_id, now, now + MFA_CHALLENGE_SECONDS, 0, client_ip),
        )
    return challenge


def consume_challenge(challenge: str, code: str, mode: str, client_ip: str) -> tuple[int, bool]:
    now = int(time.time())
    digest = token_hash(challenge)
    with sqlite3.connect(core.DB) as connection:
        row = connection.execute(
            "SELECT user_id,expires_at,attempts,client_ip FROM mfa_challenges WHERE token_hash=?",
            (digest,),
        ).fetchone()
        if row is None or row[1] <= now or row[2] >= MFA_MAX_ATTEMPTS or not hmac.compare_digest(row[3], client_ip):
            connection.execute("DELETE FROM mfa_challenges WHERE token_hash=?", (digest,))
            raise AuthSecurityError("mfa_challenge_expired")
    valid = verify_recovery(row[0], code) if mode == "recovery" else verify_totp(row[0], code)
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if not valid:
            connection.execute(
                "UPDATE mfa_challenges SET attempts=attempts+1 WHERE token_hash=?", (digest,)
            )
            if row[2] + 1 >= MFA_MAX_ATTEMPTS:
                connection.execute("DELETE FROM mfa_challenges WHERE token_hash=?", (digest,))
                raise AuthSecurityError("too_many_attempts")
            raise AuthSecurityError("invalid_mfa_code")
        consumed = connection.execute("DELETE FROM mfa_challenges WHERE token_hash=?", (digest,))
        if consumed.rowcount != 1:
            raise AuthSecurityError("mfa_challenge_expired")
        return row[0], mode == "recovery"


def mfa_status(user_id: int) -> dict:
    with sqlite3.connect(core.DB) as connection:
        row = connection.execute(
            "SELECT mfa_enabled,mfa_updated_at FROM users WHERE id=?", (user_id,)
        ).fetchone()
        remaining = connection.execute(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (user_id,)
        ).fetchone()[0]
    return {"enabled": bool(row and row[0]), "updated_at": row[1] if row else None, "recovery_codes_remaining": remaining}


def list_sessions(user_id: int, current_id: str) -> list[dict]:
    now = int(time.time())
    with sqlite3.connect(core.DB) as connection:
        rows = connection.execute(
            """SELECT public_id,created_at,last_seen_at,expires_at,idle_expires_at,client_ip,user_agent_summary
               FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>? AND idle_expires_at>?
               ORDER BY last_seen_at DESC""", (user_id, now, now)
        ).fetchall()
    return [
        {"id": row[0], "current": hmac.compare_digest(row[0], current_id), "created_at": row[1],
         "last_seen_at": row[2], "expires_at": min(row[3], row[4]), "client_ip": row[5],
         "user_agent": row[6]} for row in rows
    ]


def revoke_session(user_id: int, public_id: str, current_id: str) -> bool:
    if hmac.compare_digest(public_id, current_id):
        raise AuthSecurityError("current_session")
    with sqlite3.connect(core.DB) as connection:
        return connection.execute(
            "DELETE FROM sessions WHERE user_id=? AND public_id=?", (user_id, public_id)
        ).rowcount == 1


def revoke_other_sessions(user_id: int, current_id: str) -> int:
    with sqlite3.connect(core.DB) as connection:
        return connection.execute(
            "DELETE FROM sessions WHERE user_id=? AND public_id<>?", (user_id, current_id)
        ).rowcount


def regenerate_recovery_codes(user_id: int, current_session_id: str) -> list[str]:
    now = int(time.time())
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        codes = new_recovery_codes(connection, user_id, now)
        connection.execute(
            "DELETE FROM sessions WHERE user_id=? AND public_id<>?", (user_id, current_session_id)
        )
        connection.execute("UPDATE users SET mfa_updated_at=? WHERE id=?", (now, user_id))
    return codes


def disable_mfa(user_id: int) -> None:
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """UPDATE users SET mfa_enabled=0,encrypted_totp_secret=NULL,last_totp_counter=NULL,
               mfa_updated_at=? WHERE id=?""", (int(time.time()), user_id)
        )
        connection.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        connection.execute("DELETE FROM mfa_enrollments WHERE user_id=?", (user_id,))
        connection.execute("DELETE FROM mfa_challenges WHERE user_id=?", (user_id,))
        connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
