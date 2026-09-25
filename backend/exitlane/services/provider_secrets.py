from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from collections.abc import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from exitlane import core
from exitlane.services import auth_security

PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
FORMAT_VERSION = 1


class ProviderSecretError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _aad(provider_id: str) -> bytes:
    if not isinstance(provider_id, str) or PROVIDER_ID.fullmatch(provider_id) is None:
        raise ProviderSecretError("provider_secret_invalid")
    return f"exitlane-provider-secret-v{FORMAT_VERSION}:{provider_id}".encode("ascii")


def _key() -> bytes:
    try:
        key = auth_security.master_key_path().read_bytes()
    except OSError as error:
        raise ProviderSecretError("provider_secret_key_unavailable") from error
    if len(key) != 32:
        raise ProviderSecretError("provider_secret_key_unavailable")
    return key


def save(provider_id: str, payload: Mapping[str, object]) -> None:
    try:
        encoded = json.dumps(
            {"version": FORMAT_VERSION, "state": dict(payload)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProviderSecretError("provider_secret_invalid") from error
    nonce = secrets.token_bytes(12)
    encrypted = nonce + AESGCM(_key()).encrypt(nonce, encoded, _aad(provider_id))
    try:
        with sqlite3.connect(core.DB, timeout=5.0) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO provider_secrets(provider_id, encrypted_payload, updated_at)
                   VALUES(?, ?, ?)
                   ON CONFLICT(provider_id) DO UPDATE SET
                     encrypted_payload=excluded.encrypted_payload,
                     updated_at=excluded.updated_at""",
                (provider_id, encrypted, int(time.time())),
            )
    except sqlite3.DatabaseError as error:
        raise ProviderSecretError("provider_secret_storage_failed") from error


def load(provider_id: str) -> dict[str, object] | None:
    aad = _aad(provider_id)
    try:
        with sqlite3.connect(core.DB, timeout=5.0) as connection:
            row = connection.execute(
                "SELECT encrypted_payload FROM provider_secrets WHERE provider_id=?",
                (provider_id,),
            ).fetchone()
    except sqlite3.DatabaseError as error:
        raise ProviderSecretError("provider_secret_storage_failed") from error
    if row is None:
        return None
    value = bytes(row[0])
    if len(value) < 29:
        raise ProviderSecretError("provider_secret_invalid")
    try:
        decoded = AESGCM(_key()).decrypt(value[:12], value[12:], aad)
        envelope = json.loads(decoded)
    except Exception as error:
        raise ProviderSecretError("provider_secret_invalid") from error
    if (
        not isinstance(envelope, dict)
        or envelope.get("version") != FORMAT_VERSION
        or not isinstance(envelope.get("state"), dict)
    ):
        raise ProviderSecretError("provider_secret_invalid")
    return dict(envelope["state"])


def delete(provider_id: str) -> None:
    _aad(provider_id)
    try:
        with sqlite3.connect(core.DB, timeout=5.0) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM provider_secrets WHERE provider_id=?", (provider_id,))
    except sqlite3.DatabaseError as error:
        raise ProviderSecretError("provider_secret_storage_failed") from error
