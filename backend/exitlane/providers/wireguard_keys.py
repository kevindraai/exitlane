"""Shared local WireGuard key generation and validation for direct providers."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _wireguard_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode("ascii"), base64.b64encode(public_raw).decode(
        "ascii"
    )


def _valid_wireguard_key(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 44:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        return None
    return value if len(decoded) == 32 else None


def _public_key_for_private(private_key: object) -> str | None:
    private = _valid_wireguard_key(private_key)
    if private is None:
        return None
    try:
        key = X25519PrivateKey.from_private_bytes(base64.b64decode(private))
    except ValueError:
        return None
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public).decode("ascii")
