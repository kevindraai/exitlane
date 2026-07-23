from __future__ import annotations

import sqlite3

from exitlane import core


class CredentialError(ValueError):
    """A stable, non-sensitive credential-management failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def change_password(
    user_id: int,
    *,
    current_password: str | None,
    new_password: str,
    verify_current: bool = True,
) -> None:
    """Replace an administrator password and revoke every session atomically."""
    with sqlite3.connect(core.DB, timeout=5.0) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT password_hash, salt FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            raise CredentialError("invalid_credentials")
        if verify_current and (
            current_password is None
            or not core.verify_password(current_password, row[0], row[1])
        ):
            raise CredentialError("invalid_credentials")
        if current_password is not None and core.verify_password(new_password, row[0], row[1]):
            raise CredentialError("password_unchanged")
        try:
            digest, salt = core.hash_password(new_password)
        except ValueError as error:
            raise CredentialError("password_policy") from error
        connection.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (digest, salt, user_id),
        )
        # Keep this explicit in addition to the migration trigger for old databases.
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def reset_administrator_password(new_password: str) -> dict:
    with sqlite3.connect(core.DB) as connection:
        rows = connection.execute("SELECT id, username FROM users ORDER BY id").fetchall()
    if len(rows) != 1:
        raise CredentialError("administrator_unavailable")
    user_id, username = rows[0]
    change_password(
        user_id,
        current_password=None,
        new_password=new_password,
        verify_current=False,
    )
    return {"id": user_id, "username": username}
