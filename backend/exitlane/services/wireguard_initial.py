"""Durable first-ingress intent shared by native and container startup recovery."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from pathlib import Path

from exitlane.services import wireguard

SETTINGS = (
    "wireguard_configured",
    "wireguard_client_name",
    "wireguard_interface",
    "wireguard_endpoint",
    "wireguard_subnet",
    "wireguard_dns",
    "wireguard_port",
    "setup_current_step",
)
_INTERFACE = re.compile(r"[A-Za-z0-9-]{1,15}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class InitialSetupError(RuntimeError):
    pass


def path(database: Path) -> Path:
    return database.parent / ".wireguard-initial-setup.json"


def _sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write(database: Path, record: dict) -> None:
    validate(record)
    wireguard._atomic_write(path(database), json.dumps(record, sort_keys=True))
    _sync_directory(database.parent)


def clear(database: Path) -> None:
    path(database).unlink()
    _sync_directory(database.parent)


def validate(record: object) -> dict:
    if (
        not isinstance(record, dict)
        or set(record)
        != {"interface", "client", "subnet", "activation_attempted", "settings", "phase"}
        or record["phase"] not in {"pending", "committed"}
        or not isinstance(record["interface"], str)
        or _INTERFACE.fullmatch(record["interface"]) is None
        or not isinstance(record["client"], str)
        or _CLIENT.fullmatch(record["client"]) is None
        or record["client"] == record["interface"]
        or not isinstance(record["subnet"], str)
        or not isinstance(record["activation_attempted"], bool)
        or not isinstance(record["settings"], dict)
        or not record["settings"].keys() <= set(SETTINGS)
    ):
        raise InitialSetupError("wireguard_recovery_failed")
    wireguard._validated_ingress_network(record["subnet"])
    return record


def read(database: Path) -> dict:
    try:
        descriptor = os.open(path(database), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or facts.st_mode & 0o077
                or facts.st_nlink != 1
                or facts.st_size > 4096
            ):
                raise InitialSetupError("wireguard_recovery_failed")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                data = source.read(4097)
        finally:
            os.close(descriptor)
        if len(data) > 4096:
            raise InitialSetupError("wireguard_recovery_failed")
        return validate(json.loads(data))
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        raise InitialSetupError("wireguard_recovery_failed") from error


def _owned_file(path: Path) -> None:
    try:
        facts = path.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or facts.st_mode & 0o077
        or facts.st_nlink != 1
    ):
        raise InitialSetupError("wireguard_recovery_failed")


def rollback_persistent(database: Path, directory: Path, record: dict) -> None:
    """Leave intent in place until the caller proves recovery and clears it."""
    validate(record)
    # A committed operation is never rolled back by startup recovery.
    if record["phase"] != "pending":
        raise InitialSetupError("wireguard_recovery_failed")
    names = (record["interface"], record["client"])
    for name in names:
        _owned_file(directory / f"{name}.conf")
    with sqlite3.connect(database, timeout=5) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DELETE FROM wireguard_peers")
        connection.execute("DELETE FROM wireguard_ingress_profile")
        connection.executemany("DELETE FROM settings WHERE key=?", ((key,) for key in SETTINGS))
        connection.executemany(
            "INSERT INTO settings(key,value) VALUES(?,?)",
            ((key, json.dumps(value)) for key, value in record["settings"].items()),
        )
    # Clearing database claims before deleting files makes every crash cut
    # acceptable to the container parent validator on the next startup.
    for name in names:
        (directory / f"{name}.conf").unlink(missing_ok=True)
    for entry in directory.iterdir():
        if any(
            re.fullmatch(rf"\.{re.escape(name)}\.conf\.[A-Za-z0-9_]{{8}}", entry.name)
            for name in names
        ):
            _owned_file(entry)
            entry.unlink()
    _sync_directory(directory)
