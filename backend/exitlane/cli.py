from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from collections.abc import Callable, Sequence

from exitlane import core
from exitlane.events import record_event
from exitlane.services.credentials import CredentialError, reset_administrator_password
from exitlane.services.auth_security import disable_mfa as disable_administrator_mfa


def reset_password(
    *,
    password_reader: Callable[[str], str] = getpass.getpass,
    effective_user_id: int | None = None,
) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    first = password_reader("New administrator password: ")
    confirmation = password_reader("Repeat new administrator password: ")
    if first != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2
    try:
        actor = reset_administrator_password(first)
    except CredentialError as error:
        if error.code == "password_policy":
            print("The supplied value does not meet the configured credential policy.", file=sys.stderr)
        elif error.code == "administrator_unavailable":
            print("Exactly one local administrator is required.", file=sys.stderr)
        else:
            print("The administrator credential could not be reset.", file=sys.stderr)
        return 2
    record_event("auth.password_reset", actor=actor)
    print("Administrator password reset. All existing sessions were revoked.")
    return 0


def disable_mfa(
    *,
    input_reader: Callable[[str], str] = input,
    effective_user_id: int | None = None,
) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    if input_reader("Type DISABLE MFA to continue: ") != "DISABLE MFA":
        print("MFA recovery cancelled.", file=sys.stderr)
        return 2
    with sqlite3.connect(core.DB) as connection:
        users = connection.execute("SELECT id,username FROM users ORDER BY id").fetchall()
    if len(users) != 1:
        print("Exactly one local administrator is required.", file=sys.stderr)
        return 2
    disable_administrator_mfa(users[0][0])
    actor = {"id": users[0][0], "username": users[0][1]}
    record_event("auth.mfa_disabled_locally", actor=actor)
    print("MFA disabled. All existing sessions were revoked.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exitlane-cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "reset-password", help="reset the local administrator password interactively"
    )
    subcommands.add_parser("disable-mfa", help="disable MFA locally and revoke every session")
    arguments = parser.parse_args(argv)
    if arguments.command == "reset-password":
        core.init()
        return reset_password()
    if arguments.command == "disable-mfa":
        core.init()
        return disable_mfa()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
