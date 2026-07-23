from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sqlite3
import sys
from collections.abc import Callable, Sequence

from exitlane import core
from exitlane.events import record_event
from exitlane.services.credentials import CredentialError, reset_administrator_password
from exitlane.services.auth_security import disable_mfa as disable_administrator_mfa
from exitlane.services.network_security import current_config, reset_database_config
from exitlane.services import killswitch
from exitlane.providers.nordvpn import provider


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


def network_status(*, effective_user_id: int | None = None) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    configuration = current_config()
    public_url = configuration.public_url or "(direct access)"
    print(f"Public URL: {public_url}")
    print(f"Trusted proxies: {len(configuration.trusted_proxies)}")
    print(f"Secure-cookie policy: {configuration.secure_cookie_policy}")
    if configuration.overrides:
        print(f"Environment overrides: {', '.join(sorted(configuration.overrides))}")
    return 0


def reset_network_security(
    *,
    input_reader: Callable[[str], str] = input,
    effective_user_id: int | None = None,
) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    phrase = "RESET NETWORK SECURITY"
    if input_reader(f"Type {phrase} to continue: ") != phrase:
        print("Network security recovery cancelled.", file=sys.stderr)
        return 2
    reset_database_config()
    with sqlite3.connect(core.DB) as connection:
        connection.execute("DELETE FROM sessions")
    record_event("network.security_settings_reset_locally")
    print("Network security reset to direct-access defaults. All sessions were revoked.")
    if current_config().overrides:
        print(
            "Environment overrides remain active and must be changed outside ExitLane.",
            file=sys.stderr,
        )
    return 0


def killswitch_status(*, effective_user_id: int | None = None) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    try:
        facts = asyncio.run(provider.network_facts())
        current = asyncio.run(killswitch.status(facts))
    except killswitch.KillswitchError as error:
        print(f"Killswitch status unavailable: {error.code}", file=sys.stderr)
        return 1
    print(f"State: {current.state}")
    print(f"Configured: {'yes' if current.configured else 'no'}")
    print(f"Effective: {'yes' if current.effective else 'no'}")
    print(f"Tunnel available: {'yes' if current.tunnel_available else 'no'}")
    print(f"Firewall rules installed: {'yes' if current.firewall_rules_installed else 'no'}")
    print(f"Reason: {current.reason}")
    return 0 if current.effective or not current.configured else 1


def disable_killswitch(
    *,
    input_reader: Callable[[str], str] = input,
    effective_user_id: int | None = None,
) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    phrase = "DISABLE EXITLANE KILLSWITCH"
    if input_reader(f"Type {phrase} to continue: ") != phrase:
        print("Killswitch recovery cancelled.", file=sys.stderr)
        return 2
    try:
        asyncio.run(killswitch.disable())
    except killswitch.KillswitchError as error:
        print(f"Killswitch could not be disabled: {error.code}", file=sys.stderr)
        return 1
    with sqlite3.connect(core.DB) as connection:
        connection.execute("DELETE FROM sessions")
    record_event("network.killswitch_disabled_locally")
    print("ExitLane killswitch disabled. All sessions were revoked.")
    return 0


def restore_killswitch(*, effective_user_id: int | None = None) -> int:
    """Boot-only idempotent restore; configured gateways are closed before networking."""
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        return 77
    if not core.setting(killswitch.SETTING_CONFIGURED, False):
        return 0
    try:
        # Deliberately start closed. The backend reconciles with live provider facts
        # after startup; provider control traffic is host output and remains allowed.
        asyncio.run(killswitch.reconcile(killswitch.TunnelFacts(False)))
    except killswitch.KillswitchError:
        record_event("network.killswitch_error", metadata={"reason": "firewall_apply_failed"})
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="exitlane-cli")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "reset-password", help="reset the local administrator password interactively"
    )
    subcommands.add_parser("disable-mfa", help="disable MFA locally and revoke every session")
    subcommands.add_parser("network-status", help="show effective network security settings")
    subcommands.add_parser(
        "reset-network-security",
        help="reset database network security settings and revoke every session",
    )
    subcommands.add_parser("killswitch-status", help="show the ExitLane killswitch status")
    subcommands.add_parser(
        "disable-killswitch", help="remove only the ExitLane killswitch rules"
    )
    subcommands.add_parser("restore-killswitch", help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    if arguments.command == "reset-password":
        core.init()
        return reset_password()
    if arguments.command == "disable-mfa":
        core.init()
        return disable_mfa()
    if arguments.command == "network-status":
        core.init()
        return network_status()
    if arguments.command == "reset-network-security":
        core.init()
        return reset_network_security()
    if arguments.command == "killswitch-status":
        core.init()
        return killswitch_status()
    if arguments.command == "disable-killswitch":
        core.init()
        return disable_killswitch()
    if arguments.command == "restore-killswitch":
        core.init()
        return restore_killswitch()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
