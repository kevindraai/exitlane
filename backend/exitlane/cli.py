from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path

from exitlane import core, lifecycle
from exitlane.events import record_event
from exitlane.providers.nordvpn import provider
from exitlane.services import killswitch, network_security
from exitlane.services.auth_security import disable_mfa as disable_administrator_mfa
from exitlane.services.credentials import CredentialError, reset_administrator_password
from exitlane.services.network_security import (
    ENVIRONMENT_KEYS,
    NetworkSecurityError,
    current_config,
    reset_database_config,
    update_config,
)


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
            print(
                "The supplied value does not meet the configured credential policy.",
                file=sys.stderr,
            )
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
    proxies = ", ".join(str(proxy) for proxy in configuration.trusted_proxies) or "(none)"
    output = (
        "\n".join(
            [
                f"Public URL: {public_url} [source: {configuration.sources['public_url']}]",
                (
                    f"Trusted proxies: {proxies} "
                    f"[source: {configuration.sources['trusted_proxies']}]"
                ),
                (
                    f"Secure-cookie policy: {configuration.secure_cookie_policy} "
                    f"[source: {configuration.sources['secure_cookie_policy']}]"
                ),
            ]
        )
        + "\n"
    ).encode()
    while output:
        output = output[os.write(sys.stdout.fileno(), output) :]
    return 0


COOKIE_POLICY_ALIASES = {
    "auto": "auto",
    "automatic": "auto",
    "always": "always",
    "enabled": "always",
    "never": "never",
    "disabled": "never",
}


def set_proxy_config(
    *,
    public_url: str | None = None,
    trusted_proxies: list[str] | None = None,
    secure_cookie_policy: str | None = None,
    confirm_broad_trust: bool = False,
    effective_user_id: int | None = None,
) -> int:
    if (os.geteuid() if effective_user_id is None else effective_user_id) != 0:
        print("This command must be run as root or with sudo.", file=sys.stderr)
        return 77
    supplied = {
        field
        for field, value in {
            "public_url": public_url,
            "trusted_proxies": trusted_proxies,
            "secure_cookie_policy": secure_cookie_policy,
        }.items()
        if value is not None
    }
    if not supplied:
        print("Specify at least one proxy setting.", file=sys.stderr)
        return 2
    current = current_config()
    policy = (
        COOKIE_POLICY_ALIASES.get(secure_cookie_policy.casefold())
        if secure_cookie_policy is not None
        else current.secure_cookie_policy
    )
    if policy is None:
        print("Secure cookies must be automatic, enabled, or disabled.", file=sys.stderr)
        return 2
    effective_public_url = current.public_url if "public_url" in current.overrides else public_url
    effective_trusted_proxies = (
        [str(proxy) for proxy in current.trusted_proxies]
        if "trusted_proxies" in current.overrides
        else trusted_proxies
    )
    effective_policy = (
        current.secure_cookie_policy if "secure_cookie_policy" in current.overrides else policy
    )
    try:
        updated, changed = update_config(
            public_url=(
                current.public_url if effective_public_url is None else effective_public_url
            ),
            trusted_proxies=(
                [str(proxy) for proxy in current.trusted_proxies]
                if effective_trusted_proxies is None
                else effective_trusted_proxies
            ),
            secure_cookie_policy=effective_policy,
            confirm_broad_trust=confirm_broad_trust,
            fields=supplied,
        )
    except NetworkSecurityError as error:
        suffix = f" on line {error.line}" if error.line is not None else ""
        print(f"Proxy configuration rejected: {error.code}{suffix}.", file=sys.stderr)
        return 2
    except core.SettingsStorageError:
        print("Proxy configuration could not be stored.", file=sys.stderr)
        return 1
    ignored = supplied & current.overrides
    for field in sorted(ignored):
        print(
            f"{field} is controlled by {ENVIRONMENT_KEYS[field]}; "
            "the database value was not changed.",
            file=sys.stderr,
        )
    if changed:
        record_event(
            "network.security_settings_updated",
            metadata=network_security.settings_updated_event_metadata(updated, changed),
        )
    if supplied == ignored:
        print("No database settings changed; environment overrides remain effective.")
    else:
        print("Proxy configuration updated. Changes are active immediately.")
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
    print("Stored proxy settings removed. All sessions were revoked.")
    if current_config().overrides:
        print(
            "Environment overrides remain active and must be changed outside ExitLane; "
            "restart the service after changing them.",
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


def _read_backup_passphrase(
    secret_file: str | None,
    *,
    password_reader: Callable[[str], str] = getpass.getpass,
    confirmation: bool = False,
) -> str:
    if secret_file:
        path = Path(secret_file)
        details = path.lstat()
        if details.st_mode & 0o077 or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise lifecycle.LifecycleError("unsafe_passphrase_file")
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    else:
        value = password_reader("Backup passphrase: ")
        if confirmation and value != password_reader("Repeat backup passphrase: "):
            raise lifecycle.LifecycleError("passphrase_mismatch")
    if len(value) < 12:
        raise lifecycle.LifecycleError("passphrase_too_short")
    return value


def _systemd_service_action(action: str) -> None:
    subprocess.run(
        ["/usr/bin/systemctl", action, "exitlane.service"],
        check=True,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
    )


def _local_health_check() -> bool:
    url = f"http://127.0.0.1:{os.getenv('EXITLANE_PORT', '8787')}/api/health"
    for _attempt in range(15):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except (OSError, urllib.error.URLError):
            time.sleep(1)
    return False


def backup_command(arguments: argparse.Namespace) -> int:
    try:
        passphrase = _read_backup_passphrase(
            arguments.passphrase_file, confirmation=arguments.backup_command == "create"
        )
        source = Path(arguments.path)
        if arguments.backup_command == "create":
            core.init()
            info = lifecycle.create_backup(source, passphrase)
            print(f"Encrypted backup created: {source}")
        elif arguments.backup_command in {"inspect", "verify"}:
            info = lifecycle.inspect_backup(source, passphrase)
            if arguments.backup_command == "verify":
                print("Backup authentication, manifest, checksums, and database verified.")
        else:
            confirmation = input("Type RESTORE EXITLANE to continue: ")
            info = lifecycle.restore_backup(
                source,
                passphrase,
                confirmation=confirmation,
                service_action=_systemd_service_action,
                health_check=_local_health_check,
            )
            print("Backup restored. Existing sessions were revoked.")
        print(f"Backup ID: {info.backup_id}")
        print(f"Created: {info.created_at}")
        print(f"ExitLane version: {info.exitlane_version}")
        print(f"Database schema: {info.database_schema_version}")
        print(f"Files: {len(info.files)}")
        return 0
    except lifecycle.LifecycleError as error:
        print(f"Backup operation failed: {error.code}.", file=sys.stderr)
        return 2
    except (OSError, subprocess.SubprocessError):
        print("Backup operation failed: local_operation_failed.", file=sys.stderr)
        return 1


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
    proxy_parser = subcommands.add_parser(
        "proxy", help="manage effective reverse-proxy configuration"
    )
    proxy_commands = proxy_parser.add_subparsers(dest="proxy_command", required=True)
    proxy_commands.add_parser("status", help="show effective values and their sources")
    proxy_set = proxy_commands.add_parser("set", help="store one or more proxy settings")
    proxy_set.add_argument("--public-url")
    proxy_set.add_argument("--trusted-proxy", action="append", dest="trusted_proxies")
    proxy_set.add_argument(
        "--secure-cookies",
        choices=tuple(COOKIE_POLICY_ALIASES),
    )
    proxy_set.add_argument("--confirm-broad-trust", action="store_true")
    proxy_commands.add_parser("clear-public-url", help="use the direct request context")
    proxy_commands.add_parser("clear-trusted-proxies", help="trust no reverse proxy")
    proxy_commands.add_parser("reset", help="remove all stored proxy settings")
    subcommands.add_parser("killswitch-status", help="show the ExitLane killswitch status")
    subcommands.add_parser("disable-killswitch", help="remove only the ExitLane killswitch rules")
    subcommands.add_parser("restore-killswitch", help=argparse.SUPPRESS)
    backup_parser = subcommands.add_parser("backup", help="create, inspect, verify, or restore")
    backup_commands = backup_parser.add_subparsers(dest="backup_command", required=True)
    for backup_action in ("create", "inspect", "verify", "restore"):
        action_parser = backup_commands.add_parser(backup_action)
        action_parser.add_argument("path")
        action_parser.add_argument(
            "--passphrase-file",
            help="read the passphrase from a root-only file instead of the terminal",
        )
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
    if arguments.command == "proxy":
        core.init()
        if arguments.proxy_command == "status":
            return network_status()
        if arguments.proxy_command == "set":
            return set_proxy_config(
                public_url=arguments.public_url,
                trusted_proxies=arguments.trusted_proxies,
                secure_cookie_policy=arguments.secure_cookies,
                confirm_broad_trust=arguments.confirm_broad_trust,
            )
        if arguments.proxy_command == "clear-public-url":
            return set_proxy_config(public_url="")
        if arguments.proxy_command == "clear-trusted-proxies":
            return set_proxy_config(trusted_proxies=[])
        if arguments.proxy_command == "reset":
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
    if arguments.command == "backup":
        return backup_command(arguments)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
