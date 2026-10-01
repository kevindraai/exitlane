"""Root-only supervisor recovery client; never writes application state directly."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
import warnings

from exitlane.container_control import ControlError, UnixControlClient
from exitlane.container_service import BACKUP_NAME


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(prog="exitlane-container-control")
    parser.add_argument("command", choices=("status", "backup", "restore"))
    parser.add_argument("--name", help="A backup basename in the durable backup directory")
    parser.add_argument("--confirm", choices=("RESTORE EXITLANE",))
    parser.add_argument(
        "--passphrase-stdin",
        action="store_true",
        help="Read one bounded passphrase line from stdin",
    )
    return parser.parse_args(argv)


def read_passphrase(stdin_mode):
    if stdin_mode:
        raw = sys.stdin.readline(1026)
        if len(raw) > 1025 or not raw.endswith("\n"):
            raise ControlError("control_invalid_request")
        value = raw[:-1]
    else:
        if not sys.stdin.isatty():
            raise ControlError("control_invalid_request")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                value = getpass.getpass("Backup passphrase: ")
            except getpass.GetPassWarning:
                raise ControlError("control_invalid_request") from None
    if not 12 <= len(value) <= 1024:
        raise ControlError("control_invalid_request")
    return value


async def execute(arguments, *, client=None):
    client = client or UnixControlClient()
    if arguments.command == "status":
        if arguments.name or arguments.confirm or arguments.passphrase_stdin:
            raise ControlError("control_invalid_request")
        return await client.request("status")
    if arguments.command == "restore":
        if (
            not arguments.name
            or BACKUP_NAME.fullmatch(arguments.name) is None
            or arguments.confirm != "RESTORE EXITLANE"
        ):
            raise ControlError("control_invalid_request")
    elif arguments.name or arguments.confirm:
        raise ControlError("control_invalid_request")
    passphrase = read_passphrase(arguments.passphrase_stdin)
    payload = {"passphrase": passphrase}
    if arguments.command == "restore":
        payload.update(name=arguments.name, confirmation=arguments.confirm)
    try:
        result = await client.request(arguments.command, payload)
        if result.get("ok") is False or result.get("restored") is False:
            raise ControlError("control_operation_failed")
        return result
    finally:
        passphrase = None
        payload.clear()


def main(argv=None):
    try:
        result = asyncio.run(execute(parse_arguments(argv)))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ControlError, OSError, ValueError, EOFError, KeyboardInterrupt):
        print("container_control_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
