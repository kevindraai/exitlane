from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import available_timezones

from exitlane.core import command

TIMEDATECTL = "/usr/bin/timedatectl"
VALID_TIMEZONES = frozenset(available_timezones() - {"Factory", "localtime"})

CommandRunner = Callable[..., Awaitable[tuple[int, str, str]]]
TimezoneReader = Callable[[], str | None]


class TimezoneOperationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TimezoneChange:
    previous: str
    current: str
    changed: bool


def read_system_timezone(
    timezone_file: Path = Path("/etc/timezone"),
    localtime_file: Path = Path("/etc/localtime"),
) -> str | None:
    """Read the Debian system timezone without treating an unreadable host as UTC."""
    try:
        candidate = timezone_file.read_text(encoding="utf-8").strip()
    except OSError:
        candidate = ""
    if candidate in VALID_TIMEZONES:
        return candidate

    try:
        localtime = localtime_file.resolve(strict=True)
        marker = "zoneinfo/"
        candidate = str(localtime).split(marker, 1)[1]
    except (OSError, IndexError):
        candidate = ""
    if candidate in VALID_TIMEZONES:
        return candidate

    local_timezone = datetime.now().astimezone().tzinfo
    candidate = getattr(local_timezone, "key", "")
    return candidate if candidate in VALID_TIMEZONES else None


async def set_system_timezone(
    timezone: str,
    *,
    command_runner: CommandRunner = command,
    timezone_reader: TimezoneReader = read_system_timezone,
) -> TimezoneChange:
    """Apply one validated IANA timezone through Debian's fixed native interface."""
    if timezone not in VALID_TIMEZONES:
        raise TimezoneOperationError("invalid_timezone")

    previous = timezone_reader()
    if previous is None:
        raise TimezoneOperationError("system_timezone_unreadable")
    if previous == timezone:
        return TimezoneChange(previous=previous, current=timezone, changed=False)

    try:
        return_code, _output, _error = await command_runner(
            TIMEDATECTL,
            "set-timezone",
            timezone,
            timeout=30,
        )
    except OSError as error:
        raise TimezoneOperationError("system_timezone_change_failed") from error
    if return_code != 0:
        raise TimezoneOperationError("system_timezone_change_failed")

    confirmed = timezone_reader()
    if confirmed != timezone:
        raise TimezoneOperationError("system_timezone_verification_failed")
    return TimezoneChange(previous=previous, current=confirmed, changed=True)
