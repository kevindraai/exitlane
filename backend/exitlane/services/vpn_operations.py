from __future__ import annotations

from collections import deque
from datetime import UTC, datetime, timedelta

ACTIVE_STATES = frozenset({"connecting", "disconnecting", "recovering", "measuring"})
CONNECT_TIMEOUT_SECONDS = 40
STATUS_TIMEOUT_SECONDS = 6
RECOVERY_WINDOW = timedelta(minutes=10)
RECOVERY_LIMIT = 2

_operation = {
    "state": "idle",
    "requested_country_code": None,
    "action_started_at": None,
    "action_deadline_at": None,
    "last_error_code": None,
}
_recoveries: deque[datetime] = deque()


class VPNActionInProgress(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def snapshot() -> dict:
    return dict(_operation)


def begin(state: str, *, country_code: str | None = None, timeout: int = 45) -> dict:
    if _operation["state"] in ACTIVE_STATES:
        raise VPNActionInProgress(_operation["state"])
    now = _now()
    _operation.update(
        state=state,
        requested_country_code=country_code,
        action_started_at=now.isoformat(),
        action_deadline_at=(now + timedelta(seconds=timeout)).isoformat(),
        last_error_code=None,
    )
    return snapshot()


def transition(state: str) -> dict:
    _operation["state"] = state
    return snapshot()


def finish(*, connected: bool, error_code: str | None = None) -> dict:
    _operation.update(
        state="connected" if connected else "failed" if error_code else "idle",
        requested_country_code=None,
        action_started_at=None,
        action_deadline_at=None,
        last_error_code=error_code,
    )
    return snapshot()


def recovery_allowed(now: datetime | None = None) -> bool:
    current = now or _now()
    cutoff = current - RECOVERY_WINDOW
    while _recoveries and _recoveries[0] < cutoff:
        _recoveries.popleft()
    return len(_recoveries) < RECOVERY_LIMIT


def record_recovery(now: datetime | None = None) -> None:
    _recoveries.append(now or _now())


def reset_for_tests() -> None:
    _operation.update(
        state="idle",
        requested_country_code=None,
        action_started_at=None,
        action_deadline_at=None,
        last_error_code=None,
    )
    _recoveries.clear()
