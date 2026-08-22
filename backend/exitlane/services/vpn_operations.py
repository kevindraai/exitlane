from __future__ import annotations

from collections import deque
from datetime import UTC, datetime, timedelta

DEFAULT_CONNECTION_ID = "provider:nordvpn"
ACTIVE_STATES = frozenset({"connecting", "disconnecting", "recovering"})
CONNECT_TIMEOUT_SECONDS = 40
STATUS_TIMEOUT_SECONDS = 6
RECOVERY_WINDOW = timedelta(minutes=10)
RECOVERY_LIMIT = 2


class VPNActionInProgress(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


def _new_connection(connection_id: str) -> dict:
    kind, _separator, identity = connection_id.partition(":")
    return {
        "connection_id": connection_id,
        "kind": kind or "provider",
        "provider_id": (identity or None) if kind == "provider" else None,
        "interface": None,
        "state": "idle",
        "requested_country_code": None,
        "action_started_at": None,
        "action_deadline_at": None,
        "last_error_code": None,
        "selection": {
            "state": "idle",
            "country_code": None,
            "server": None,
            "generation": 0,
        },
    }


_connections: dict[str, dict] = {DEFAULT_CONNECTION_ID: _new_connection(DEFAULT_CONNECTION_ID)}
_recoveries: dict[str, deque[datetime]] = {}


def _connection(connection_id: str = DEFAULT_CONNECTION_ID) -> dict:
    return _connections.setdefault(connection_id, _new_connection(connection_id))


def snapshot(connection_id: str = DEFAULT_CONNECTION_ID) -> dict:
    current = _connection(connection_id)
    return {**current, "selection": dict(current["selection"])}


def snapshots() -> list[dict]:
    return [snapshot(connection_id) for connection_id in sorted(_connections)]


def begin(
    state: str,
    *,
    country_code: str | None = None,
    timeout: int = 45,
    connection_id: str = DEFAULT_CONNECTION_ID,
) -> dict:
    current = _connection(connection_id)
    if current["state"] in ACTIVE_STATES:
        raise VPNActionInProgress(current["state"])
    now = _now()
    current.update(
        state=state,
        requested_country_code=country_code,
        action_started_at=now.isoformat(),
        action_deadline_at=(now + timedelta(seconds=timeout)).isoformat(),
        last_error_code=None,
    )
    return snapshot(connection_id)


def transition(state: str, *, connection_id: str = DEFAULT_CONNECTION_ID) -> dict:
    _connection(connection_id)["state"] = state
    return snapshot(connection_id)


def set_interface(interface: str | None, *, connection_id: str = DEFAULT_CONNECTION_ID) -> dict:
    _connection(connection_id)["interface"] = interface
    return snapshot(connection_id)


def begin_selection(country_code: str, *, connection_id: str = DEFAULT_CONNECTION_ID) -> int:
    selection = _connection(connection_id)["selection"]
    generation = int(selection["generation"]) + 1
    selection.update(
        state="selecting",
        country_code=country_code.upper(),
        server=None,
        generation=generation,
    )
    return generation


def finish_selection(
    generation: int,
    *,
    server: str | None,
    fallback: bool = False,
    connection_id: str = DEFAULT_CONNECTION_ID,
) -> bool:
    selection = _connection(connection_id)["selection"]
    if selection["generation"] != generation:
        return False
    selection.update(state="fallback" if fallback else "selected", server=server)
    return True


def finish(
    *,
    connected: bool,
    error_code: str | None = None,
    connection_id: str = DEFAULT_CONNECTION_ID,
) -> dict:
    _connection(connection_id).update(
        state="connected" if connected else "failed" if error_code else "idle",
        requested_country_code=None,
        action_started_at=None,
        action_deadline_at=None,
        last_error_code=error_code,
    )
    return snapshot(connection_id)


def recovery_allowed(
    now: datetime | None = None, *, connection_id: str = DEFAULT_CONNECTION_ID
) -> bool:
    current = now or _now()
    cutoff = current - RECOVERY_WINDOW
    recoveries = _recoveries.setdefault(connection_id, deque())
    while recoveries and recoveries[0] < cutoff:
        recoveries.popleft()
    return len(recoveries) < RECOVERY_LIMIT


def record_recovery(
    now: datetime | None = None, *, connection_id: str = DEFAULT_CONNECTION_ID
) -> None:
    _recoveries.setdefault(connection_id, deque()).append(now or _now())


def reset_for_tests() -> None:
    _connections.clear()
    _connections[DEFAULT_CONNECTION_ID] = _new_connection(DEFAULT_CONNECTION_ID)
    _recoveries.clear()
