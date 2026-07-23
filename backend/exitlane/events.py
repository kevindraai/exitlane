from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field

from exitlane import core
from exitlane.config import EVENT_RETENTION_MAX_COUNT, EVENT_RETENTION_MAX_DAYS

logger = logging.getLogger(__name__)
Level = Literal["info", "warning", "error"]

EVENT_DEFINITIONS = {
    "system.started": ("system", "info", set()),
    "setup.completed": ("setup", "info", set()),
    "auth.login_succeeded": ("auth", "info", set()),
    "auth.login_failed": ("auth", "warning", {"reason"}),
    "auth.logout": ("auth", "info", set()),
    "auth.session_expired": ("auth", "info", set()),
    "auth.session_revoked": ("auth", "warning", set()),
    "auth.password_changed": ("auth", "info", set()),
    "auth.password_reset": ("auth", "warning", set()),
    "auth.mfa_enrollment_started": ("auth", "info", set()),
    "auth.mfa_enabled": ("auth", "info", set()),
    "auth.mfa_disabled": ("auth", "warning", set()),
    "auth.mfa_disabled_locally": ("auth", "warning", set()),
    "auth.recovery_codes_generated": ("auth", "info", set()),
    "auth.recovery_codes_regenerated": ("auth", "warning", set()),
    "auth.recovery_code_used": ("auth", "warning", set()),
    "auth.other_sessions_revoked": ("auth", "warning", set()),
    "settings.updated": ("settings", "info", {"fields"}),
    "network.security_settings_updated": (
        "settings",
        "warning",
        {"fields", "public_scheme", "trusted_proxy_count"},
    ),
    "network.security_settings_reset_locally": ("settings", "warning", set()),
    "provider.connect_started": ("provider", "info", {"target", "country_code", "cli_action"}),
    "provider.connected": ("provider", "info", {"country", "city", "server", "country_code", "cli_action", "exit_code"}),
    "provider.connect_failed": ("provider", "error", {"target", "reason", "country_code", "cli_action", "exit_code"}),
    "provider.recovery_started": ("provider", "warning", {"country_code", "reason"}),
    "provider.recovered": ("provider", "info", {"country_code"}),
    "provider.recovery_failed": ("provider", "error", {"country_code", "reason"}),
    "provider.recovery_rate_limited": ("provider", "error", {"country_code", "reason"}),
    "provider.retry_started": ("provider", "info", {"country_code"}),
    "provider.disconnect_started": ("provider", "info", set()),
    "provider.disconnected": ("provider", "info", set()),
    "provider.disconnect_failed": ("provider", "error", {"reason"}),
    "provider.session_started": ("provider", "info", {"provider"}),
    "provider.session_ended": ("provider", "warning", {"provider"}),
    "provider.session_end_failed": ("provider", "error", {"provider", "reason"}),
    "wireguard.configuration_generated": ("wireguard", "info", {"client_name"}),
    "wireguard.configuration_regenerated": ("wireguard", "warning", {"client_name"}),
    "wireguard.interface_active": ("wireguard", "info", {"interface"}),
    "wireguard.interface_inactive": ("wireguard", "warning", {"interface"}),
    "wireguard.handshake_received": ("wireguard", "info", {"client_name"}),
    "notifications.webhook_added": ("notifications", "info", {"name"}),
}
FILTER_CATEGORIES = frozenset(value[0] for value in EVENT_DEFINITIONS.values())
FILTER_LEVELS = frozenset({"info", "warning", "error"})
SAFE_REASONS = frozenset({"invalid_credentials", "timeout", "healthcheck_failed", "provider_unavailable", "provider_status_unavailable", "connection_failed", "not_connected", "wrong_country", "invalid_target", "unknown", "already_signed_out", "daemon_unavailable", "command_unavailable", "provider_error"})
MAX_STRING = 160
MAX_METADATA_BYTES = 2048


class EventActor(BaseModel):
    username: str


class EventItem(BaseModel):
    id: int
    created_at: str
    level: Literal["info", "warning", "error"]
    category: str
    code: str
    actor: EventActor | None = None
    metadata: dict[str, object] = Field(default_factory=dict)
    correlation_id: str | None = None


class EventPage(BaseModel):
    items: list[EventItem]
    next_cursor: int | None
    has_more: bool


def _safe_string(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Event metadata strings must be strings")
    return value.strip()[:MAX_STRING]


def validate_metadata(code: str, metadata: dict[str, object] | None) -> dict[str, object]:
    if code not in EVENT_DEFINITIONS:
        raise ValueError("Unknown event code")
    value = metadata or {}
    if not isinstance(value, dict) or set(value) - EVENT_DEFINITIONS[code][2]:
        raise ValueError("Event metadata contains unsupported fields")
    normalized: dict[str, object] = {}
    for key, item in value.items():
        if key == "fields":
            if not isinstance(item, list):
                raise ValueError("Event fields must be a list")
            normalized[key] = [_safe_string(entry) for entry in item[:20]]
        else:
            normalized[key] = _safe_string(item)
    if normalized.get("reason") not in (None, *SAFE_REASONS):
        raise ValueError("Unsupported event reason")
    if len(json.dumps(normalized, separators=(",", ":")).encode()) > MAX_METADATA_BYTES:
        raise ValueError("Event metadata is too large")
    return normalized


def cleanup_events(connection: sqlite3.Connection, *, now: datetime, max_count: int, max_days: int) -> None:
    cutoff = (now - timedelta(days=max_days)).isoformat(timespec="seconds").replace("+00:00", "Z")
    connection.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))
    connection.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)", (max_count,))


def record_event(code: str, *, actor: dict | None = None, metadata: dict[str, object] | None = None, correlation_id: str | None = None, now: datetime | None = None) -> bool:
    """Best-effort event write; audit storage never breaks the primary operation."""
    try:
        category, level, _ = EVENT_DEFINITIONS[code]
        safe_metadata = validate_metadata(code, metadata)
        current = now or datetime.now(UTC)
        timestamp = current.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        username = _safe_string(actor["username"]) if actor and actor.get("username") else None
        actor_id = actor.get("id") if actor else None
        correlation = _safe_string(correlation_id) if correlation_id else None
        with sqlite3.connect(core.DB, timeout=5.0) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO events(created_at, level, category, code, actor_user_id,
                   actor_username, metadata_json, correlation_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (timestamp, level, category, code, actor_id, username, json.dumps(safe_metadata), correlation),
            )
            cleanup_events(connection, now=current, max_count=EVENT_RETENTION_MAX_COUNT, max_days=EVENT_RETENTION_MAX_DAYS)
        return True
    except (KeyError, TypeError, ValueError, sqlite3.Error):
        logger.warning("Could not store application event %s", code, exc_info=True)
        return False


def list_events(*, limit: int = 50, cursor: int | None = None, category: str | None = None, level: str | None = None, code: str | None = None) -> EventPage:
    clauses: list[str] = []
    parameters: list[object] = []
    if cursor is not None:
        clauses.append("id < ?")
        parameters.append(cursor)
    for column, value in (("category", category), ("level", level), ("code", code)):
        if value is not None:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    try:
        with sqlite3.connect(core.DB) as connection:
            query = f"""SELECT id, created_at, level, category, code, actor_username,
                    metadata_json, correlation_id FROM events{where}
                    ORDER BY id DESC LIMIT ?"""  # nosec B608
            # `where` contains only fixed column/operator fragments above; every value is bound.
            rows = connection.execute(
                query,
                (*parameters, limit + 1),
            ).fetchall()
    except sqlite3.Error as error:
        raise RuntimeError("Events are temporarily unavailable") from error
    has_more = len(rows) > limit
    rows = rows[:limit]
    items = []
    for row in rows:
        try:
            metadata = validate_metadata(row[4], json.loads(row[6]))
        except (json.JSONDecodeError, TypeError, ValueError):
            metadata = {}
        items.append(EventItem(id=row[0], created_at=row[1], level=row[2], category=row[3], code=row[4], actor=EventActor(username=row[5]) if row[5] else None, metadata=metadata, correlation_id=row[7]))
    return EventPage(items=items, next_cursor=items[-1].id if has_more and items else None, has_more=has_more)
