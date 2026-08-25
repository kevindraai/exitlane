from __future__ import annotations

import json
import platform
import socket

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from exitlane import __version__
from exitlane.config import APP_NAME, PROVIDER_REFRESH_INTERVAL_SECONDS, SESSION_MAX_AGE_SECONDS
from exitlane.core import SettingsStorageError, set_settings, setting
from exitlane.services import timezone as timezone_service

TIMEZONE_KEY = "timezone"
POLLING_INTERVAL_KEY = "provider_refresh_interval_seconds"
REPOSITORY_URL = "https://github.com/kevindraai/exitlane"
VALID_TIMEZONES = timezone_service.VALID_TIMEZONES


class TimezoneUpdatePersistenceError(RuntimeError):
    def __init__(self, *, rollback_performed: bool) -> None:
        super().__init__("settings_storage_failed")
        self.rollback_performed = rollback_performed


def system_hostname() -> str:
    return socket.gethostname() or "Exitlane"


def system_timezone() -> str:
    return timezone_service.read_system_timezone() or "UTC"


def timezone_consistency() -> dict[str, object]:
    actual = timezone_service.read_system_timezone()
    try:
        configured = setting(TIMEZONE_KEY, None)
    except (json.JSONDecodeError, TypeError, ValueError):
        configured = None
        stored_invalid = True
    else:
        stored_invalid = configured is not None and configured not in VALID_TIMEZONES

    if stored_invalid:
        return {
            "configured": True,
            "consistent": False,
            "error": "invalid_stored_timezone",
        }
    if actual is None:
        return {
            "configured": configured is not None,
            "consistent": False,
            "error": "system_timezone_unreadable",
        }
    return {
        "configured": configured is not None,
        "consistent": configured is None or configured == actual,
        "error": None if configured is None or configured == actual else "timezone_mismatch",
    }


class GeneralSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timezone: str = Field(min_length=1, max_length=128)
    provider_refresh_interval_seconds: int = Field(ge=2, le=300, strict=True)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str) -> str:
        if value not in VALID_TIMEZONES:
            raise ValueError("Timezone must be a valid IANA timezone")
        return value


class GeneralSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timezone: str | None = Field(default=None, min_length=1, max_length=128)
    provider_refresh_interval_seconds: int | None = Field(default=None, ge=2, le=300, strict=True)

    @field_validator("timezone")
    @classmethod
    def validate_timezone(cls, value: str | None) -> str:
        if value is None or value not in VALID_TIMEZONES:
            raise ValueError("Timezone must be a valid IANA timezone")
        return value

    @field_validator("provider_refresh_interval_seconds")
    @classmethod
    def validate_polling_interval(cls, value: int | None) -> int:
        if value is None:
            raise ValueError("Polling interval must not be null")
        return value

    @model_validator(mode="after")
    def require_change(self) -> GeneralSettingsUpdate:
        if not self.model_fields_set:
            raise ValueError("At least one general setting is required")
        return self


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    general: GeneralSettingsUpdate


def safe_setting(key: str, default: object) -> object:
    try:
        return setting(key, default)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


def validated_stored_value(key: str, default: object, field: str) -> object:
    values = {
        "timezone": system_timezone(),
        "provider_refresh_interval_seconds": PROVIDER_REFRESH_INTERVAL_SECONDS,
    }
    values[field] = safe_setting(key, default)
    try:
        return getattr(GeneralSettings(**values), field)
    except ValidationError:
        return default


def current_general_settings() -> GeneralSettings:
    return GeneralSettings(
        timezone=validated_stored_value(TIMEZONE_KEY, system_timezone(), "timezone"),
        provider_refresh_interval_seconds=validated_stored_value(
            POLLING_INTERVAL_KEY,
            PROVIDER_REFRESH_INTERVAL_SECONDS,
            "provider_refresh_interval_seconds",
        ),
    )


def settings_response() -> dict:
    hostname = system_hostname()
    release_channel = (
        "alpha"
        if "a" in __version__
        else "beta"
        if "b" in __version__
        else "release candidate"
        if "rc" in __version__
        else "stable"
    )
    return {
        "general": current_general_settings().model_dump(),
        "system": {
            "hostname": hostname,
            "system_timezone": system_timezone(),
            "timezone_consistency": timezone_consistency(),
            "session_duration_seconds": SESSION_MAX_AGE_SECONDS,
        },
        "about": {
            "product": APP_NAME,
            "version": __version__,
            "release_channel": release_channel,
            "runtime_environment": "Python / FastAPI",
            "python_version": platform.python_version(),
            "platform": platform.system(),
            "setup_complete": bool(safe_setting("setup_complete", False)),
            "repository_url": REPOSITORY_URL,
            "license": "GPL-3.0",
        },
        "metadata": {
            "runtime_editable": [
                "general.timezone",
                "general.provider_refresh_interval_seconds",
            ],
            "environment_only": ["system.session_duration_seconds"],
            "restart_required": [],
        },
        "timezones": sorted(VALID_TIMEZONES),
        "languages": ["en", "nl"],
    }


async def update_settings(update: SettingsUpdate) -> dict:
    current = current_general_settings().model_dump()
    changes = update.general.model_dump(exclude_unset=True)
    validated = GeneralSettings(**(current | changes))
    keys = {
        "timezone": TIMEZONE_KEY,
        "provider_refresh_interval_seconds": POLLING_INTERVAL_KEY,
    }
    timezone_change = None
    if "timezone" in changes:
        timezone_change = await timezone_service.set_system_timezone(validated.timezone)
    try:
        set_settings({keys[field]: getattr(validated, field) for field in changes})
    except SettingsStorageError:
        if "timezone" not in changes:
            raise
        rollback_performed = bool(timezone_change and timezone_change.changed)
        if rollback_performed:
            try:
                await timezone_service.set_system_timezone(timezone_change.previous)
            except timezone_service.TimezoneOperationError as error:
                raise timezone_service.TimezoneOperationError(
                    "system_timezone_rollback_failed"
                ) from error
        raise TimezoneUpdatePersistenceError(rollback_performed=rollback_performed) from None
    return settings_response()


async def reconcile_timezone() -> timezone_service.TimezoneChange | None:
    status = timezone_consistency()
    if not status["configured"]:
        return None
    if status["consistent"]:
        return None
    if status["error"] != "timezone_mismatch":
        raise timezone_service.TimezoneOperationError(str(status["error"]))
    configured = validated_stored_value(TIMEZONE_KEY, None, "timezone")
    if not isinstance(configured, str):
        raise timezone_service.TimezoneOperationError("invalid_stored_timezone")
    return await timezone_service.set_system_timezone(configured)
