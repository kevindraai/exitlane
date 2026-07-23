from __future__ import annotations

import json
import platform
import socket
from datetime import datetime
from pathlib import Path
from zoneinfo import available_timezones

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from exitlane import __version__
from exitlane.config import APP_NAME, PROVIDER_REFRESH_INTERVAL_SECONDS, SESSION_MAX_AGE_SECONDS
from exitlane.core import set_settings, setting

TIMEZONE_KEY = "timezone"
POLLING_INTERVAL_KEY = "provider_refresh_interval_seconds"
REPOSITORY_URL = "https://github.com/kevindraai/exitlane"
VALID_TIMEZONES = frozenset(available_timezones() - {"Factory", "localtime"})


def system_hostname() -> str:
    return socket.gethostname() or "Exitlane"


def system_timezone(
    timezone_file: Path = Path("/etc/timezone"),
    localtime_file: Path = Path("/etc/localtime"),
) -> str:
    try:
        candidate = timezone_file.read_text(encoding="utf-8").strip()
    except OSError:
        candidate = ""
    if candidate in VALID_TIMEZONES:
        return candidate

    try:
        localtime = localtime_file.resolve()
        marker = "zoneinfo/"
        candidate = str(localtime).split(marker, 1)[1]
    except (OSError, IndexError):
        candidate = ""
    if candidate in VALID_TIMEZONES:
        return candidate

    local_timezone = datetime.now().astimezone().tzinfo
    candidate = getattr(local_timezone, "key", "")
    return candidate if candidate in VALID_TIMEZONES else "UTC"


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
    def require_change(self) -> "GeneralSettingsUpdate":
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
            "restart_required": ["general.timezone"],
        },
        "timezones": sorted(VALID_TIMEZONES),
        "languages": ["en", "nl"],
    }


def update_settings(update: SettingsUpdate) -> dict:
    current = current_general_settings().model_dump()
    changes = update.general.model_dump(exclude_unset=True)
    validated = GeneralSettings(**(current | changes))
    keys = {
        "timezone": TIMEZONE_KEY,
        "provider_refresh_interval_seconds": POLLING_INTERVAL_KEY,
    }
    set_settings({keys[field]: getattr(validated, field) for field in changes})
    return settings_response()
