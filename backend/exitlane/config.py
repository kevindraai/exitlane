from __future__ import annotations

import os
from pathlib import Path


def environment_int(name: str, default: int) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        return int(value)
    except ValueError as error:
        raise RuntimeError(f"Environment variable {name} must contain an integer") from error


def environment_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"Environment variable {name} must contain a boolean")


APP_NAME = "Exitlane"

WEB_HOST = os.getenv("EXITLANE_HOST", "0.0.0.0")
WEB_PORT = environment_int("EXITLANE_PORT", 8787)

CONFIG_DIR = Path(os.getenv("EXITLANE_CONFIG_DIR", "/etc/exitlane"))
DATA_DIR = Path(os.getenv("EXITLANE_DATA_DIR", "/var/lib/exitlane"))
LOG_DIR = Path(os.getenv("EXITLANE_LOG_DIR", "/var/log/exitlane"))

MIN_PASSWORD_LENGTH = environment_int(
    "EXITLANE_MIN_PASSWORD_LENGTH",
    8,
)
MAX_PASSWORD_LENGTH = environment_int(
    "EXITLANE_MAX_PASSWORD_LENGTH",
    256,
)
SESSION_MAX_AGE_SECONDS = environment_int("EXITLANE_SESSION_MAX_AGE", 86400)
SESSION_COOKIE_SECURE = environment_bool("EXITLANE_SESSION_COOKIE_SECURE", False)

DEFAULT_WIREGUARD_INTERFACE = os.getenv(
    "EXITLANE_WIREGUARD_INTERFACE",
    "wg0",
)
DEFAULT_WIREGUARD_SUBNET = os.getenv(
    "EXITLANE_WIREGUARD_SUBNET",
    "10.99.99.0/24",
)

DEFAULT_WIREGUARD_DNS = os.getenv(
    "EXITLANE_WIREGUARD_DNS",
    "1.1.1.1",
)

DEFAULT_WIREGUARD_PORT = environment_int(
    "EXITLANE_WIREGUARD_PORT",
    51820,
)
DEFAULT_WIREGUARD_CLIENT = os.getenv(
    "EXITLANE_WIREGUARD_CLIENT",
    "router",
)

PROVIDER_REFRESH_INTERVAL_SECONDS = environment_int(
    "EXITLANE_PROVIDER_REFRESH_INTERVAL",
    5,
)
EVENT_RETENTION_MAX_COUNT = environment_int("EXITLANE_EVENT_RETENTION_MAX_COUNT", 5000)
EVENT_RETENTION_MAX_DAYS = environment_int("EXITLANE_EVENT_RETENTION_MAX_DAYS", 90)

DEFAULT_WIREGUARD_VPN_INTERFACE = os.getenv(
    "EXITLANE_WIREGUARD_VPN_INTERFACE",
    "nordlynx",
)
DEFAULT_WIREGUARD_ALLOWED_IPS = os.getenv(
    "EXITLANE_WIREGUARD_ALLOWED_IPS",
    "0.0.0.0/0",
)
DEFAULT_WIREGUARD_KEEPALIVE = environment_int(
    "EXITLANE_WIREGUARD_KEEPALIVE",
    25,
)


def validate_config() -> None:
    if EVENT_RETENTION_MAX_COUNT < 1 or EVENT_RETENTION_MAX_DAYS < 1:
        raise RuntimeError("Event retention limits must be positive")

    if not 6 <= MIN_PASSWORD_LENGTH <= MAX_PASSWORD_LENGTH:
        raise RuntimeError(
            "EXITLANE_MIN_PASSWORD_LENGTH must be between 6 and EXITLANE_MAX_PASSWORD_LENGTH"
        )

    if not 1 <= WEB_PORT <= 65535:
        raise RuntimeError("EXITLANE_PORT must be between 1 and 65535")

    if not 1 <= DEFAULT_WIREGUARD_PORT <= 65535:
        raise RuntimeError("EXITLANE_WIREGUARD_PORT must be between 1 and 65535")

    if SESSION_MAX_AGE_SECONDS < 60:
        raise RuntimeError("EXITLANE_SESSION_MAX_AGE must be at least 60 seconds")
