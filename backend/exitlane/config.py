from __future__ import annotations

import os
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit


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

# The appliance UI must be reachable from its management VLAN by default. Deployment
# guidance requires a firewall; operators can narrow this with EXITLANE_HOST.
WEB_HOST = os.getenv("EXITLANE_HOST", "0.0.0.0")  # nosec B104
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
SESSION_IDLE_TIMEOUT_SECONDS = environment_int("EXITLANE_SESSION_IDLE_TIMEOUT", 3600)
SESSION_COOKIE_POLICY = os.getenv("EXITLANE_SECURE_COOKIES", "auto").strip().lower()
# Backwards-compatible opt-in: the old boolean can only strengthen the new policy.
if environment_bool("EXITLANE_SESSION_COOKIE_SECURE", False):
    SESSION_COOKIE_POLICY = "always"
MAX_REQUEST_BODY_BYTES = environment_int("EXITLANE_MAX_REQUEST_BODY_BYTES", 1_048_576)
PUBLIC_URL = os.getenv("EXITLANE_PUBLIC_URL", "").strip()
TRUSTED_PROXY_VALUES = tuple(
    item.strip() for item in os.getenv("EXITLANE_TRUSTED_PROXIES", "").split(",") if item.strip()
)
TRUSTED_PROXIES = tuple(ipaddress.ip_network(item, strict=False) for item in TRUSTED_PROXY_VALUES)

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

    if SESSION_MAX_AGE_SECONDS < 60 or SESSION_IDLE_TIMEOUT_SECONDS < 60:
        raise RuntimeError("EXITLANE_SESSION_MAX_AGE must be at least 60 seconds")
    if SESSION_IDLE_TIMEOUT_SECONDS > SESSION_MAX_AGE_SECONDS:
        raise RuntimeError("EXITLANE_SESSION_IDLE_TIMEOUT cannot exceed the absolute session age")
    if SESSION_COOKIE_POLICY not in {"auto", "always", "never"}:
        raise RuntimeError("EXITLANE_SECURE_COOKIES must be auto, always, or never")
    if PUBLIC_URL:
        parsed = urlsplit(PUBLIC_URL)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError(
                "EXITLANE_PUBLIC_URL must be an http(s) origin without credentials or path"
            )

    if not 1024 <= MAX_REQUEST_BODY_BYTES <= 16 * 1024 * 1024:
        raise RuntimeError("EXITLANE_MAX_REQUEST_BODY_BYTES must be between 1024 and 16777216")
