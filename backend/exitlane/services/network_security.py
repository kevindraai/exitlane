from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from exitlane import core

PUBLIC_URL_KEY = "network.public_url"
TRUSTED_PROXIES_KEY = "network.trusted_proxies"
COOKIE_POLICY_KEY = "network.secure_cookie_policy"
COOKIE_POLICIES = {"auto", "always", "never"}
CONFIGURATION_KEYS = (PUBLIC_URL_KEY, TRUSTED_PROXIES_KEY, COOKIE_POLICY_KEY)
FIELD_KEYS = {
    "public_url": PUBLIC_URL_KEY,
    "trusted_proxies": TRUSTED_PROXIES_KEY,
    "secure_cookie_policy": COOKIE_POLICY_KEY,
}
DEFAULT_VALUES = {
    "public_url": "",
    "trusted_proxies": [],
    "secure_cookie_policy": "auto",
}
MAX_PUBLIC_URL_LENGTH = 2048
MAX_PROXY_ENTRIES = 64
ENVIRONMENT_KEYS = {
    "public_url": "EXITLANE_PUBLIC_URL",
    "trusted_proxies": "EXITLANE_TRUSTED_PROXIES",
    "secure_cookie_policy": "EXITLANE_SECURE_COOKIES",
}
LEGACY_SECURE_COOKIE_ENVIRONMENT = "EXITLANE_SESSION_COOKIE_SECURE"
BROAD_PRIVATE_NETWORKS = {
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
}


class NetworkSecurityError(ValueError):
    def __init__(
        self,
        code: str,
        *,
        field: str | None = None,
        line: int | None = None,
        value: str | None = None,
    ):
        super().__init__(code)
        self.code = code
        self.field = field
        self.line = line
        self.value = value


@dataclass(frozen=True)
class NetworkSecurityConfig:
    public_url: str
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    secure_cookie_policy: str
    overrides: frozenset[str]
    sources: dict[str, Literal["environment", "database", "default"]] = dataclass_field(
        default_factory=lambda: {field: "default" for field in ENVIRONMENT_KEYS}
    )

    def as_public_dict(self) -> dict:
        return {
            "public_url": self.public_url,
            "trusted_proxies": [str(network) for network in self.trusted_proxies],
            "secure_cookie_policy": self.secure_cookie_policy,
            "environment_overrides": {field: field in self.overrides for field in ENVIRONMENT_KEYS},
            "sources": dict(self.sources),
            "restart_required": {
                field: self.sources[field] == "environment" for field in ENVIRONMENT_KEYS
            },
        }


def normalize_public_url(value: str) -> str:
    if len(value) > MAX_PUBLIC_URL_LENGTH or re.search(r"[\s\x00-\x1f\x7f]", value):
        raise NetworkSecurityError("invalid_public_url", field="public_url")
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise NetworkSecurityError("invalid_public_url", field="public_url") from error
    scheme = parsed.scheme.casefold()
    if (
        scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise NetworkSecurityError("invalid_public_url", field="public_url")
    hostname = parsed.hostname.casefold()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = 443 if scheme == "https" else 80
    netloc = hostname if port in {None, default_port} else f"{hostname}:{port}"
    return urlunsplit((scheme, netloc, "", "", ""))


def parse_trusted_proxies(
    values: str | list[str] | tuple[str, ...],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    raw_entries = (
        values.replace(",", "\n").splitlines()
        if isinstance(values, str)
        else [str(part) for part in values]
    )
    entries = [(line, entry.strip()) for line, entry in enumerate(raw_entries, start=1)]
    entries = [(line, entry) for line, entry in entries if entry]
    if len(entries) > MAX_PROXY_ENTRIES:
        raise NetworkSecurityError("too_many_trusted_proxies", field="trusted_proxies")
    networks = []
    for line, entry in entries:
        if entry == "*" or any(character in entry for character in " \\;&|$`()"):
            raise NetworkSecurityError(
                "invalid_trusted_proxy",
                field="trusted_proxies",
                line=line,
                value=entry[:128],
            )
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as error:
            raise NetworkSecurityError(
                "invalid_trusted_proxy",
                field="trusted_proxies",
                line=line,
                value=entry[:128],
            ) from error
        if network.prefixlen == 0:
            raise NetworkSecurityError(
                "proxy_range_too_broad",
                field="trusted_proxies",
                line=line,
                value=entry[:128],
            )
        networks.append(network)
    return tuple(dict.fromkeys(networks))


def validate_configuration(
    public_url: str,
    trusted_proxies: str | list[str] | tuple[str, ...],
    secure_cookie_policy: str,
    *,
    confirm_broad_trust: bool = False,
) -> tuple[str, tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...], str]:
    normalized_url = normalize_public_url(public_url.strip())
    networks = parse_trusted_proxies(trusted_proxies)
    policy = secure_cookie_policy.strip().casefold()
    if policy not in COOKIE_POLICIES:
        raise NetworkSecurityError("invalid_cookie_policy", field="secure_cookie_policy")
    broad = any(network in BROAD_PRIVATE_NETWORKS for network in networks)
    if broad and not confirm_broad_trust:
        raise NetworkSecurityError("broad_proxy_confirmation_required", field="trusted_proxies")
    scheme = urlsplit(normalized_url).scheme if normalized_url else ""
    if scheme == "https" and not networks:
        raise NetworkSecurityError("trusted_proxy_required", field="trusted_proxies")
    return normalized_url, networks, policy


def current_config() -> NetworkSecurityConfig:
    stored = core.stored_settings(CONFIGURATION_KEYS)
    override_fields = {
        field for field, environment in ENVIRONMENT_KEYS.items() if environment in os.environ
    }
    legacy_secure = os.getenv(LEGACY_SECURE_COOKIE_ENVIRONMENT, "").strip().casefold()
    if "secure_cookie_policy" not in override_fields and legacy_secure in {
        "1",
        "true",
        "yes",
        "on",
    }:
        override_fields.add("secure_cookie_policy")
    overrides = frozenset(override_fields)
    values = {}
    sources = {}
    for field, environment in ENVIRONMENT_KEYS.items():
        key = FIELD_KEYS[field]
        if field in overrides:
            values[field] = (
                "always"
                if field == "secure_cookie_policy" and environment not in os.environ
                else os.environ[environment]
            )
            sources[field] = "environment"
        elif key in stored:
            values[field] = stored[key]
            sources[field] = "database"
        else:
            values[field] = DEFAULT_VALUES[field]
            sources[field] = "default"
    public_value = values["public_url"]
    proxy_value = values["trusted_proxies"]
    cookie_value = values["secure_cookie_policy"]
    public_url = normalize_public_url(str(public_value).strip())
    proxies = parse_trusted_proxies(proxy_value)
    policy = str(cookie_value).strip().casefold()
    if policy not in COOKIE_POLICIES:
        raise NetworkSecurityError("invalid_cookie_policy", field="secure_cookie_policy")
    return NetworkSecurityConfig(public_url, proxies, policy, overrides, sources)


def validate_update(
    *,
    public_url: str,
    trusted_proxies: str | list[str],
    secure_cookie_policy: str,
    confirm_broad_trust: bool = False,
) -> NetworkSecurityConfig:
    current = current_config()
    supplied = {
        "public_url": public_url,
        "trusted_proxies": trusted_proxies,
        "secure_cookie_policy": secure_cookie_policy,
    }
    effective = current.as_public_dict()
    for field in current.overrides:
        candidate = supplied[field]
        if field == "public_url":
            candidate = normalize_public_url(str(candidate).strip())
        elif field == "trusted_proxies":
            candidate = [str(network) for network in parse_trusted_proxies(candidate)]
        else:
            candidate = str(candidate).strip().casefold()
        if candidate != effective[field]:
            raise NetworkSecurityError("environment_override", field=field)
    normalized_url, networks, policy = validate_configuration(
        str(effective["public_url"])
        if "public_url" in current.overrides
        else str(supplied["public_url"]),
        effective["trusted_proxies"]
        if "trusted_proxies" in current.overrides
        else supplied["trusted_proxies"],
        str(effective["secure_cookie_policy"])
        if "secure_cookie_policy" in current.overrides
        else str(supplied["secure_cookie_policy"]),
        confirm_broad_trust=confirm_broad_trust,
    )
    sources = {
        field: "environment" if field in current.overrides else "database"
        for field in ENVIRONMENT_KEYS
    }
    return NetworkSecurityConfig(normalized_url, networks, policy, current.overrides, sources)


def update_config(
    *,
    public_url: str,
    trusted_proxies: str | list[str],
    secure_cookie_policy: str,
    confirm_broad_trust: bool = False,
    fields: set[str] | None = None,
) -> tuple[NetworkSecurityConfig, list[str]]:
    current = current_config()
    validated = validate_update(
        public_url=public_url,
        trusted_proxies=trusted_proxies,
        secure_cookie_policy=secure_cookie_policy,
        confirm_broad_trust=confirm_broad_trust,
    )
    values = {
        PUBLIC_URL_KEY: validated.public_url,
        TRUSTED_PROXIES_KEY: [str(network) for network in validated.trusted_proxies],
        COOKIE_POLICY_KEY: validated.secure_cookie_policy,
    }
    stored = core.stored_settings(CONFIGURATION_KEYS)
    selected_fields = set(FIELD_KEYS) if fields is None else fields & set(FIELD_KEYS)
    changed = [
        field
        for field, key in FIELD_KEYS.items()
        if field in selected_fields
        and stored.get(key, DEFAULT_VALUES[field]) != values[key]
        and field not in current.overrides
    ]
    values_to_store = {
        key: values[key]
        for field, key in FIELD_KEYS.items()
        if field in selected_fields and field not in current.overrides
    }
    if values_to_store:
        core.set_settings(values_to_store)
    return current_config(), changed


def reset_database_config() -> None:
    core.delete_settings(CONFIGURATION_KEYS)
