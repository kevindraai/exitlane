from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from exitlane import core

PUBLIC_URL_KEY = "network.public_url"
TRUSTED_PROXIES_KEY = "network.trusted_proxies"
COOKIE_POLICY_KEY = "network.secure_cookie_policy"
COOKIE_POLICIES = {"auto", "always", "never"}
MAX_PUBLIC_URL_LENGTH = 2048
MAX_PROXY_ENTRIES = 64
ENVIRONMENT_KEYS = {
    "public_url": "EXITLANE_PUBLIC_URL",
    "trusted_proxies": "EXITLANE_TRUSTED_PROXIES",
    "secure_cookie_policy": "EXITLANE_SECURE_COOKIES",
}
BROAD_PRIVATE_NETWORKS = {
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
}


class NetworkSecurityError(ValueError):
    def __init__(self, code: str, *, field: str | None = None):
        super().__init__(code)
        self.code = code
        self.field = field


@dataclass(frozen=True)
class NetworkSecurityConfig:
    public_url: str
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    secure_cookie_policy: str
    overrides: frozenset[str]

    def as_public_dict(self) -> dict:
        return {
            "public_url": self.public_url,
            "trusted_proxies": [str(network) for network in self.trusted_proxies],
            "secure_cookie_policy": self.secure_cookie_policy,
            "environment_overrides": {
                field: field in self.overrides for field in ENVIRONMENT_KEYS
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
    entries = (
        [part.strip() for part in values.replace(",", "\n").splitlines()]
        if isinstance(values, str)
        else [str(part).strip() for part in values]
    )
    entries = [entry for entry in entries if entry]
    if len(entries) > MAX_PROXY_ENTRIES:
        raise NetworkSecurityError("too_many_trusted_proxies", field="trusted_proxies")
    networks = []
    for entry in entries:
        if entry == "*" or any(character in entry for character in " \\;&|$`()"):
            raise NetworkSecurityError("invalid_trusted_proxy", field="trusted_proxies")
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as error:
            raise NetworkSecurityError("invalid_trusted_proxy", field="trusted_proxies") from error
        if network.prefixlen == 0:
            raise NetworkSecurityError("proxy_range_too_broad", field="trusted_proxies")
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
    if scheme == "https" and policy == "never":
        raise NetworkSecurityError("inconsistent_cookie_policy", field="secure_cookie_policy")
    if scheme == "http" and policy == "always":
        raise NetworkSecurityError("inconsistent_cookie_policy", field="secure_cookie_policy")
    if scheme == "https" and not networks:
        raise NetworkSecurityError("trusted_proxy_required", field="trusted_proxies")
    return normalized_url, networks, policy


def current_config() -> NetworkSecurityConfig:
    overrides = frozenset(
        field for field, environment in ENVIRONMENT_KEYS.items() if environment in os.environ
    )
    public_value = (
        os.environ["EXITLANE_PUBLIC_URL"]
        if "public_url" in overrides
        else core.setting(PUBLIC_URL_KEY, "")
    )
    proxy_value = (
        os.environ["EXITLANE_TRUSTED_PROXIES"]
        if "trusted_proxies" in overrides
        else core.setting(TRUSTED_PROXIES_KEY, [])
    )
    cookie_value = (
        os.environ["EXITLANE_SECURE_COOKIES"]
        if "secure_cookie_policy" in overrides
        else core.setting(COOKIE_POLICY_KEY, "auto")
    )
    public_url = normalize_public_url(str(public_value).strip())
    proxies = parse_trusted_proxies(proxy_value)
    policy = str(cookie_value).strip().casefold()
    if policy not in COOKIE_POLICIES:
        raise NetworkSecurityError("invalid_cookie_policy", field="secure_cookie_policy")
    return NetworkSecurityConfig(public_url, proxies, policy, overrides)


def update_config(
    *,
    public_url: str,
    trusted_proxies: str | list[str],
    secure_cookie_policy: str,
    confirm_broad_trust: bool = False,
) -> tuple[NetworkSecurityConfig, list[str]]:
    current = current_config()
    supplied = {
        "public_url": public_url,
        "trusted_proxies": trusted_proxies,
        "secure_cookie_policy": secure_cookie_policy,
    }
    for field in current.overrides:
        effective = current.as_public_dict()[field]
        candidate = supplied[field]
        if field == "trusted_proxies":
            candidate = [str(network) for network in parse_trusted_proxies(candidate)]
        elif field == "public_url":
            candidate = normalize_public_url(str(candidate).strip())
        else:
            candidate = str(candidate).strip().casefold()
        if candidate != effective:
            raise NetworkSecurityError("environment_override", field=field)
    normalized, networks, policy = validate_configuration(
        public_url,
        trusted_proxies,
        secure_cookie_policy,
        confirm_broad_trust=confirm_broad_trust,
    )
    values = {
        PUBLIC_URL_KEY: normalized,
        TRUSTED_PROXIES_KEY: [str(network) for network in networks],
        COOKIE_POLICY_KEY: policy,
    }
    changed = [
        field
        for field, key in {
            "public_url": PUBLIC_URL_KEY,
            "trusted_proxies": TRUSTED_PROXIES_KEY,
            "secure_cookie_policy": COOKIE_POLICY_KEY,
        }.items()
        if core.setting(key, "" if field == "public_url" else [] if field == "trusted_proxies" else "auto")
        != values[key]
        and field not in current.overrides
    ]
    keys = {
        "public_url": PUBLIC_URL_KEY,
        "trusted_proxies": TRUSTED_PROXIES_KEY,
        "secure_cookie_policy": COOKIE_POLICY_KEY,
    }
    core.set_settings(
        {key: values[key] for field, key in keys.items() if field not in current.overrides}
    )
    return current_config(), changed


def reset_database_config() -> None:
    core.set_settings(
        {
            PUBLIC_URL_KEY: "",
            TRUSTED_PROXIES_KEY: [],
            COOKIE_POLICY_KEY: "auto",
        }
    )
