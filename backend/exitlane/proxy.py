from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import Request

from exitlane.config import PUBLIC_URL, SESSION_COOKIE_POLICY, TRUSTED_PROXIES
from exitlane.services.network_security import NetworkSecurityConfig, current_config

_INITIAL_PUBLIC_URL = PUBLIC_URL
_INITIAL_TRUSTED_PROXIES = TRUSTED_PROXIES
_INITIAL_COOKIE_POLICY = SESSION_COOKIE_POLICY

MAX_FORWARD_HEADER_LENGTH = 4096
MAX_PROXY_HOPS = 16


@dataclass(frozen=True)
class RequestSecurity:
    client_ip: str
    scheme: str
    direct_peer_trusted: bool
    reverse_proxy: bool
    forwarded_ignored: bool
    forwarded_rejected: bool = False
    cookie_policy: str = "auto"

    @property
    def secure_cookie(self) -> bool:
        return self.cookie_policy == "always" or (
            self.cookie_policy == "auto" and self.scheme == "https"
        )


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValueError("malformed IPv6 address")
        value = value[1:end]
    elif value.count(":") == 1 and "." in value:
        value = value.rsplit(":", 1)[0]
    return ipaddress.ip_address(value)


def _configuration() -> NetworkSecurityConfig:
    configured = current_config()
    # Preserve the documented test/integration seams exported by this module.
    public_url = PUBLIC_URL if PUBLIC_URL != _INITIAL_PUBLIC_URL else configured.public_url
    proxies = (
        TRUSTED_PROXIES
        if TRUSTED_PROXIES != _INITIAL_TRUSTED_PROXIES
        else configured.trusted_proxies
    )
    cookie_policy = (
        SESSION_COOKIE_POLICY
        if SESSION_COOKIE_POLICY != _INITIAL_COOKIE_POLICY
        else configured.secure_cookie_policy
    )
    return NetworkSecurityConfig(public_url, tuple(proxies), cookie_policy, configured.overrides)


def _trusted(
    address: ipaddress._BaseAddress,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(address in network for network in networks)


def request_security(request: Request) -> RequestSecurity:
    configuration = _configuration()
    peer_text = request.client.host if request.client else str(ipaddress.IPv4Address(0))
    try:
        peer = _address(peer_text)
    except ValueError:
        peer = ipaddress.IPv4Address(0)
    trusted_peer = _trusted(peer, configuration.trusted_proxies)
    forwarding_present = any(
        name in request.headers
        for name in ("forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host")
    )
    if not trusted_peer:
        return RequestSecurity(
            str(peer),
            request.url.scheme,
            False,
            False,
            forwarding_present,
            cookie_policy=configuration.secure_cookie_policy,
        )

    # ExitLane's explicit contract uses X-Forwarded-* and ignores RFC Forwarded when both exist.
    raw_for = request.headers.get("x-forwarded-for", "")
    raw_proto = request.headers.get("x-forwarded-proto", "")
    client = peer
    reverse_proxy = False
    forwarded_rejected = False
    if raw_for and len(raw_for) <= MAX_FORWARD_HEADER_LENGTH:
        parts = [part.strip() for part in raw_for.split(",")]
        if 0 < len(parts) <= MAX_PROXY_HOPS:
            try:
                chain = [_address(part) for part in parts]
            except ValueError:
                chain = []
            if chain:
                reverse_proxy = True
                for candidate in reversed(chain):
                    client = candidate
                    if not _trusted(candidate, configuration.trusted_proxies):
                        break
            else:
                forwarded_rejected = True
        else:
            forwarded_rejected = True
    scheme = request.url.scheme
    if raw_proto and len(raw_proto) <= 32:
        protos = [part.strip().lower() for part in raw_proto.split(",")]
        if protos and len(set(protos)) == 1 and protos[0] in {"http", "https"}:
            scheme = protos[0]
            reverse_proxy = True
        else:
            forwarded_rejected = True
    elif raw_proto:
        forwarded_rejected = True
    return RequestSecurity(
        str(client),
        scheme,
        True,
        reverse_proxy,
        forwarded_rejected,
        forwarded_rejected,
        configuration.secure_cookie_policy,
    )


def normalized_origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    scheme = parsed.scheme.casefold()
    effective_port = port or (443 if scheme == "https" else 80)
    return scheme, parsed.hostname.casefold(), effective_port


def trusted_origin(request: Request, security: RequestSecurity) -> str:
    public_url = _configuration().public_url
    if public_url:
        parsed = urlsplit(public_url)
        return f"{parsed.scheme}://{parsed.netloc}".casefold()
    host = request.headers.get("host", "")
    if not host or any(character in host for character in "\r\n/\\"):
        return ""
    return f"{security.scheme}://{host}".casefold()


def deployment_status(request: Request) -> dict:
    configuration = _configuration()
    state = request_security(request)
    warnings = []
    if state.scheme != "https":
        warnings.append("direct_http")
    if state.forwarded_ignored:
        warnings.append("forwarded_headers_ignored")
    if configuration.public_url and urlsplit(configuration.public_url).scheme != state.scheme:
        warnings.append("public_url_mismatch")
    if configuration.secure_cookie_policy == "never" and state.scheme == "https":
        warnings.append("secure_cookie_disabled")
    return {
        "https": state.scheme == "https",
        "reverse_proxy": state.reverse_proxy,
        "direct_peer_trusted": state.direct_peer_trusted,
        "secure_cookie": state.secure_cookie,
        "direct_peer": (request.client.host if request.client else str(ipaddress.IPv4Address(0))),
        "public_url": configuration.public_url or None,
        "trusted_proxies": list(str(network) for network in configuration.trusted_proxies),
        "secure_cookie_policy": configuration.secure_cookie_policy,
        "configuration": configuration.as_public_dict(),
        "warnings": warnings,
    }
