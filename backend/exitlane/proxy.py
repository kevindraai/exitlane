from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import Request

from exitlane.config import PUBLIC_URL, SESSION_COOKIE_POLICY, TRUSTED_PROXIES

MAX_FORWARD_HEADER_LENGTH = 4096
MAX_PROXY_HOPS = 16


@dataclass(frozen=True)
class RequestSecurity:
    client_ip: str
    scheme: str
    direct_peer_trusted: bool
    reverse_proxy: bool
    forwarded_ignored: bool

    @property
    def secure_cookie(self) -> bool:
        return SESSION_COOKIE_POLICY == "always" or (
            SESSION_COOKIE_POLICY == "auto" and self.scheme == "https"
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


def _trusted(address: ipaddress._BaseAddress) -> bool:
    return any(address in network for network in TRUSTED_PROXIES)


def request_security(request: Request) -> RequestSecurity:
    peer_text = request.client.host if request.client else str(ipaddress.IPv4Address(0))
    try:
        peer = _address(peer_text)
    except ValueError:
        peer = ipaddress.IPv4Address(0)
    trusted_peer = _trusted(peer)
    forwarding_present = any(
        name in request.headers
        for name in ("forwarded", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host")
    )
    if not trusted_peer:
        return RequestSecurity(str(peer), request.url.scheme, False, False, forwarding_present)

    # ExitLane's explicit contract uses X-Forwarded-* and ignores RFC Forwarded when both exist.
    raw_for = request.headers.get("x-forwarded-for", "")
    raw_proto = request.headers.get("x-forwarded-proto", "")
    client = peer
    reverse_proxy = False
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
                    if not _trusted(candidate):
                        break
    scheme = request.url.scheme
    if raw_proto and len(raw_proto) <= 32:
        protos = [part.strip().lower() for part in raw_proto.split(",")]
        if protos and all(proto in {"http", "https"} for proto in protos):
            scheme = protos[0]
            reverse_proxy = True
    return RequestSecurity(str(client), scheme, True, reverse_proxy, False)


def trusted_origin(request: Request, security: RequestSecurity) -> str:
    if PUBLIC_URL:
        parsed = urlsplit(PUBLIC_URL)
        return f"{parsed.scheme}://{parsed.netloc}".casefold()
    host = request.headers.get("host", "")
    if not host or any(character in host for character in "\r\n/\\"):
        return ""
    return f"{security.scheme}://{host}".casefold()


def deployment_status(request: Request) -> dict:
    state = request_security(request)
    warnings = []
    if state.scheme != "https":
        warnings.append("direct_http")
    if state.forwarded_ignored:
        warnings.append("forwarded_headers_ignored")
    if PUBLIC_URL and urlsplit(PUBLIC_URL).scheme != state.scheme:
        warnings.append("public_url_mismatch")
    if SESSION_COOKIE_POLICY == "never" and state.scheme == "https":
        warnings.append("secure_cookie_disabled")
    return {
        "https": state.scheme == "https",
        "reverse_proxy": state.reverse_proxy,
        "direct_peer_trusted": state.direct_peer_trusted,
        "secure_cookie": state.secure_cookie,
        "public_url": PUBLIC_URL or None,
        "trusted_proxies": list(str(network) for network in TRUSTED_PROXIES),
        "warnings": warnings,
    }
