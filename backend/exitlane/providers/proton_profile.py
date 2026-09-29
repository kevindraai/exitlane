"""Strict parser for administrator supplied Proton WireGuard profiles."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .wireguard_keys import _public_key_for_private, _valid_wireguard_key

MAX_PROFILE_BYTES = 16_384
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
KEYS = {
    "Interface": frozenset({"Address", "PrivateKey", "DNS", "MTU"}),
    "Peer": frozenset(
        {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
    ),
}


class ProtonProfileError(ValueError):
    def __init__(self, code: str = "invalid_proton_profile"):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProtonProfile:
    address: str
    private_key: str
    dns_address: str
    peer_public_key: str
    endpoint_host: str
    endpoint_port: int
    mtu: int
    preshared_key: str | None = None


def _addresses(value: str, *, kind: str) -> tuple[str, ...]:
    tokens = tuple(item.strip() for item in value.split(","))
    if not tokens or len(tokens) > 2 or not all(tokens):
        raise ProtonProfileError()
    parsed = []
    for token in tokens:
        try:
            address = ipaddress.ip_interface(token) if kind == "interface" else ipaddress.ip_address(token)
        except ValueError as error:
            raise ProtonProfileError() from error
        if (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
            or address.is_link_local
        ):
            raise ProtonProfileError()
        parsed.append(address)
    if len({item.version for item in parsed}) != len(parsed):
        raise ProtonProfileError()
    return tuple(str(item) for item in parsed)


def parse_profile(content: str) -> ProtonProfile:
    if not isinstance(content, str) or len(content) > MAX_PROFILE_BYTES:
        raise ProtonProfileError()
    try:
        encoded = content.encode("utf-8")
    except UnicodeError as error:
        raise ProtonProfileError() from error
    if len(encoded) > MAX_PROFILE_BYTES:
        raise ProtonProfileError()
    if not content.isascii() or "\x00" in content:
        raise ProtonProfileError()
    sections: dict[str, dict[str, str]] = {}
    section: str | None = None
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in {"[Interface]", "[Peer]"}:
            section = line[1:-1]
            if section in sections or (section == "Peer" and "Interface" not in sections):
                raise ProtonProfileError()
            sections[section] = {}
            continue
        if section is None or "=" not in line:
            raise ProtonProfileError()
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in KEYS[section] or key in sections[section] or not value:
            raise ProtonProfileError()
        sections[section][key] = value
    if set(sections) != {"Interface", "Peer"}:
        raise ProtonProfileError()
    interface = sections["Interface"]
    peer = sections["Peer"]
    if not {"Address", "PrivateKey", "DNS"} <= interface.keys() or not {
        "PublicKey", "AllowedIPs", "Endpoint"
    } <= peer.keys():
        raise ProtonProfileError()
    addresses = _addresses(interface["Address"], kind="interface")
    v4 = [item for item in addresses if ipaddress.ip_interface(item).version == 4]
    if len(v4) != 1 or ipaddress.ip_interface(v4[0]).network.prefixlen != 32:
        raise ProtonProfileError()
    if any(
        ipaddress.ip_interface(item).network.prefixlen != 128
        for item in addresses
        if ipaddress.ip_interface(item).version == 6
    ):
        raise ProtonProfileError()
    dns = _addresses(interface["DNS"], kind="dns")
    dns_v4 = [item for item in dns if ipaddress.ip_address(item).version == 4]
    if len(dns_v4) != 1:
        raise ProtonProfileError()
    private = _valid_wireguard_key(interface["PrivateKey"])
    public = _valid_wireguard_key(peer["PublicKey"])
    if private is None or _public_key_for_private(private) is None or public is None:
        raise ProtonProfileError()
    psk = peer.get("PresharedKey")
    if psk is not None and _valid_wireguard_key(psk) is None:
        raise ProtonProfileError()
    allowed_list = [item.strip() for item in peer["AllowedIPs"].split(",")]
    allowed = set(allowed_list)
    if len(allowed_list) != len(allowed):
        raise ProtonProfileError()
    if allowed not in ({"0.0.0.0/0"}, {"0.0.0.0/0", "::/0"}):
        raise ProtonProfileError()
    if peer.get("PersistentKeepalive", "25") != "25":
        raise ProtonProfileError()
    mtu_text = interface.get("MTU", "1380")
    if len(mtu_text) > 4 or not mtu_text.isascii() or not mtu_text.isdecimal():
        raise ProtonProfileError()
    mtu = int(mtu_text)
    if not 1280 <= mtu <= 1420:
        raise ProtonProfileError()
    endpoint = peer["Endpoint"].rsplit(":", 1)
    if (
        len(endpoint) != 2
        or len(endpoint[1]) > 5
        or not endpoint[1].isascii()
        or not endpoint[1].isdecimal()
    ):
        raise ProtonProfileError()
    host, port_text = endpoint
    port = int(port_text)
    if not 1 <= port <= 65535 or HOSTNAME.fullmatch(host) is None:
        raise ProtonProfileError()
    if all(character in "0123456789." for character in host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError as error:
            raise ProtonProfileError() from error
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if ip.version != 4 or not ip.is_global:
            raise ProtonProfileError()
    return ProtonProfile(v4[0], private, dns_v4[0], public, host.lower(), port, mtu, psk)
