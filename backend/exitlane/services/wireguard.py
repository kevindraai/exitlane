from __future__ import annotations

import ipaddress
import os
import re

from exitlane.config import (
    DEFAULT_WIREGUARD_ALLOWED_IPS,
    DEFAULT_WIREGUARD_CLIENT,
    DEFAULT_WIREGUARD_DNS,
    DEFAULT_WIREGUARD_INTERFACE,
    DEFAULT_WIREGUARD_KEEPALIVE,
    DEFAULT_WIREGUARD_PORT,
    DEFAULT_WIREGUARD_SUBNET,
    DEFAULT_WIREGUARD_VPN_INTERFACE,
)
from exitlane.core import WG_DIR, command


async def keypair() -> tuple[str, str]:
    rc, private, error = await command(
        "wg",
        "genkey",
    )

    if rc != 0:
        raise RuntimeError(error or "WireGuard private key generation failed")

    rc, public, error = await command(
        "wg",
        "pubkey",
        input_text=private + "\n",
    )

    if rc != 0:
        raise RuntimeError(error or "WireGuard public key generation failed")

    return private.strip(), public.strip()


async def create(
    endpoint: str,
    subnet: str = DEFAULT_WIREGUARD_SUBNET,
    dns: str = DEFAULT_WIREGUARD_DNS,
    port: int = DEFAULT_WIREGUARD_PORT,
    interface: str = DEFAULT_WIREGUARD_INTERFACE,
    client: str = DEFAULT_WIREGUARD_CLIENT,
    vpn_interface: str = DEFAULT_WIREGUARD_VPN_INTERFACE,
    allowed_ips: str = DEFAULT_WIREGUARD_ALLOWED_IPS,
    keepalive: int = DEFAULT_WIREGUARD_KEEPALIVE,
) -> dict:
    try:
        network = ipaddress.ip_network(
            subnet,
            strict=True,
        )
    except ValueError as error:
        raise ValueError("Het WireGuard-tunnelnetwerk is ongeldig.") from error

    hosts = list(network.hosts())

    if network.version != 4 or len(hosts) < 2:
        raise ValueError("Het WireGuard-tunnelnetwerk moet minimaal twee IPv4-adressen bevatten.")

    if not re.fullmatch(
        r"[A-Za-z0-9-]{1,15}",
        interface,
    ):
        raise ValueError("De WireGuard-interfacenaam is ongeldig.")

    if not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}",
        client,
    ):
        raise ValueError("De WireGuard-clientnaam is ongeldig.")

    if not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,15}",
        vpn_interface,
    ):
        raise ValueError("De VPN-interfacenaam is ongeldig.")

    try:
        ipaddress.ip_address(dns)
    except ValueError as error:
        raise ValueError("De DNS-server moet een geldig IP-adres zijn.") from error

    if not 1 <= port <= 65535:
        raise ValueError("De WireGuard-poort moet tussen 1 en 65535 liggen.")

    if not 0 <= keepalive <= 65535:
        raise ValueError("De WireGuard keepalive-waarde is ongeldig.")

    server_private_key, server_public_key = await keypair()
    client_private_key, client_public_key = await keypair()

    server_address = f"{hosts[0]}/{network.prefixlen}"
    client_address = f"{hosts[1]}/32"

    server_config = f"""[Interface]
Address = {server_address}
ListenPort = {port}
PrivateKey = {server_private_key}
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i {interface} -o {vpn_interface} -j ACCEPT
PostUp = iptables -A FORWARD -i {vpn_interface} -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o {vpn_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i {interface} -o {vpn_interface} -j ACCEPT
PostDown = iptables -D FORWARD -i {vpn_interface} -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {vpn_interface} -j MASQUERADE

[Peer]
PublicKey = {client_public_key}
AllowedIPs = {client_address}
PersistentKeepalive = {keepalive}
"""

    client_config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_address}
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
Endpoint = {endpoint}:{port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = {keepalive}
"""

    WG_DIR.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o700,
    )

    server_path = WG_DIR / f"{interface}.conf"
    client_path = WG_DIR / f"{client}.conf"

    server_path.write_text(
        server_config,
        encoding="utf-8",
    )
    client_path.write_text(
        client_config,
        encoding="utf-8",
    )

    os.chmod(
        server_path,
        0o600,
    )
    os.chmod(
        client_path,
        0o600,
    )

    return {
        "interface": interface,
        "server_public_key": server_public_key,
        "client_public_key": client_public_key,
        "client_config": client_config,
        "client_name": client,
    }
