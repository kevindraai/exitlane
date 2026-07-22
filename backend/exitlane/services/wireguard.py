from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Awaitable, Callable

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


class WireGuardConfigurationError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _restore(path: Path, content: str | None) -> None:
    if content is None:
        path.unlink(missing_ok=True)
    else:
        _atomic_write(path, content)


def _value(configuration: str, key: str, *, section: str) -> str | None:
    current = ""
    for raw_line in configuration.splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
        elif current == section and "=" in line:
            name, value = line.split("=", 1)
            if name.strip() == key:
                return value.strip()
    return None


async def _public_key(private_key: str) -> str:
    rc, public_key, _error = await command(
        "wg", "pubkey", input_text=private_key + "\n", timeout=5
    )
    if rc != 0 or not public_key.strip():
        raise WireGuardConfigurationError("wireguard_configuration_invalid")
    return public_key.strip()


async def read_current(interface: str, client: str) -> dict | None:
    server_path = WG_DIR / f"{interface}.conf"
    client_path = WG_DIR / f"{client}.conf"
    if not server_path.exists() and not client_path.exists():
        return None
    try:
        server_config = server_path.read_text(encoding="utf-8")
        client_config = client_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise WireGuardConfigurationError("wireguard_configuration_invalid") from error

    server_private = _value(server_config, "PrivateKey", section="Interface")
    client_private = _value(client_config, "PrivateKey", section="Interface")
    server_peer = _value(server_config, "PublicKey", section="Peer")
    client_peer = _value(client_config, "PublicKey", section="Peer")
    if not all((server_private, client_private, server_peer, client_peer)):
        raise WireGuardConfigurationError("wireguard_configuration_invalid")
    if await _public_key(server_private) != client_peer:
        raise WireGuardConfigurationError("wireguard_configuration_invalid")
    if await _public_key(client_private) != server_peer:
        raise WireGuardConfigurationError("wireguard_configuration_invalid")
    return {
        "client_name": client,
        "filename": "exitlane-wireguard.conf",
        "client_config": client_config,
    }


async def parameters_from_current(interface: str, client: str) -> dict:
    current = await read_current(interface, client)
    if current is None:
        raise WireGuardConfigurationError("wireguard_configuration_missing")
    try:
        server_config = (WG_DIR / f"{interface}.conf").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise WireGuardConfigurationError("wireguard_configuration_invalid") from error
    client_config = current["client_config"]
    endpoint_value = _value(client_config, "Endpoint", section="Peer") or ""
    endpoint, separator, port_value = endpoint_value.rpartition(":")
    server_address = _value(server_config, "Address", section="Interface")
    dns = _value(client_config, "DNS", section="Interface")
    allowed_ips = _value(client_config, "AllowedIPs", section="Peer")
    keepalive = _value(client_config, "PersistentKeepalive", section="Peer")
    vpn_match = re.search(r"^PostUp\s*=.*\s-o\s+([A-Za-z0-9_.-]{1,15})\s", server_config, re.MULTILINE)
    try:
        subnet = str(ipaddress.ip_interface(server_address or "").network)
        port = int(port_value)
        keepalive_value = int(keepalive or DEFAULT_WIREGUARD_KEEPALIVE)
    except (ValueError, TypeError) as error:
        raise WireGuardConfigurationError("wireguard_configuration_invalid") from error
    if not separator or not endpoint or not dns or not allowed_ips:
        raise WireGuardConfigurationError("wireguard_configuration_invalid")
    return {
        "endpoint": endpoint,
        "subnet": subnet,
        "dns": dns,
        "port": port,
        "interface": interface,
        "client": client,
        "vpn_interface": vpn_match.group(1) if vpn_match else DEFAULT_WIREGUARD_VPN_INTERFACE,
        "allowed_ips": allowed_ips,
        "keepalive": keepalive_value,
    }


async def keypair() -> tuple[str, str]:
    rc, private, error = await command(
        "wg",
        "genkey",
        timeout=10,
    )

    if rc != 0:
        raise RuntimeError(error or "WireGuard private key generation failed")

    rc, public, error = await command(
        "wg",
        "pubkey",
        input_text=private + "\n",
        timeout=10,
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

    _atomic_write(server_path, server_config)
    _atomic_write(client_path, client_config)

    return {
        "interface": interface,
        "server_public_key": server_public_key,
        "client_public_key": client_public_key,
        "client_config": client_config,
        "client_name": client,
    }


async def provision(
    *,
    activate: Callable[[str], Awaitable[None]],
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
    paths = (WG_DIR / f"{interface}.conf", WG_DIR / f"{client}.conf")
    previous: dict[Path, str | None] = {}
    for path in paths:
        try:
            previous[path] = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            previous[path] = None
        except (OSError, UnicodeError) as error:
            raise WireGuardConfigurationError("wireguard_configuration_invalid") from error

    try:
        result = await create(
            endpoint=endpoint,
            subnet=subnet,
            dns=dns,
            port=port,
            interface=interface,
            client=client,
            vpn_interface=vpn_interface,
            allowed_ips=allowed_ips,
            keepalive=keepalive,
        )
        await activate(interface)
        return result
    except (ValueError, WireGuardConfigurationError):
        for path, content in previous.items():
            _restore(path, content)
        raise
    except Exception as error:
        for path, content in previous.items():
            with suppress(OSError):
                _restore(path, content)
        if all(content is not None for content in previous.values()):
            with suppress(Exception):
                await activate(interface)
        raise WireGuardConfigurationError("wireguard_reload_failed") from error
