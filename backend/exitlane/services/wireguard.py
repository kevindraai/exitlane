from __future__ import annotations
import ipaddress
import os
import re
from exitlane.core import WG_DIR, command


async def keypair():
    rc, private, err = await command("wg", "genkey")
    if rc:
        raise RuntimeError(err)
    rc, public, err = await command("wg", "pubkey", input_text=private + "\n")
    if rc:
        raise RuntimeError(err)
    return private.strip(), public.strip()


async def create(
    endpoint,
    subnet="10.99.99.0/24",
    port=51820,
    interface="wg0",
    client="router",
    vpn_interface="nordlynx",
):
    network = ipaddress.ip_network(subnet, strict=True)
    hosts = list(network.hosts())
    if network.version != 4 or len(hosts) < 2:
        raise ValueError("invalid subnet")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,15}", interface):
        raise ValueError("invalid interface")
    spubpriv = await keypair()
    cpubpriv = await keypair()
    spriv, spub = spubpriv
    cpriv, cpub = cpubpriv
    server = f"""[Interface]
Address = {hosts[0]}/{network.prefixlen}
ListenPort = {port}
PrivateKey = {spriv}
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i {interface} -o {vpn_interface} -j ACCEPT
PostUp = iptables -A FORWARD -i {vpn_interface} -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o {vpn_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i {interface} -o {vpn_interface} -j ACCEPT
PostDown = iptables -D FORWARD -i {vpn_interface} -o {interface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {vpn_interface} -j MASQUERADE

[Peer]
PublicKey = {cpub}
AllowedIPs = {hosts[1]}/32
PersistentKeepalive = 25
"""
    client_cfg = f"""[Interface]
PrivateKey = {cpriv}
Address = {hosts[1]}/32

[Peer]
PublicKey = {spub}
Endpoint = {endpoint}:{port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    WG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    (WG_DIR / f"{interface}.conf").write_text(server)
    (WG_DIR / f"{client}.conf").write_text(client_cfg)
    os.chmod(WG_DIR / f"{interface}.conf", 0o600)
    os.chmod(WG_DIR / f"{client}.conf", 0o600)
    return {
        "interface": interface,
        "server_public_key": spub,
        "client_public_key": cpub,
        "client_config": client_cfg,
        "client_name": client,
    }
