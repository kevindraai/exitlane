#!/usr/bin/env python3
"""Real kernel multi-peer ingress against an isolated synthetic Proton egress.

Run as root on a disposable native test appliance with installed ExitLane.
No commercial credentials, host routes/firewall changes or external destinations.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def run(*argv, input=None, ok=True):
    result = subprocess.run(argv, input=input, text=True, capture_output=True, timeout=45,
                            check=False)
    if ok and result.returncode:
        raise RuntimeError("qualification_command_failed:" + argv[0])
    return result


def ns(namespace, *argv, **kwargs):
    return run("ip", "netns", "exec", namespace, *argv, **kwargs)


def private(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)


def install_client(namespace, text, endpoint, directory):
    config = directory / (namespace + ".conf")
    private(config, re.sub(r"(?m)^Endpoint = .*", "Endpoint = " + endpoint, text))
    ns(namespace, "ip", "link", "delete", "wg-client", ok=False)
    ns(namespace, "ip", "link", "add", "wg-client", "type", "wireguard")
    stripped = run("wg-quick", "strip", str(config)).stdout
    ns(namespace, "wg", "setconf", "wg-client", "/dev/stdin", input=stripped)
    address = re.search(r"(?m)^Address = (.+)$", text).group(1)
    ns(namespace, "ip", "address", "add", address, "dev", "wg-client")
    ns(namespace, "ip", "link", "set", "wg-client", "up")
    ns(namespace, "ip", "route", "replace", "1.1.1.1/32", "dev", "wg-client")


def ping(namespace, *, blocked=False):
    result = ns(namespace, "ping", "-n", "-c", "3", "-i", "0.2", "-W", "1", "1.1.1.1", ok=False)
    assert (result.returncode != 0) if blocked else (result.returncode == 0), "packet_expectation_failed"
    if not blocked:
        assert " 0% packet loss" in result.stdout, "packet_loss"


def paired(a, b, *, blocked=False):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(ping, name, blocked=blocked) for name in (a, b)]
        for result in results:
            result.result()


async def qualify(directory, a, b, remote):
    from exitlane import cli, core
    from exitlane.providers.proton import Proton
    from exitlane.providers.wireguard_keys import _wireguard_keypair
    from exitlane.runtime import runtime
    from exitlane.services import auth_security, wireguard, wireguard_peers

    core.init()
    auth_security.ensure_master_key()
    core.set_setting("wireguard_interface", "wg0")
    core.set_setting("wireguard_subnet", "10.98.240.0/29")
    core.set_setting("wireguard_client_name", "UniFi-Gateway")

    async def activate(interface):
        run("wg-quick", "up", str(core.WG_DIR / (interface + ".conf")))

    async def sync(interface):
        await runtime.sync_ingress(interface, source_directory=core.WG_DIR, runner=core.command)

    initial = await wireguard.provision(activate=activate, endpoint="10.99.1.1", subnet="10.98.240.0/29", interface="wg0", client="UniFi-Gateway")
    server_before = (core.WG_DIR / "wg0.conf").read_bytes()
    a_before = (core.WG_DIR / "UniFi-Gateway.conf").read_bytes()
    assert await wireguard_peers.migrate_legacy("wg0", "UniFi-Gateway")
    assert not await wireguard_peers.migrate_legacy("wg0", "UniFi-Gateway")
    assert (core.WG_DIR / "wg0.conf").read_bytes() == server_before
    assert (core.WG_DIR / "UniFi-Gateway.conf").read_bytes() == a_before
    first = wireguard_peers.list_peers()[0]
    server_public = run("wg", "show", "wg0", "public-key").stdout.strip()
    ifindex = Path("/sys/class/net/wg0/ifindex").read_text()
    install_client(a, initial["client_config"], "10.99.1.1:51820", directory)
    # A usable ordinary route is a required negative-test control.
    await asyncio.to_thread(ping, a)

    provider_private, provider_public = _wireguard_keypair()
    egress_private, egress_public = _wireguard_keypair()
    provider_config = "[Interface]\nPrivateKey = " + provider_private + "\nListenPort = 1337\n[Peer]\nPublicKey = " + egress_public + "\nAllowedIPs = 10.4.1.2/32\n"
    ns(remote, "ip", "link", "add", "wg-peer", "type", "wireguard")
    ns(remote, "wg", "setconf", "wg-peer", "/dev/stdin", input=provider_config)
    ns(remote, "ip", "address", "add", "10.4.1.1/24", "dev", "wg-peer")
    ns(remote, "ip", "address", "add", "10.0.0.242/32", "dev", "wg-peer")
    ns(remote, "ip", "link", "set", "wg-peer", "up")
    provider = Proton()
    profile = "[Interface]\nPrivateKey = " + egress_private + "\nAddress = 10.4.1.2/32\nDNS = 10.0.0.242\n[Peer]\nPublicKey = " + provider_public + "\nEndpoint = 8.8.8.8:1337\nAllowedIPs = 0.0.0.0/0\n"
    imported = await provider.import_profile(profile, "Synthetic multi-peer", "NL")
    assert imported["ok"]
    profile_id = imported["profile"]["id"]
    assert (await provider.connect(profile_id, timeout=15))["ok"], "provider_connect_failed"
    await asyncio.to_thread(ping, a)
    created = await wireguard_peers.create("wg0", "Deluge - Synology", "Synthetic consumer B", sync)
    second = created["peer"]
    config_b = created.get("configuration") or created.get("client_config")
    install_client(b, config_b, "10.99.2.1:51820", directory)
    await asyncio.to_thread(paired, a, b)

    def unchanged_a():
        row = wireguard_peers.get_peer(first["peer_id"])
        assert row["public_key"] == first["public_key"] and row["tunnel_ip"] == first["tunnel_ip"]
        assert (core.WG_DIR / "UniFi-Gateway.conf").read_bytes() == a_before
        assert run("wg", "show", "wg0", "public-key").stdout.strip() == server_public
        assert Path("/sys/class/net/wg0/ifindex").read_text() == ifindex

    unchanged_a()
    dump = run("wg", "show", "wg0", "dump").stdout.splitlines()[1:]
    for peer in (first, second):
        line = next(item.split("\t") for item in dump if item.split("\t")[0] == peer["public_key"])
        assert int(line[4]) > 0 and int(line[5]) > 0 and int(line[6]) > 0
    regenerated = await wireguard_peers.regenerate("wg0", second["peer_id"], sync)
    unchanged_a()
    assert regenerated["peer"]["public_key"] != second["public_key"]
    assert regenerated["peer"]["tunnel_ip"] == second["tunnel_ip"]
    await asyncio.to_thread(ping, b, blocked=True)
    await asyncio.to_thread(ping, a)
    config_b = regenerated.get("configuration") or regenerated.get("client_config")
    install_client(b, config_b, "10.99.2.1:51820", directory)
    await asyncio.to_thread(paired, a, b)
    await wireguard_peers.revoke("wg0", second["peer_id"], sync)
    unchanged_a()
    await asyncio.to_thread(ping, b, blocked=True)
    await asyncio.to_thread(ping, a)
    reactivated = await wireguard_peers.regenerate("wg0", second["peer_id"], sync)
    config_b = reactivated.get("configuration") or reactivated.get("client_config")
    install_client(b, config_b, "10.99.2.1:51820", directory)
    await asyncio.to_thread(paired, a, b)
    # Actual installed provider guard survives loss; ordinary route stays usable.
    await provider.wireguard.stop_interface("wg-proton")
    assert await asyncio.to_thread(cli.restore_provider_egress_guard, effective_user_id=0) == 0
    await asyncio.to_thread(paired, a, b, blocked=True)
    for peer in (first, second):
        route = run("ip", "-4", "route", "get", "1.1.1.1", "from", peer["tunnel_ip"], "iif", "wg0", ok=False)
        assert route.returncode != 0, "plaintext_route_fallback"
    assert run("ping", "-n", "-c", "1", "-W", "1", "1.1.1.1", ok=False).returncode == 0
    assert (await provider.reconnect(profile_id, timeout=15))["ok"]
    await asyncio.to_thread(paired, a, b)
    unchanged_a()
    print(json.dumps({"migration_exact_bytes": True, "migration_idempotent": True, "simultaneous_handshakes_and_egress": True, "create_preserves_a": True, "regenerate_preserves_a_old_b_rejected": True, "revoke_preserves_a_old_b_rejected": True, "provider_loss_blocks_both_with_usable_plaintext_control": True, "provider_recovery_restores_both": True, "server_identity_and_ifindex_unchanged": True}))


def outer():
    if os.geteuid() != 0:
        raise SystemExit("root_required")
    suffix = uuid.uuid4().hex[:6]
    names = ["el-mp-" + suffix + "-" + part for part in ("gw", "a", "b", "remote")]
    gw, a, b, remote = names
    dns = None
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="exitlane-multipeer-") as work:
        directory = Path(work)
        try:
            for name in names:
                run("ip", "netns", "add", name)
                ns(name, "ip", "link", "set", "lo", "up")
            for index, other, prefix in ((1, a, "10.99.1"), (2, b, "10.99.2"), (3, remote, "8.8.8")):
                left, right = "ml" + suffix + str(index), "mr" + suffix + str(index)
                run("ip", "link", "add", left, "type", "veth", "peer", "name", right)
                run("ip", "link", "set", left, "netns", gw)
                run("ip", "link", "set", right, "netns", other)
                gateway_ip, other_ip = (prefix + ".9", prefix + ".8") if index == 3 else (prefix + ".1", prefix + ".2")
                for name, link, address in ((gw, left, gateway_ip), (other, right, other_ip)):
                    ns(name, "ip", "address", "add", address + "/24", "dev", link)
                    ns(name, "ip", "link", "set", link, "up")
                if index == 3:
                    ns(gw, "ip", "route", "add", "default", "via", other_ip)
            ns(gw, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            ns(remote, "ip", "address", "add", "1.1.1.1/32", "dev", "lo")
            dns_script = directory / "dns.py"
            private(dns_script, 'import socket,struct\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind(("0.0.0.0",53))\nwhile True:\n q,a=s.recvfrom(4096)\n if len(q)>16:s.sendto(q[:2]+struct.pack("!HHHHH",0x8180,1,1,0,0)+q[12:]+b"\\xc0\\x0c"+struct.pack("!HHIH",1,1,60,4)+bytes((1,1,1,1)),a)\n')
            dns = subprocess.Popen(["ip", "netns", "exec", remote, sys.executable, str(dns_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.2)
            result = run("ip", "netns", "exec", gw, "env", "EXITLANE_DATA_DIR=" + str(directory / "data"), sys.executable, str(Path(__file__).resolve()), "--inner", work, a, b, remote)
            print(result.stdout.strip())
        finally:
            if dns:
                dns.terminate()
                dns.wait(timeout=5)
            for name in reversed(names):
                run("ip", "netns", "delete", name, ok=False)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        asyncio.run(qualify(Path(sys.argv[2]), *sys.argv[3:]))
    else:
        outer()
