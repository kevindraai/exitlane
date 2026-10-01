#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the isolated Proton qualification as root." >&2
  exit 77
fi

readonly CLIENT_NS="exitlane-proton-client-$$"
readonly SERVER_NS="exitlane-proton-peer-$$"
WORK="$(mktemp -d /tmp/exitlane-proton-qualification.XXXXXXXX)"
readonly WORK
cleanup() {
  if [[ -n ${DNS_PID:-} ]]; then kill "$DNS_PID" 2>/dev/null || true; fi
  ip netns delete "$CLIENT_NS" 2>/dev/null || true
  ip netns delete "$SERVER_NS" 2>/dev/null || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT

ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"
# Explicit native gateway prerequisite; never inherit or change host forwarding.
ip netns exec "$CLIENT_NS" sysctl -q -w net.ipv4.ip_forward=1
ip link add veth-pr-client type veth peer name veth-pr-server
ip link set veth-pr-client netns "$CLIENT_NS"
ip link set veth-pr-server netns "$SERVER_NS"
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" address add 8.8.8.9/24 dev veth-pr-client
ip -n "$SERVER_NS" address add 8.8.8.8/24 dev veth-pr-server
ip -n "$CLIENT_NS" link set veth-pr-client up
ip -n "$SERVER_NS" link set veth-pr-server up
ip -n "$CLIENT_NS" link add ingress type dummy
ip -n "$CLIENT_NS" address add 198.18.0.254/15 dev ingress
ip -n "$CLIENT_NS" link set ingress up
ip -n "$SERVER_NS" address add 1.1.1.1/32 dev lo

umask 077
wg genkey > "$WORK/server.key"
wg pubkey < "$WORK/server.key" > "$WORK/server.pub"
ip -n "$SERVER_NS" link add wg-peer type wireguard
ip netns exec "$SERVER_NS" wg set wg-peer private-key "$WORK/server.key" listen-port 1337
ip -n "$SERVER_NS" address add 10.0.0.1/24 dev wg-peer
ip -n "$SERVER_NS" address add 10.0.0.242/32 dev wg-peer
ip -n "$SERVER_NS" link set wg-peer up
ip -n "$SERVER_NS" route add 10.4.1.2/32 dev wg-peer

cat > "$WORK/dns.py" <<'PY'
import socket
import struct

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("10.0.0.242", 53))
    while True:
        query, sender = server.recvfrom(4096)
        if len(query) < 17:
            continue
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((1, 1, 1, 1))
        server.sendto(header + query[12:] + answer, sender)
PY
ip netns exec "$SERVER_NS" python3 "$WORK/dns.py" &
DNS_PID=$!

cat > "$WORK/qualify.py" <<'PY'
import asyncio
import json
import subprocess
import sys
from pathlib import Path

from exitlane import cli, core
from exitlane.providers.proton import Proton
from exitlane.providers.wireguard_keys import _wireguard_keypair
from exitlane.services import auth_security, provider_secrets

server_ns, server_pub_path = sys.argv[1:]


def peer(public):
    subprocess.run(
        ["ip", "netns", "exec", server_ns, "wg", "set", "wg-peer", "peer", public,
         "allowed-ips", "10.4.1.2/32"],
        check=True, capture_output=True, timeout=5,
    )


def profile(private, server_pub):
    return (
        "[Interface]\n"
        f"PrivateKey = {private}\nAddress = 10.4.1.2/32, 2a07:e340::2/128\n"
        "DNS = 10.0.0.242\nMTU = 1380\n[Peer]\n"
        f"PublicKey = {server_pub}\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        "Endpoint = 8.8.8.8:1337\n"
    )


async def main():
    core.init()
    auth_security.ensure_master_key()
    core.set_setting("wireguard_interface", "ingress")
    provider = Proton()
    server_pub = Path(server_pub_path).read_text().strip()
    first_private, first_public = _wireguard_keypair()
    second_private, second_public = _wireguard_keypair()
    first = await provider.import_profile(profile(first_private, server_pub), "NL synthetic", "NL")
    second = await provider.import_profile(profile(second_private, server_pub), "DE synthetic", "DE")
    assert first["ok"] and second["ok"]
    first_id, second_id = first["profile"]["id"], second["profile"]["id"]
    with open(core.DB, "rb") as database:
        assert first_private.encode() not in database.read()
    failed = await provider.connect(first_id, timeout=1)
    assert failed["ok"] is False and provider.direct_egress_intent() is None, failed
    rules = subprocess.run(
        ["ip", "-4", "rule", "show"], check=True, capture_output=True, text=True, timeout=5
    ).stdout
    assert "oif wg-proton" not in rules, rules
    await provider.wireguard.arm(("ingress",), "wg-mullvad")
    await provider.wireguard.disarm(("ingress",), "wg-mullvad")
    peer(first_public)
    connected = await provider.connect(first_id, timeout=12)
    assert connected["ok"], connected
    status = await provider.status()
    assert status["connected"] and status["server"] == first_id, status
    assert first_private not in json.dumps(status)
    assert await provider.delete_profile(first_id) == {"ok": False, "error_code": "proton_profile_active"}
    route = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "198.18.0.1", "iif", "ingress"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    assert "dev wg-proton" in route and "table 51820" in route, route
    host_route = subprocess.run(
        ["ip", "-4", "route", "get", "8.8.8.8"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    assert "dev veth-pr-client" in host_route and "wg-proton" not in host_route
    peer(second_public)
    switched = await provider.connect(second_id, timeout=12)
    assert switched["ok"], switched
    assert (await provider.status())["server"] == second_id
    restarted = Proton()
    assert (await restarted.status())["connected"]
    await restarted.wireguard.stop_interface("wg-proton")
    assert cli._direct_egress_state().provider_id == "proton"
    assert await asyncio.to_thread(cli.restore_provider_egress_guard, effective_user_id=0) == 0
    guarded = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "198.18.0.1", "iif", "ingress"],
        capture_output=True, timeout=5,
    )
    assert guarded.returncode != 0
    recovered = await restarted.reconnect(second_id, timeout=12)
    assert recovered["ok"], recovered
    assert (await restarted.status())["connected"]
    assert (await restarted.disconnect())["ok"]
    assert not (await restarted.status())["connected"]
    late = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "10.4.1.2"],
        capture_output=True, timeout=5,
    )
    assert late.returncode != 0
    assert (await restarted.delete_profile(second_id))["ok"]
    assert provider_secrets.load("proton")["profiles"].get(second_id) is None


asyncio.run(main())
PY

readonly PYTHON_BIN="${EXITLANE_TEST_PYTHON:-/opt/exitlane/venv/bin/python}"
ip netns exec "$CLIENT_NS" env EXITLANE_DATA_DIR="$WORK/data" \
  "$PYTHON_BIN" "$WORK/qualify.py" "$SERVER_NS" "$WORK/server.pub"
echo "Proton synthetic profile lifecycle and real kernel dataplane passed."
