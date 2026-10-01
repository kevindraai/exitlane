#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run the isolated PIA qualification as root." >&2
  exit 77
fi

readonly CLIENT_NS="exitlane-pia-client-$$"
readonly SERVER_NS="exitlane-pia-peer-$$"
WORK="$(mktemp -d /tmp/exitlane-pia-qualification.XXXXXXXX)"
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
ip link add veth-pia-client type veth peer name veth-pia-server
ip link set veth-pia-client netns "$CLIENT_NS"
ip link set veth-pia-server netns "$SERVER_NS"
ip -n "$CLIENT_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" address add 8.8.8.9/24 dev veth-pia-client
ip -n "$SERVER_NS" address add 8.8.8.8/24 dev veth-pia-server
ip -n "$CLIENT_NS" link set veth-pia-client up
ip -n "$SERVER_NS" link set veth-pia-server up
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
from exitlane.providers.pia import Pia
from exitlane.providers.pia_api import PiaKeyResponse, PiaServer
from exitlane.services import auth_security, provider_secrets

server_ns, server_pub_path = sys.argv[1:]
server = PiaServer("nl_synthetic", "NL synthetic", "NL", "synthetic401", "8.8.8.8", "8.8.8.8")
other_region = PiaServer("de_synthetic", "DE synthetic", "DE", "synthetic402", "8.8.8.8", "8.8.8.8")


class ProviderBoundary:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    async def token(self):
        return "a" * 40

    async def catalog(self):
        return [server, other_region]

    async def add_key(self, selected, public_key):
        assert selected in {server, other_region}
        subprocess.run(
            ["ip", "netns", "exec", server_ns, "wg", "set", "wg-peer", "peer", public_key,
             "allowed-ips", "10.4.1.2/32"],
            check=True, capture_output=True, timeout=5,
        )
        return PiaKeyResponse("10.4.1.2/32", Path(server_pub_path).read_text().strip(), 1337, "10.0.0.242")


async def main():
    core.init()
    auth_security.ensure_master_key()
    core.set_setting("wireguard_interface", "ingress")
    provider = Pia(api_factory=ProviderBoundary)
    assert (await provider.authenticate_credentials("p1234567", "synthetic-only"))["ok"]
    with open(core.DB, "rb") as database:
        assert b"synthetic-only" not in database.read()
    real_dns_probe = provider.wireguard.dns_probe

    async def unavailable_dns(*_args):
        return False

    provider.wireguard.dns_probe = unavailable_dns
    failed = await provider.connect("NL", timeout=1)
    assert failed["ok"] is False and failed["error_code"] == "provider_dns_unavailable", failed
    assert provider.direct_egress_intent() is None
    pia_rules = subprocess.run(
        ["ip", "-4", "rule", "show"], check=True, capture_output=True, text=True, timeout=5
    ).stdout
    assert "oif wg-pia" not in pia_rules, pia_rules
    await provider.wireguard.arm(("ingress",), "wg-mullvad")
    await provider.wireguard.disarm(("ingress",), "wg-mullvad")
    provider.wireguard.dns_probe = real_dns_probe
    result = await provider.connect("NL", timeout=12)
    assert result["ok"], result
    status = await provider.status()
    assert status["connected"] and status["handshake"] > 0, status
    assert status["server"] == server.selection_id
    assert "synthetic-only" not in json.dumps(status)
    route = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "198.18.0.1", "iif", "ingress"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    assert "dev wg-pia" in route and "table 51820" in route, route
    host_route = subprocess.run(
        ["ip", "-4", "route", "get", "8.8.8.8"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    assert "dev veth-pia-client" in host_route and "wg-pia" not in host_route
    switched = await provider.connect("DE", timeout=12)
    assert switched["ok"], switched
    assert (await provider.status())["country_code"] == "DE"
    restarted = Pia(api_factory=ProviderBoundary)
    assert (await restarted.status())["connected"]
    await restarted.wireguard.stop_interface("wg-pia")
    assert cli._direct_egress_state().provider_id == "pia"
    assert await asyncio.to_thread(cli.restore_provider_egress_guard, effective_user_id=0) == 0
    guarded = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "198.18.0.1", "iif", "ingress"],
        capture_output=True, timeout=5,
    )
    assert guarded.returncode != 0
    recovered = await restarted.reconnect("DE", timeout=12)
    assert recovered["ok"], recovered
    assert (await restarted.status())["connected"]
    assert (await restarted.disconnect())["ok"]
    assert not (await restarted.status())["connected"]
    late = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1", "from", "10.4.1.2"],
        capture_output=True, timeout=5,
    )
    assert late.returncode != 0
    subprocess.run(["ip", "link", "add", "wg-mullvad", "type", "dummy"], check=True, timeout=5)
    subprocess.run(["ip", "link", "set", "wg-mullvad", "up"], check=True, timeout=5)
    subprocess.run(
        ["ip", "-4", "route", "replace", "default", "dev", "wg-mullvad", "table", "51820",
         "metric", "10", "proto", "196"],
        check=True, timeout=5,
    )
    assert (await restarted.sign_out())["ok"]
    assert provider_secrets.load("pia") is None
    shared = subprocess.run(
        ["ip", "-4", "route", "show", "table", "51820"],
        check=True, capture_output=True, text=True, timeout=5,
    ).stdout
    assert "dev wg-mullvad" in shared


asyncio.run(main())
PY

readonly PYTHON_BIN="${EXITLANE_TEST_PYTHON:-/opt/exitlane/venv/bin/python}"
ip netns exec "$CLIENT_NS" env EXITLANE_DATA_DIR="$WORK/data" \
  "$PYTHON_BIN" "$WORK/qualify.py" "$SERVER_NS" "$WORK/server.pub"
echo "PIA synthetic provider lifecycle and real kernel dataplane passed."
