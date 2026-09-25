#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

readonly NAMESPACE="exitlane-egress-test-$$"
readonly TABLE_ID="51820"
readonly PROTOCOL="196"

cleanup() {
  ip netns delete "${NAMESPACE}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this isolated network-namespace test as root." >&2
  exit 77
fi

ip netns add "${NAMESPACE}"
ip -n "${NAMESPACE}" link set lo up
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "${NAMESPACE}" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip -n "${NAMESPACE}" link add ingress type dummy
ip -n "${NAMESPACE}" link add wg-mullvad type dummy
ip -n "${NAMESPACE}" link add uplink type dummy
ip -n "${NAMESPACE}" link set ingress up
ip -n "${NAMESPACE}" link set wg-mullvad up
ip -n "${NAMESPACE}" link set uplink up
ip -n "${NAMESPACE}" address add 10.67.12.34/32 dev wg-mullvad
ip -n "${NAMESPACE}" address add 198.18.0.254/15 dev ingress
ip -n "${NAMESPACE}" address add 192.0.2.2/24 dev uplink
ip -n "${NAMESPACE}" route add default dev uplink
ip -n "${NAMESPACE}" -6 route add default dev uplink

ip -n "${NAMESPACE}" -4 route replace unreachable default \
  table "${TABLE_ID}" metric 42760 proto "${PROTOCOL}"
# Exact provider-source replies have no ingress or bound output interface.
# They must precede even the temporary management routing priority (1).
ip -n "${NAMESPACE}" -4 rule add priority 0 from 10.67.12.34/32 \
  table "${TABLE_ID}" protocol "${PROTOCOL}"
ip -n "${NAMESPACE}" -4 route add default dev uplink table 10000
ip -n "${NAMESPACE}" -4 rule add priority 1 to 10.64.0.1/32 table 10000
ip -n "${NAMESPACE}" -4 rule add priority 20000 iif ingress \
  table "${TABLE_ID}" protocol "${PROTOCOL}"
ip -n "${NAMESPACE}" -4 rule add priority 19999 oif wg-mullvad \
  table "${TABLE_ID}" protocol "${PROTOCOL}"
ip -n "${NAMESPACE}" -6 route replace unreachable default \
  table "${TABLE_ID}" metric 42760 proto "${PROTOCOL}"
ip -n "${NAMESPACE}" -6 rule add priority 20000 iif ingress \
  table "${TABLE_ID}" protocol "${PROTOCOL}"

if ip netns exec "${NAMESPACE}" ip -4 route get 1.1.1.1 from 198.18.0.1 iif ingress \
  >/dev/null 2>&1; then
  echo "Protected ingress unexpectedly escaped while the provider route was absent." >&2
  exit 1
fi

ip -n "${NAMESPACE}" -4 route replace default dev wg-mullvad \
  table "${TABLE_ID}" metric 10 proto "${PROTOCOL}"
protected_route="$(
  ip netns exec "${NAMESPACE}" ip -4 route get 1.1.1.1 from 198.18.0.1 iif ingress
)"
[[ "${protected_route}" == *"dev wg-mullvad"* ]] || {
  echo "Protected ingress did not select the provider interface." >&2
  exit 1
}
[[ "${protected_route}" == *"table ${TABLE_ID}"* ]] || {
  echo "Protected ingress did not select the owned provider table." >&2
  exit 1
}
probe_route="$(ip netns exec "${NAMESPACE}" ip -4 route get 1.1.1.1 oif wg-mullvad)"
[[ "${probe_route}" == *"dev wg-mullvad"*"table ${TABLE_ID}"* ]] || {
  echo "Interface-bound readiness probes do not use the provider table." >&2
  exit 1
}

for destination in 1.1.1.1 10.64.0.1; do
  source_route="$(
    ip netns exec "${NAMESPACE}" ip -4 route get "${destination}" from 10.67.12.34
  )"
  [[ "${source_route}" == *"dev wg-mullvad"*"table ${TABLE_ID}"* ]] || {
    echo "Provider-source output bypassed the provider table." >&2
    exit 1
  }
done
local_route="$(
  ip netns exec "${NAMESPACE}" ip -4 route get 10.67.12.34 from 10.67.12.34
)"
[[ "${local_route}" == local*"dev lo"* ]] || {
  echo "The source guard displaced kernel local routing." >&2
  exit 1
}

ip netns exec "${NAMESPACE}" nft -f - <<'NFT'
table inet source_guard_test {
  chain output {
    type filter hook output priority 300; policy accept;
    ip saddr 10.67.12.34 oifname "uplink" counter comment "plaintext"
    ip saddr 10.67.12.34 oifname "wg-mullvad" counter comment "provider"
  }
}
NFT
ip netns exec "${NAMESPACE}" python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    # Deliberately no SO_BINDTODEVICE: this is the missing host-output path.
    client.bind(("10.67.12.34", 0))
    for destination in ("1.1.1.1", "10.64.0.1"):
        client.sendto(b"provider-source-guard-test", (destination, 53))
PY
ip netns exec "${NAMESPACE}" nft -j list table inet source_guard_test |
  python3 -c '
import json, sys
counts = {}
for entry in json.load(sys.stdin)["nftables"]:
    rule = entry.get("rule", {})
    for expression in rule.get("expr", []):
        if "counter" in expression:
            counts[rule["comment"]] = expression["counter"]["packets"]
assert counts == {"plaintext": 0, "provider": 2}, counts
'

if ip netns exec "${NAMESPACE}" ip -6 route get 2606:4700:4700::1111 \
  from 2001:db8:ffff::1 iif ingress \
  >/dev/null 2>&1; then
  echo "Protected IPv6 unexpectedly escaped the IPv4-only provider policy." >&2
  exit 1
fi

host_route="$(ip netns exec "${NAMESPACE}" ip -4 route get 1.1.1.1)"
[[ "${host_route}" == *"dev uplink"* ]] || {
  echo "Host output was incorrectly captured by provider egress policy." >&2
  exit 1
}

ip -n "${NAMESPACE}" -4 route del default dev wg-mullvad \
  table "${TABLE_ID}" metric 10 proto "${PROTOCOL}"
ip -n "${NAMESPACE}" link delete wg-mullvad
# The exact source rule and unreachable route remain after disconnect/sign-out.
ip netns exec "${NAMESPACE}" ip -j -4 rule show | python3 -c '
import json, sys
zero = [r for r in json.load(sys.stdin) if r.get("priority") == 0]
assert zero and str(zero[0].get("table")) in {"local", "255"}, zero
assert any(r.get("src") in {"10.67.12.34", "10.67.12.34/32"}
           and str(r.get("table")) == "51820" and str(r.get("protocol")) == "196"
           and set(r) <= {"src", "priority", "table", "protocol"}
           for r in zero[1:]), zero
'
ip netns exec "${NAMESPACE}" ip -j -4 route show table "${TABLE_ID}" | python3 -c '
import json, sys
routes = json.load(sys.stdin)
assert any(r.get("type") == "unreachable" and r.get("dst") == "default"
           and r.get("metric") == 42760 and str(r.get("protocol")) == "196"
           for r in routes), routes
'
for destination in 1.1.1.1 10.64.0.1; do
  if ip netns exec "${NAMESPACE}" ip -4 route get "${destination}" from 10.67.12.34 \
    >/dev/null 2>&1; then
    echo "Late provider-source output escaped after interface teardown." >&2
    exit 1
  fi
done
ip netns exec "${NAMESPACE}" python3 - <<'PY'
import errno
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.setsockopt(socket.SOL_IP, 15, 1)  # IP_FREEBIND after address removal.
    client.bind(("10.67.12.34", 0))
    for destination in ("1.1.1.1", "10.64.0.1"):
        try:
            client.sendto(b"late-provider-reply", (destination, 53))
        except OSError as error:
            assert error.errno in {errno.ENETUNREACH, errno.EHOSTUNREACH}, error
        else:
            raise AssertionError("Late source-bound packet was accepted")
PY
host_route="$(
  ip netns exec "${NAMESPACE}" ip -4 route get 1.1.1.1 from 192.0.2.2
)"
[[ "${host_route}" == *"dev uplink"* ]] || {
  echo "Management-source traffic was blocked after provider teardown." >&2
  exit 1
}
if ip netns exec "${NAMESPACE}" ip -4 route get 1.1.1.1 from 198.18.0.1 iif ingress \
  >/dev/null 2>&1; then
  echo "Protected ingress fell through after provider interface teardown." >&2
  exit 1
fi

rule_dump="$(ip netns exec "${NAMESPACE}" ip -4 rule show)"
[[ "${rule_dump}" == *"iif ingress lookup ${TABLE_ID} proto ${PROTOCOL}"* ]] || {
  echo "The owned ingress rule was not retained with its protocol marker." >&2
  exit 1
}

echo "Provider egress namespace tests passed."
