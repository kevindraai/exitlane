#!/usr/bin/env bash
set -euo pipefail

readonly NS="exitlane-ks-test"
readonly CLIENT_NS="exitlane-ks-client"
readonly WAN_NS="exitlane-ks-wan"
RULES="$(mktemp)"
readonly RULES
CAPTURE="$(mktemp --suffix=.pcap)"
readonly CAPTURE
CAPTURE_PID=""

cleanup() {
  if [[ -n "${CAPTURE_PID}" ]]; then
    kill "${CAPTURE_PID}" 2>/dev/null || true
    wait "${CAPTURE_PID}" 2>/dev/null || true
  fi
  ip netns del "${NS}" 2>/dev/null || true
  ip netns del "${CLIENT_NS}" 2>/dev/null || true
  ip netns del "${WAN_NS}" 2>/dev/null || true
  rm -f "${RULES}" "${CAPTURE}"
}
trap cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this disposable network-namespace test as root." >&2
  exit 77
fi

ip netns add "${NS}"
ip netns add "${CLIENT_NS}"
ip netns add "${WAN_NS}"
ip link add wg0 netns "${NS}" type veth peer name client0 netns "${CLIENT_NS}"
ip link add wan0 netns "${NS}" type veth peer name server0 netns "${WAN_NS}"
ip -n "${NS}" address add 10.10.0.1/24 dev wg0
ip -n "${CLIENT_NS}" address add 10.10.0.2/24 dev client0
ip -n "${NS}" address add 198.51.100.1/24 dev wan0
ip -n "${WAN_NS}" address add 198.51.100.2/24 dev server0
ip -n "${NS}" address add fd10::1/64 dev wg0
ip -n "${CLIENT_NS}" address add fd10::2/64 dev client0
ip -n "${NS}" address add fd20::1/64 dev wan0
ip -n "${WAN_NS}" address add fd20::2/64 dev server0
ip -n "${NS}" link set lo up
ip -n "${CLIENT_NS}" link set lo up
ip -n "${WAN_NS}" link set lo up
ip -n "${NS}" link set wg0 up
ip -n "${CLIENT_NS}" link set client0 up
ip -n "${NS}" link set wan0 up
ip -n "${WAN_NS}" link set server0 up
ip -n "${CLIENT_NS}" route add default via 10.10.0.1
ip -n "${WAN_NS}" route add 10.10.0.0/24 via 198.51.100.1
ip -n "${CLIENT_NS}" -6 route add default via fd10::1
ip -n "${WAN_NS}" -6 route add fd10::/64 via fd20::1
ip netns exec "${NS}" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "${NS}" sysctl -q -w net.ipv6.conf.all.forwarding=1
chmod 0600 "${RULES}"

# The same fail-closed shape used by the application: no input/output hooks,
# explicit DNS guard, IPv4/IPv6 forward protection, and an owned table only.
{
  echo 'destroy table inet exitlane_killswitch'
  echo 'table inet exitlane_killswitch {'
  echo ' set protected_ingress { type ifname; elements = { "wg0" } }'
  echo ' chain forward {'
  echo '  type filter hook forward priority -150; policy accept;'
  echo '  ct state established,related accept'
  echo '  iifname @protected_ingress udp dport 53 counter drop'
  echo '  iifname @protected_ingress tcp dport 53 counter drop'
  echo '  iifname @protected_ingress counter drop'
  echo ' }'
  echo '}'
} > "${RULES}"

ip netns exec "${NS}" nft -c -f "${RULES}"
ip netns exec "${NS}" nft -f "${RULES}"
ip netns exec "${NS}" nft -f "${RULES}"
ip netns exec "${NS}" nft list table inet exitlane_killswitch |
  grep -E 'iifname @protected_ingress .*drop' >/dev/null
ip netns exec "${NS}" nft list ruleset |
  grep 'table inet exitlane_killswitch' >/dev/null

ip netns exec "${WAN_NS}" tcpdump -U -i server0 -nn -w "${CAPTURE}" \
  'ip src net 10.10.0.0/24 or ip6 src net fd10::/64' >/dev/null 2>&1 &
CAPTURE_PID=$!
sleep 1

if ip netns exec "${CLIENT_NS}" ping -c 1 -W 1 198.51.100.2 >/dev/null 2>&1; then
  echo "IPv4 clear-net leak detected" >&2
  exit 1
fi
if ip netns exec "${CLIENT_NS}" ping -6 -c 1 -W 1 fd20::2 >/dev/null 2>&1; then
  echo "IPv6 clear-net leak detected" >&2
  exit 1
fi
ip netns exec "${CLIENT_NS}" bash -c \
  'printf leak-test >/dev/udp/198.51.100.2/53' 2>/dev/null || true
ip netns exec "${CLIENT_NS}" timeout 1 bash -c \
  'printf leak-test >/dev/tcp/198.51.100.2/53' 2>/dev/null || true
sleep 1
kill "${CAPTURE_PID}" 2>/dev/null || true
wait "${CAPTURE_PID}" 2>/dev/null || true
CAPTURE_PID=""

if [[ "$(tcpdump -nn -r "${CAPTURE}" 2>/dev/null | wc -l)" -ne 0 ]]; then
  echo "Packet capture detected protected traffic on clear-net WAN" >&2
  exit 1
fi
ip netns exec "${NS}" nft list chain inet exitlane_killswitch forward |
  grep -E 'counter packets [1-9][0-9]*' >/dev/null

# Reboot-equivalent: remove namespace state, recreate it, and prove the early
# fail-closed rules can be restored before any network interface exists.
ip netns del "${NS}"
ip netns del "${CLIENT_NS}"
ip netns del "${WAN_NS}"
ip netns add "${NS}"
ip netns exec "${NS}" nft -f "${RULES}"
ip netns exec "${NS}" nft list table inet exitlane_killswitch |
  grep -E 'tcp dport 53 .*drop' >/dev/null

echo "killswitch nft syntax, idempotence, DNS/IPv4/IPv6 capture and reboot restore passed"
