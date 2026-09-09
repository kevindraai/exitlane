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
