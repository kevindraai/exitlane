#!/usr/bin/env bash
set -euo pipefail

readonly NS="exitlane-management-routing-test"
readonly GATEWAY_LINK="exl-mgmt-gw"
readonly PROVIDER_TABLE="1836018789"

cleanup() {
  ip netns del "${NS}" 2>/dev/null || true
  ip link del "${GATEWAY_LINK}" 2>/dev/null || true
}
trap cleanup EXIT

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this disposable network-namespace test as root." >&2
  exit 1
fi

cleanup
ip netns add "${NS}"
ip link add management0 netns "${NS}" type veth peer name "${GATEWAY_LINK}"
ip link set "${GATEWAY_LINK}" up
ip address add 172.16.130.1/24 dev "${GATEWAY_LINK}"
ip -n "${NS}" link set lo up
ip -n "${NS}" link set management0 name eth0
ip -n "${NS}" link set eth0 up
ip -n "${NS}" address add 172.16.130.81/24 dev eth0
ip -n "${NS}" route add default via 172.16.130.1 dev eth0
ip -n "${NS}" route add 172.16.5.0/24 via 172.16.130.1 dev eth0 \
  protocol 196 metric 42760

ip -n "${NS}" link add wg0 type dummy
ip -n "${NS}" link set wg0 up
ip -n "${NS}" address add 10.99.99.1/24 dev wg0

ip -n "${NS}" link add wg0-mullvad type dummy
ip -n "${NS}" link set wg0-mullvad up
ip -n "${NS}" address add 10.160.101.153/32 dev wg0-mullvad
ip -n "${NS}" route add default dev wg0-mullvad table "${PROVIDER_TABLE}"
ip -n "${NS}" rule add priority 0 not fwmark 0x6d6f6c65 table "${PROVIDER_TABLE}"
ip -n "${NS}" rule add priority 0 table main suppress_prefixlength 0

# Reproduce the live regression: a stale ExitLane-owned priority-0 rule plus
# newer duplicate-generation rules. Provider rules above must survive exactly.
ip -n "${NS}" rule add priority 0 to 172.16.5.0/24 table main protocol 196
ip -n "${NS}" rule add priority 10000 to 172.16.5.0/24 table main protocol 196
ip -n "${NS}" rule add priority 10001 to 172.16.130.0/24 table main protocol 196

PYTHONPATH="${PWD}/backend" TEST_NAMESPACE="${NS}" \
  TEST_PROVIDER_TABLE="${PROVIDER_TABLE}" \
  "${PWD}/backend/.venv/bin/python" - <<'PY'
import asyncio
import ipaddress
import json
import os

from exitlane import core
from exitlane.services import management_routing


namespace = os.environ["TEST_NAMESPACE"]
provider_table = os.environ["TEST_PROVIDER_TABLE"]


async def namespaced_ip(*arguments, timeout=10, input_text=None, environment=None):
    return await core.command(
        arguments[0],
        "netns",
        "exec",
        namespace,
        arguments[0],
        *arguments[1:],
        timeout=timeout,
        input_text=input_text,
        environment=environment,
    )


async def verify():
    backend = management_routing.ManagementRoutingBackend(runner=namespaced_ip)
    configured = ["172.16.5.0/24"]
    protected = (
        management_routing.ProtectedDestination(
            network=ipaddress.ip_network("10.99.99.0/24"),
            expected_device="wg0",
            source="wireguard_ingress",
        ),
    )
    await backend.reconcile(configured, protected)
    await backend.prepare_provider_transition(configured, protected)
    await backend.reconcile(configured, protected)

    # A fresh backend represents process restart/reboot reconciliation against
    # the same kernel state and must remain a no-op for owned rules.
    backend = management_routing.ManagementRoutingBackend(runner=namespaced_ip)
    result = await backend.reconcile(configured, protected)
    rules = await backend._rules(4)
    owned = backend._owned_rules(4, rules)
    assert owned == [
        (10000, ipaddress.ip_network("10.99.99.0/24")),
        (10000, ipaddress.ip_network("172.16.5.0/24")),
        (10000, ipaddress.ip_network("172.16.130.0/24")),
    ], owned
    assert all(priority != 0 for priority, _network in owned)
    assert any(
        int(rule.get("priority", -1)) == 0
        and str(rule.get("table")) == "1836018789"
        for rule in rules
    )

    all_routes = await backend._all_routes(4)
    owned_provider_routes = backend._owned_provider_routes(4, all_routes)
    assert owned_provider_routes == {
        (
            "1836018789",
            ipaddress.ip_network("10.99.99.0/24"),
        ): (None, "wg0"),
        (
            "1836018789",
            ipaddress.ip_network("172.16.130.0/24"),
        ): (None, "eth0"),
        (
            "1836018789",
            ipaddress.ip_network("172.16.5.0/24"),
        ): ("172.16.130.1", "eth0"),
    }, owned_provider_routes

    observations = {}
    for destination in (
        "10.99.99.2",
        "172.16.130.1",
        "172.16.130.2",
        "172.16.5.1",
        "1.1.1.1",
    ):
        family = ipaddress.ip_address(destination).version
        rc, output, _error = await namespaced_ip(
            management_routing.IP_BINARY,
            "-j",
            f"-{family}",
            "route",
            "get",
            destination,
        )
        assert rc == 0
        observations[destination] = json.loads(output)[0]
    assert observations["10.99.99.2"]["dev"] == "wg0"
    assert observations["172.16.130.1"]["dev"] == "eth0"
    assert observations["172.16.130.2"]["dev"] == "eth0"
    assert observations["172.16.5.1"]["gateway"] == "172.16.130.1"
    assert observations["172.16.5.1"]["dev"] == "eth0"
    assert observations["1.1.1.1"]["dev"] == "wg0-mullvad"
    assert str(observations["1.1.1.1"]["table"]) == "1836018789"
    assert result.added == 0 and result.removed == 0

    # Interface recreation must close the configured destination instead of
    # allowing the provider default, then converge when the local route returns.
    rc, _output, _error = await namespaced_ip(
        management_routing.IP_BINARY,
        "link",
        "del",
        "wg0",
    )
    assert rc == 0
    try:
        await backend.reconcile(configured, protected)
    except management_routing.ManagementRoutingError as error:
        assert error.code == "protected_destination_route_unavailable"
    else:
        raise AssertionError("missing WireGuard route must fail closed")
    provider_routes = await backend._table_routes(4, provider_table)
    fail_closed = [
        route
        for route in provider_routes
        if backend._route_network(route) == ipaddress.ip_network("10.99.99.0/24")
    ]
    assert len(fail_closed) == 1
    assert fail_closed[0].get("type") == "unreachable"

    for arguments in (
        ("link", "add", "wg0", "type", "dummy"),
        ("link", "set", "wg0", "up"),
        ("address", "add", "10.99.99.1/24", "dev", "wg0"),
    ):
        rc, _output, _error = await namespaced_ip(
            management_routing.IP_BINARY,
            *arguments,
        )
        assert rc == 0
    await backend.reconcile(configured, protected)
    rc, output, _error = await namespaced_ip(
        management_routing.IP_BINARY,
        "-j",
        "-4",
        "route",
        "get",
        "10.99.99.2",
    )
    assert rc == 0
    assert json.loads(output)[0]["dev"] == "wg0"


asyncio.run(verify())
PY

echo "protected routing cleanup, WireGuard/management postconditions, provider preservation and idempotence passed"
