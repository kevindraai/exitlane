"""Synthetic lifecycle ownership, ordering and bounded recovery; no host mutations."""

import asyncio
import base64
import json
from pathlib import Path

import pytest

from exitlane.container_runtime import (
    TABLE,
    ContainerLifecycleError,
    ContainerSupervisor,
    ContainerWireGuardLifecycle,
    IngressConfig,
)
from exitlane.services.wireguard import _forwarding_rules

KEY = base64.b64encode(bytes(range(32))).decode()


def config():
    return IngressConfig("wg-office", "10.88.0.1/24", KEY, KEY, "10.88.0.2/32", 51821)


class FakeGuard:
    def __init__(self, commands):
        self.commands = commands

    async def arm(self, ingress):
        self.commands.append(("guard", *ingress))


class Namespace:
    def __init__(self):
        self.commands = []
        self.inputs = []
        self.exists = False
        self.ifindex = 101
        self.guard_exists = False
        self.foreign = False
        self.bad_observation = False
        self.forwarding = "1"
        self.fail_setconf = False
        self.network = ContainerWireGuardLifecycle(
            config(), runner=self.run, provider_guard=FakeGuard(self.commands)
        )

    def nft(self):
        chains = []
        rules = []
        for name, expressions in (("forward", self.network.forward_expressions(self.network.policy_interface)), ("input", self.network.input_expressions()), ("output", self.network.output_expressions())):
            chain = {"family": "inet", "table": TABLE, "name": name, "type": "filter", "hook": name, "prio": 0 if name == "output" else -200, "policy": "accept"}
            chains.append({"chain": chain})
            rules += [{"rule": {"family": "inet", "table": TABLE, "chain": name, "expr": expr}} for expr in expressions]
        if self.bad_observation or self.foreign:
            rules[0]["rule"]["expr"] = [{"accept": None}]
        return json.dumps({"nftables": [*chains, *rules]})

    async def run(self, *args, **kwargs):
        self.commands.append(args)
        if kwargs.get("input_text"):
            self.inputs.append((args, kwargs["input_text"]))
        if args[:4] == ("ip", "-j", "link", "show"):
            return (
                (0, json.dumps([{"ifname": "wg-office", "ifindex": self.ifindex}]), "")
                if self.exists
                else (1, "", "")
            )
        if args[:3] == ("ip", "link", "show"):
            return (0 if self.exists else 1), "", ""
        if args[0] == "cat":
            return 0, self.forwarding, ""
        if args[:3] == ("nft", "-j", "list"):
            if args[-1] == "tables":
                return (
                    0,
                    json.dumps(
                        {
                            "nftables": [{"table": {"family": "inet", "name": TABLE}}]
                            if self.guard_exists
                            else []
                        }
                    ),
                    "",
                )
            return 0, self.nft(), ""
        if args[:3] == ("nft", "-f", "/dev/stdin"):
            self.guard_exists = True
        if args[:3] == ("ip", "link", "add"):
            self.exists = True
        if args[:3] == ("ip", "link", "delete"):
            self.exists = False
        if args[0] == "wg" and self.fail_setconf:
            return 1, "", KEY
        if args[:3] in (("ip", "-4", "-j"), ("ip", "-6", "-j")):
            facts = (
                [{"type": "unreachable", "dst": "default"}]
                if "route" in args
                else [{"iif": "wg-office", "table": 51820, "priority": 20000}]
            )
            return 0, json.dumps(facts), ""
        return 0, "", ""


def test_native_generated_hooks_validated_but_not_executed(tmp_path):
    path = tmp_path / "wg-office.conf"
    hooks = "PostUp = sysctl -w net.ipv4.ip_forward=1\n" + _forwarding_rules(
        "wg-office", "10.88.0.0/24", None
    )
    path.write_text(
        f"[Interface]\nAddress = 10.88.0.1/24\nPrivateKey = {KEY}\nListenPort = 51821\n{hooks}\n[Peer]\nPublicKey = {KEY}\nAllowedIPs = 10.88.0.2/32\n"
    )
    path.chmod(0o600)
    parsed = IngressConfig.from_file(path)
    assert parsed == config()
    assert "PostUp" not in parsed.wireguard_payload()
    assert "iptables" not in parsed.wireguard_payload()
    assert KEY not in repr(parsed)


@pytest.mark.parametrize(
    "directive",
    [
        "PostUp = touch /tmp/hostile",
        "Table = auto",
        "SaveConfig = true",
        "DNS = 8.8.8.8",
        "PrivateKey = duplicate",
    ],
)
def test_hostile_or_unsupported_config_rejected(tmp_path, directive):
    path = tmp_path / "wg-office.conf"
    path.write_text(
        f"[Interface]\nAddress = 10.88.0.1/24\nPrivateKey = {KEY}\nListenPort = 51821\n{directive}\n[Peer]\nPublicKey = {KEY}\nAllowedIPs = 10.88.0.2/32\n"
    )
    path.chmod(0o600)
    with pytest.raises(ContainerLifecycleError, match="config_invalid") as error:
        IngressConfig.from_file(path)
    assert KEY not in repr(error.value)


def test_secret_only_stdin_guard_before_creation_and_retained():
    ns = Namespace()
    asyncio.run(ns.network.activate())
    assert ns.commands.index(("guard", "wg-office")) < ns.commands.index(
        ("ip", "link", "add", "dev", "wg-office", "type", "wireguard")
    )
    assert ns.commands.index(("nft", "-j", "list", "table", "inet", TABLE)) < ns.commands.index(
        ("ip", "link", "add", "dev", "wg-office", "type", "wireguard")
    )
    assert KEY not in repr(ns.commands)
    assert any(KEY in value and command[0] == "wg" for command, value in ns.inputs)
    asyncio.run(ns.network.deactivate())
    assert ns.guard_exists and not ns.exists
    assert not any(command[:2] == ("sysctl", "-w") for command in ns.commands)


@pytest.mark.parametrize("problem", ["collision", "foreign", "stale", "forwarding"])
def test_failure_before_interface_mutation(problem):
    ns = Namespace()
    ns.exists = problem == "collision"
    ns.guard_exists = problem == "foreign"
    ns.foreign = problem == "foreign"
    ns.bad_observation = problem == "stale"
    ns.forwarding = "0" if problem == "forwarding" else "1"
    with pytest.raises(ContainerLifecycleError):
        asyncio.run(ns.network.activate())
    assert not any(command[:3] == ("ip", "link", "add") for command in ns.commands)
    if problem in ("collision", "foreign", "forwarding"):
        assert not any(command[0] == "guard" for command in ns.commands)


def test_failed_secret_configuration_keeps_guard_and_cleans_owned_interface():
    ns = Namespace()
    ns.fail_setconf = True
    with pytest.raises(ContainerLifecycleError) as error:
        asyncio.run(ns.network.activate())
    assert KEY not in str(error.value)
    assert ns.guard_exists and not ns.exists


class Worker:
    def __init__(self, crash=False, ignore_term=False):
        self.returncode = 1 if crash else None
        self.finished = asyncio.Event()
        if crash:
            self.finished.set()
        self.ignore_term = ignore_term
        self.killed = False

    async def wait(self):
        await self.finished.wait()
        return self.returncode

    def terminate(self):
        if not self.ignore_term:
            self.returncode = 0
            self.finished.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.finished.set()


def test_worker_crashes_bounded_budget_preserves_guard():
    ns = Namespace()
    workers = []

    async def spawn():
        worker = Worker(crash=True)
        workers.append(worker)
        return worker

    supervisor = ContainerSupervisor(ns.network, spawn, restart_budget=2)
    assert asyncio.run(supervisor.run(install_signals=False)) == 1
    assert len(workers) == 3 and ns.guard_exists and not ns.exists


def test_signal_stop_kills_unresponsive_worker_and_reaps():
    ns = Namespace()
    workers = []

    async def scenario():
        async def spawn():
            worker = Worker(ignore_term=True)
            workers.append(worker)
            asyncio.get_running_loop().call_soon(supervisor.request_stop)
            return worker

        supervisor = ContainerSupervisor(ns.network, spawn, stop_timeout=0.01)
        return await supervisor.run(install_signals=False)

    assert asyncio.run(scenario()) == 0
    assert workers[0].killed and workers[0].returncode == -9
    assert not ns.exists and ns.guard_exists


def test_interface_recreation_rearms_and_reobserves():
    ns = Namespace()

    async def scenario():
        await ns.network.activate()
        await ns.network.deactivate()
        await ns.network.activate()
        assert await ns.network.observe()
        await ns.network.deactivate()

    asyncio.run(scenario())
    assert sum(command == ("guard", "wg-office") for command in ns.commands) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("interface", None),
        ("private_key", []),
        ("address", 123),
        ("listen_port", True),
        ("keepalive", -1),
        ("allowed_ips", "0.0.0.0/0"),
    ],
)
def test_typed_invalid_configuration_is_fixed_error(field, value):
    from dataclasses import replace

    with pytest.raises(ContainerLifecycleError) as error:
        replace(config(), **{field: value}).validated()
    assert KEY not in repr(error.value)


def test_missing_symlink_or_readable_secret_config_rejected(tmp_path):
    path = tmp_path / "wg-office.conf"
    with pytest.raises(ContainerLifecycleError):
        IngressConfig.from_file(path)
    path.write_text("PrivateKey = " + KEY)
    with pytest.raises(ContainerLifecycleError):
        IngressConfig.from_file(path)
    target = tmp_path / "target"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(ContainerLifecycleError):
        IngressConfig.from_file(path)


def test_command_timeout_and_stale_rpdb_never_create_interface():
    ns = Namespace()
    original = ns.run

    async def no_routes(*args, **kwargs):
        if args[:3] == ("ip", "-6", "-j"):
            return 0, "[]", ""
        return await original(*args, **kwargs)

    ns.network.runner = no_routes
    with pytest.raises(ContainerLifecycleError, match="guard_unproven"):
        asyncio.run(ns.network.activate())
    assert not ns.exists

    async def timeout(*args, **kwargs):
        return 124, "", KEY

    ns.network.runner = timeout
    with pytest.raises(ContainerLifecycleError) as error:
        asyncio.run(ns.network.activate())
    assert KEY not in str(error.value)
    assert not ns.exists


def test_supervisor_worker_start_failure_closes_ingress_guard_retained():
    ns = Namespace()

    async def broken_worker():
        raise RuntimeError("synthetic-worker-start-failure")

    supervisor = ContainerSupervisor(ns.network, broken_worker)
    with pytest.raises(RuntimeError, match="synthetic-worker"):
        asyncio.run(supervisor.run(install_signals=False))
    assert ns.guard_exists and not ns.exists


def test_supervisor_cancellation_closes_ingress_and_reaps_worker():
    ns = Namespace()
    workers = []

    async def scenario():
        started = asyncio.Event()

        async def spawn():
            worker = Worker()
            workers.append(worker)
            started.set()
            return worker

        supervisor = ContainerSupervisor(ns.network, spawn)
        task = asyncio.create_task(supervisor.run(install_signals=False))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert workers[0].returncode == 0 and not ns.exists and ns.guard_exists


def test_fifo_configuration_rejected_without_waiting_for_writer(tmp_path):
    import os
    import subprocess
    import sys

    fifo = tmp_path / "wg-office.conf"
    os.mkfifo(fifo, 0o600)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; from exitlane.container_runtime import IngressConfig,ContainerLifecycleError\ntry: IngressConfig.from_file(Path(sys.argv[1]))\nexcept ContainerLifecycleError as e: print(e.code)\n",
            str(fifo),
        ],
        capture_output=True,
        text=True,
        timeout=2,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "container_ingress_config_invalid"


@pytest.mark.parametrize("failure", [TimeoutError, asyncio.CancelledError])
def test_uncertain_creation_keeps_guard_no_name_cleanup_retry_or_worker(failure):
    ns = Namespace()
    original = ns.run
    workers = []

    async def uncertain(*args, **kwargs):
        result = await original(*args, **kwargs)
        if args[:3] == ("ip", "link", "add"):
            raise failure()
        return result

    async def spawn():
        workers.append(True)
        return Worker()

    ns.network.runner = uncertain
    supervisor = ContainerSupervisor(ns.network, spawn)
    with pytest.raises(ContainerLifecycleError, match="creation_uncertain"):
        asyncio.run(supervisor.run(install_signals=False))
    assert ns.exists and ns.guard_exists and ns.network.uncertain_creation
    assert not workers
    assert not any(command[:3] == ("ip", "link", "delete") for command in ns.commands)
    before = len(ns.commands)
    with pytest.raises(ContainerLifecycleError, match="creation_uncertain"):
        asyncio.run(ns.network.activate())
    assert len(ns.commands) == before


def test_recreated_interface_with_changed_ifindex_not_deleted():
    ns = Namespace()
    asyncio.run(ns.network.activate())
    ns.ifindex += 1
    with pytest.raises(ContainerLifecycleError, match="ownership_changed"):
        asyncio.run(ns.network.deactivate())
    assert ns.exists and ns.guard_exists
    assert not any(command[:3] == ("ip", "link", "delete") for command in ns.commands)


# Captured from the NET_ADMIN-only appliance on Debian 13 / nftables 1.1.3.
# Independent kernel output: do not derive this receipt from the renderer.
KERNEL_BLOCK_GUARD = r'''
{
  "nftables": [
    {
      "table": {
        "family": "inet",
        "name": "exitlane_container_guard",
        "handle": 3
      }
    },
    {
      "chain": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "name": "forward",
        "handle": 1,
        "type": "filter",
        "hook": "forward",
        "prio": -200,
        "policy": "accept"
      }
    },
    {
      "chain": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "name": "input",
        "handle": 2,
        "type": "filter",
        "hook": "input",
        "prio": -200,
        "policy": "accept"
      }
    },
    {
      "rule": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "chain": "forward",
        "handle": 3,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {
                "meta": {
                  "key": "iifname"
                }
              },
              "right": "wg-office"
            }
          },
          {
            "drop": null
          }
        ]
      }
    },
    {
      "rule": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "chain": "forward",
        "handle": 4,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "ip",
                  "field": "saddr"
                }
              },
              "right": {
                "prefix": {
                  "addr": "10.77.0.0",
                  "len": 24
                }
              }
            }
          },
          {
            "drop": null
          }
        ]
      }
    },
    {
      "rule": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "chain": "input",
        "handle": 5,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {
                "meta": {
                  "key": "iifname"
                }
              },
              "right": "wg-office"
            }
          },
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "udp",
                  "field": "dport"
                }
              },
              "right": 53
            }
          },
          {
            "drop": null
          }
        ]
      }
    },
    {
      "rule": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "chain": "input",
        "handle": 6,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {
                "meta": {
                  "key": "iifname"
                }
              },
              "right": "wg-office"
            }
          },
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "tcp",
                  "field": "dport"
                }
              },
              "right": 53
            }
          },
          {
            "drop": null
          }
        ]
      }
    },
    {
      "rule": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "chain": "input",
        "handle": 7,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "ip",
                  "field": "saddr"
                }
              },
              "right": {
                "prefix": {
                  "addr": "10.77.0.0",
                  "len": 24
                }
              }
            }
          },
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "udp",
                  "field": "dport"
                }
              },
              "right": 53
            }
          },
          {
            "drop": null
          }
        ]
      }
    },
    {
      "rule": {
        "family": "inet",
        "table": "exitlane_container_guard",
        "chain": "input",
        "handle": 8,
        "expr": [
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "ip",
                  "field": "saddr"
                }
              },
              "right": {
                "prefix": {
                  "addr": "10.77.0.0",
                  "len": 24
                }
              }
            }
          },
          {
            "match": {
              "op": "==",
              "left": {
                "payload": {
                  "protocol": "tcp",
                  "field": "dport"
                }
              },
              "right": 53
            }
          },
          {
            "drop": null
          }
        ]
      }
    }
  ]
}
'''


def kernel_guard_network():
    return ContainerWireGuardLifecycle(
        IngressConfig("wg-office", "10.77.0.1/24", KEY, KEY, "10.77.0.2/32", 51821)
    )


def kernel_guard_receipt():
    # The captured INPUT canonical form plus the new mandatory OUTPUT chain.
    data = json.loads(KERNEL_BLOCK_GUARD)
    data["nftables"].append({"chain": {"family": "inet", "table": TABLE, "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": "accept"}})
    return data


def test_actual_nft_113_block_guard_readback():
    network = kernel_guard_network()
    with pytest.raises(ContainerLifecycleError, match="guard_unproven"):
        network.validate_nft_guard(json.loads(KERNEL_BLOCK_GUARD))
    network.validate_nft_guard(kernel_guard_receipt())
    payload = network.guard_payload(None)
    assert "meta l4proto" not in payload
    assert 'iifname "wg-office" udp dport 53 drop' in payload
    assert "ip saddr 10.77.0.0/24 tcp dport 53 drop" in payload


@pytest.mark.parametrize("tamper", ["protocol", "port", "missing_port", "accept", "extra_rule", "selector", "order"])
def test_kernel_dns_guard_semantic_changes_refused(tamper):
    data = kernel_guard_receipt()
    rules = [item["rule"] for item in data["nftables"] if "rule" in item and item["rule"]["chain"] == "input"]
    expr = rules[0]["expr"]
    if tamper == "protocol":
        expr[1]["match"]["left"]["payload"]["protocol"] = "tcp"
    elif tamper == "port":
        expr[1]["match"]["right"] = 54
    elif tamper == "missing_port":
        expr.pop(1)
    elif tamper == "accept":
        expr[-1] = {"accept": None}
    elif tamper == "extra_rule":
        data["nftables"].append({"rule": rules[0]})
    elif tamper == "selector":
        expr[0]["match"]["right"] = "eth0"
    else:
        expr.reverse()
    with pytest.raises(ContainerLifecycleError, match="^container_guard_unproven$"):
        kernel_guard_network().validate_nft_guard(data)


def historical_source_receipt(*, permit=True):
    data = kernel_guard_receipt()
    selector = {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.64.0.2"}}
    expressions = []
    if permit:
        expressions.append([selector, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-mullvad"}}, {"accept": None}])
    expressions.append([selector, {"drop": None}])
    for expr in expressions:
        data["nftables"].append({"rule": {"family": "inet", "table": TABLE, "chain": "output", "expr": expr}})
    return data


def test_exact_historical_sources_recovered_then_blocked():
    network = kernel_guard_network()
    receipt = historical_source_receipt()
    network.validate_previous_policy(receipt)
    assert network.source_addresses == ("10.64.0.2",)
    assert network.probe_interface is None
    payload = network.guard_payload(None)
    assert "ip saddr 10.64.0.2 drop" in payload
    assert "oifname" not in payload
    network.validate_nft_guard(historical_source_receipt(permit=False))


@pytest.mark.parametrize("tamper", ["eth0", "lo", "port", "wildcard", "prefix", "multicast", "loopback", "verdict", "priority", "missing_drop", "extra_rule"])
def test_historical_output_inventory_cannot_adopt_weakened_guard(tamper):
    data = historical_source_receipt()
    output = [o["rule"] for o in data["nftables"] if "rule" in o and o["rule"]["chain"] == "output"]
    if tamper in ("eth0", "lo"):
        output[0]["expr"][1]["match"]["right"] = tamper
    elif tamper == "port":
        output[-1]["expr"].insert(1, {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 53}})
    elif tamper in ("wildcard", "prefix", "multicast", "loopback"):
        replacement = {"wildcard": "10.*", "prefix": {"prefix": {"addr": "10.64.0.0", "len": 24}}, "multicast": "224.0.0.1", "loopback": "127.0.0.1"}[tamper]
        for rule in output:
            rule["expr"][0]["match"]["right"] = replacement
    elif tamper == "verdict":
        output[-1]["expr"][-1] = {"accept": None}
    elif tamper == "priority":
        next(o["chain"] for o in data["nftables"] if "chain" in o and o["chain"]["name"] == "output")["prio"] = -200
    elif tamper == "missing_drop":
        data["nftables"] = [o for o in data["nftables"] if o.get("rule") is not output[-1]]
    else:
        data["nftables"].append({"rule": output[-1]})
    with pytest.raises(ContainerLifecycleError, match="^container_guard_resource_conflict$"):
        kernel_guard_network().validate_previous_policy(data)


def test_source_inventory_overflow_never_evicts_protection():
    from types import SimpleNamespace
    ns = Namespace()
    asyncio.run(ns.network.activate())
    ns.network.source_addresses = tuple(f"10.99.0.{i}" for i in range(1, 65))
    before = tuple(ns.network.source_addresses)
    commands = len(ns.commands)
    with pytest.raises(ContainerLifecycleError, match="source_budget_exhausted"):
        asyncio.run(ns.network.register_source(SimpleNamespace(address="10.99.1.1/32", interface="wg-pia")))
    assert ns.network.source_addresses == before
    assert len(ns.commands) == commands


def test_startup_retains_previous_namespace_source_guard_inventory():
    ns = Namespace()
    ns.network = kernel_guard_network()
    ns.network.runner = ns.run
    ns.network.provider_guard = FakeGuard(ns.commands)
    ns.guard_exists = True
    receipt = historical_source_receipt()
    original = ns.run
    replaced = False

    async def kernel_snapshot(*args, **kwargs):
        nonlocal replaced
        if args[:3] == ("nft", "-j", "list") and args[-1] == TABLE and not replaced:
            return 0, json.dumps(receipt), ""
        if args[:3] == ("nft", "-f", "/dev/stdin"):
            replaced = True
        return await original(*args, **kwargs)

    ns.network.runner = kernel_snapshot
    asyncio.run(ns.network.arm_guard())
    assert replaced
    assert ns.network.source_addresses == ("10.64.0.2",)
    assert ns.network.probe_interface is None
    assert "ip saddr 10.64.0.2 drop" in ns.inputs[-1][1]
    assert "oifname" not in ns.inputs[-1][1]
