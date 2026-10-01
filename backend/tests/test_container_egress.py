"""Container proof/commit policy tests; native transactions remain shared."""

import asyncio
import json
import time
from dataclasses import replace
from unittest.mock import patch

import pytest
from test_container_runtime import Namespace
from test_provider_wireguard import PEER_KEY, PRIVATE_KEY, Runner, config

from exitlane.container_egress import ContainerWireGuardEgress
from exitlane.container_runtime import TABLE
from exitlane.services.provider_wireguard import ProviderWireGuard, ProviderWireGuardError


class PolicyNamespace(Namespace):
    def __init__(self):
        super().__init__()
        self.kernel_policy = None
        self.loaded = False
        self.fail_allow = False

    def nft(self):
        objects = []
        policy = self.kernel_policy
        groups = [
            ("forward", "filter", -200, self.network.forward_expressions(policy)),
            ("input", "filter", -200, self.network.input_expressions()),
            ("output", "filter", 0, self.network.output_expressions()),
        ]
        if policy:
            groups.append(("postrouting", "nat", 100, self.network.nat_expressions(policy)))
        for name, kind, priority, expressions in groups:
            objects.append(
                {
                    "chain": {
                        "family": "inet",
                        "table": TABLE,
                        "name": name,
                        "type": kind,
                        "hook": name,
                        "prio": priority,
                        "policy": "accept",
                    }
                }
            )
            objects.extend(
                {"rule": {"family": "inet", "table": TABLE, "chain": name, "expr": expr}}
                for expr in expressions
            )
        if self.foreign:
            next(item["rule"] for item in objects if "rule" in item)["expr"] = [{"accept": None}]
        return json.dumps({"nftables": objects})

    async def run(self, *args, **kwargs):
        if args[:3] == ("nft", "-f", "/dev/stdin"):
            payload = kwargs["input_text"]
            if "masquerade" in payload:
                if self.fail_allow:
                    return 1, "", "synthetic-allow-failure"
                import re

                self.kernel_policy = re.search(r'oifname "([^"]+)"', payload)[1]
            else:
                self.kernel_policy = None
        return await super().run(*args, **kwargs)


@pytest.fixture
def container(tmp_path):
    ns = PolicyNamespace()
    native = Runner()
    native.handshake = int(time.time())
    state = {"udp": True, "tcp": True, "pings": 0, "ping_fail": False}

    async def run(*args, **kwargs):
        if (
            args[0] in ("nft", "cat")
            or args[:3] in (("ip", "-4", "-j"), ("ip", "-6", "-j"))
            or "wg-office" in args
            and args[:2] == ("ip", "link")
            or args[:4] == ("ip", "-j", "link", "show")
        ):
            return await ns.run(*args, **kwargs)
        if args[0] == "ping":
            state["pings"] += 1
            if state["ping_fail"]:
                return 1, "", ""
        return await native(*args, timeout=kwargs["timeout"])

    async def udp(*_args):
        return state["udp"]

    async def tcp(*_args):
        return state["tcp"]

    ns.network.runner = run
    adapter = ContainerWireGuardEgress(
        ns.network, runner=run, root=tmp_path / "provider", dns_probe=udp, tcp_dns_probe=tcp
    )
    asyncio.run(ns.network.activate())
    return ns, native, state, adapter


def test_actual_shared_start_proof_then_commit_only_opens(container):
    ns, native, state, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert ns.kernel_policy is None
        assert (await adapter.probe(config()))["ready"]
        assert ns.kernel_policy is None
        await adapter.committed(config())
        assert ns.kernel_policy == "wg-mullvad"
        assert (await adapter.observe(config()))["connected"]
        await adapter.stop_interface("wg-mullvad")
        assert ns.kernel_policy is None

    asyncio.run(scenario())
    assert state["pings"] >= 4
    assert ns.guard_exists
    assert PRIVATE_KEY not in repr(native.calls)
    assert PEER_KEY not in repr(ns.commands)


@pytest.mark.parametrize(
    "failure", ["udp", "tcp", "dataplane", "handshake", "future", "wrong-peer"]
)
def test_incomplete_proof_cannot_commit(container, failure):
    ns, native, state, adapter = container
    if failure in ("udp", "tcp"):
        state[failure] = False
    elif failure == "dataplane":
        state["ping_fail"] = True
    elif failure == "handshake":
        native.handshake = 0
    elif failure == "future":
        native.handshake = int(time.time()) + 30

    async def scenario():
        candidate = config(peer_public_key=PRIVATE_KEY) if failure == "wrong-peer" else config()
        await adapter.start(candidate, ("wg-office",))
        assert (await adapter.probe(candidate))["ready"] is False
        with pytest.raises(ProviderWireGuardError, match="commit_unproven"):
            await adapter.committed(candidate)
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_observe_revokes_loss_and_never_reopens_from_late_handshake(container):
    ns, native, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert (await adapter.probe(config()))["ready"]
        await adapter.committed(config())
        native.handshake = 0
        assert (await adapter.observe(config()))["connected"] is False
        assert ns.kernel_policy is None
        native.handshake = int(time.time())
        observation = await adapter.observe(config())
        assert observation["ready"] and not observation["connected"]
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_stale_completion_cannot_open_or_replace_new_candidate(container):
    ns, _, _, adapter = container

    async def scenario():
        old = config()
        new = replace(old, generation="new-generation")
        await adapter.start(old, ("wg-office",))
        assert (await adapter.probe(old))["ready"]
        await adapter.start(new, ("wg-office",))
        assert (await adapter.probe(old))["ready"] is False
        with pytest.raises(ProviderWireGuardError):
            await adapter.committed(old)
        assert ns.kernel_policy is None
        assert (await adapter.probe(new))["ready"]
        await adapter.committed(new)
        assert ns.kernel_policy == "wg-mullvad"
        with pytest.raises(ProviderWireGuardError):
            await adapter.committed(old)
        assert ns.kernel_policy == "wg-mullvad"

    asyncio.run(scenario())


def test_failed_allow_transaction_restores_permanent_block(container):
    ns, _, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert (await adapter.probe(config()))["ready"]
        ns.fail_allow = True
        with pytest.raises(ProviderWireGuardError, match="commit_failed"):
            await adapter.committed(config())
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_rollback_requires_new_full_proof_before_reopening(container):
    ns, _, state, adapter = container

    async def scenario():
        old = config()
        await adapter.start(old, ("wg-office",))
        assert (await adapter.probe(old))["ready"]
        await adapter.committed(old)
        new = replace(old, generation="target-generation")
        await adapter.start(new, ("wg-office",))
        assert ns.kernel_policy is None
        state["tcp"] = False
        assert not (await adapter.probe(new))["ready"]
        await adapter.start(old, ("wg-office",))
        with pytest.raises(ProviderWireGuardError):
            await adapter.committed(old)
        state["tcp"] = True
        assert (await adapter.probe(old))["ready"]
        await adapter.committed(old)
        assert ns.kernel_policy == "wg-mullvad"

    asyncio.run(scenario())


def test_pending_no_provider_policy_blocks_ipv6_and_local_dns_proxy(container):
    ns, _, _, _ = container
    blocked = ns.network.guard_payload(None)
    assert 'iifname "wg-office" drop' in blocked
    assert "chain input" in blocked
    assert "udp dport 53 drop" in blocked and "tcp dport 53 drop" in blocked
    assert "ip saddr 10.88.0.0/24" in blocked
    allowed = ns.network.guard_payload("wg-pia")
    assert 'meta nfproto ipv4 oifname "wg-pia" accept' in allowed
    assert "masquerade" in allowed
    assert "nfproto ipv6" not in allowed


def test_foreign_guard_policy_refused_before_provider_mutation(container):
    ns, native, _, adapter = container
    ns.foreign = True
    count = len(native.calls)
    with pytest.raises(ProviderWireGuardError, match="guard_failed"):
        asyncio.run(adapter.start(config(), ("wg-office",)))
    assert len(native.calls) == count


def test_permanent_source_guards_are_not_removed_on_disarm(container):
    ns, native, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        await adapter.disarm(("wg-office",), "wg-mullvad")

    asyncio.run(scenario())
    assert native.source_rules
    assert not any(
        call[:4] == ("ip", "-4", "route", "del") and "unreachable" in call for call in native.calls
    )
    assert ns.guard_exists and ns.kernel_policy is None


def test_cross_adapter_instance_stale_commit_cannot_replace_new_provider(container, tmp_path):
    ns, native, _, old_adapter = container

    async def success(*_args):
        return True

    new_adapter = ContainerWireGuardEgress(
        ns.network, root=tmp_path / "new-provider", dns_probe=success, tcp_dns_probe=success
    )

    async def scenario():
        old = config()
        await old_adapter.start(old, ("wg-office",))
        assert (await old_adapter.probe(old))["ready"]
        await old_adapter.committed(old)
        await old_adapter.stop_interface(old.interface)
        native.interface_name = "wg-pia"
        new = replace(old, provider_id="pia", interface="wg-pia", generation="pia-generation")
        await new_adapter.start(new, ("wg-office",))
        assert (await new_adapter.probe(new))["ready"]
        await new_adapter.committed(new)
        with pytest.raises(ProviderWireGuardError):
            await old_adapter.committed(old)
        assert not (await old_adapter.observe(old))["connected"]
        assert ns.kernel_policy == "wg-pia"

    asyncio.run(scenario())


def test_expired_proof_cannot_commit(container):
    ns, _, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert (await adapter.probe(config()))["ready"]
        epoch, item, observed = ns.network.policy_proof
        ns.network.policy_proof = epoch, item, observed - 10
        with pytest.raises(ProviderWireGuardError, match="commit_unproven"):
            await adapter.committed(item)
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_hooked_teardown_file_never_executed(container):
    ns, native, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        path = adapter._path("wg-mullvad")
        path.write_text(path.read_text() + "\nPostDown = synthetic-hostile-hook\n")
        before = len(native.calls)
        with pytest.raises(ProviderWireGuardError, match="teardown_config_invalid"):
            await adapter.stop_interface("wg-mullvad")
        assert not any(call[:2] == ("wg-quick", "down") for call in native.calls[before:])
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_late_first_probe_failure_requires_two_complete_rounds(container):
    ns, _, _, adapter = container
    calls = []

    async def flaky_udp(*_args):
        calls.append(True)
        return len(calls) != 2

    adapter.dns_probe = flaky_udp

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert not (await adapter.probe(config()))["ready"]
        assert ns.kernel_policy is None
        assert (await adapter.probe(config()))["ready"]
        assert len(calls) == 4

    asyncio.run(scenario())


@pytest.mark.parametrize("tcp", [False, True])
@pytest.mark.parametrize("problem", [None, "wrong-id", "wrong-question", "truncated", "no-answer"])
def test_dns_probe_binds_only_provider_device_validates_real_reply(monkeypatch, tcp, problem):
    import socket
    import struct

    from exitlane.container_egress import _dns_query

    calls = []

    class DnsSocket:
        def __init__(self, family, kind):
            assert family == socket.AF_INET
            assert kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM)
            self.data = b""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, timeout):
            assert 0 < timeout <= 1

        def setsockopt(self, level, option, value):
            assert level == socket.SOL_SOCKET and option == socket.SO_BINDTODEVICE
            assert value == b"wg-mullvad\x00"
            calls.append("bound")

        def connect(self, address):
            assert address == ("10.64.0.1", 53)

        def respond(self, data):
            query = data[2:] if tcp else data
            response = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:]
            response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x01\x01\x01"
            if problem == "wrong-id":
                response = bytes((response[0] ^ 1,)) + response[1:]
            elif problem == "wrong-question":
                response = response[:13] + b"!" + response[14:]
            elif problem == "truncated":
                response = response[:-1]
            elif problem == "no-answer":
                response = response[:6] + b"\0\0" + response[8:]
            self.data = struct.pack("!H", len(response)) + response if tcp else response

        def sendall(self, data):
            self.respond(data)

        def send(self, data):
            self.respond(data)
            return len(data)

        def recv(self, size):
            chunk, self.data = self.data[:size], self.data[size:]
            return chunk

    monkeypatch.setattr(socket, "socket", DnsSocket)
    assert _dns_query("wg-mullvad", "10.64.0.1", "example.com", 1, tcp=tcp) is (problem is None)
    assert calls == ["bound"]


def test_same_interface_writer_race_serialized_and_stale_stop_refused(container, tmp_path):
    ns, _, _, old_adapter = container

    async def ready(*_args):
        return True

    other = ContainerWireGuardEgress(
        ns.network, root=tmp_path / "other", dns_probe=ready, tcp_dns_probe=ready
    )
    entered = []

    async def scenario():
        first_started = asyncio.Event()
        release = asyncio.Event()

        async def suspended_start(_self, candidate, _ingress):
            entered.append(candidate.generation)
            if len(entered) == 1:
                first_started.set()
                await release.wait()

        with patch.object(ProviderWireGuard, "start", suspended_start):
            old = config()
            new = replace(old, generation="new-same-interface")
            old_task = asyncio.create_task(old_adapter.start(old, ("wg-office",)))
            await first_started.wait()
            new_task = asyncio.create_task(other.start(new, ("wg-office",)))
            await asyncio.sleep(0)
            assert entered == [old.generation]
            assert ns.network.policy_candidate == old
            release.set()
            await asyncio.gather(old_task, new_task)
            assert entered == [old.generation, new.generation]
            assert ns.network.policy_candidate == new
            before = len(ns.commands)
            with pytest.raises(ProviderWireGuardError, match="stale_generation"):
                await old_adapter.stop_interface(old.interface)
            assert len(ns.commands) == before
            assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_cancelled_allow_mutation_reverts_kernel_before_propagation(container):
    ns, _, _, adapter = container
    original = ns.run
    cancelled = []

    async def interrupt_allow(*args, **kwargs):
        result = await original(*args, **kwargs)
        if (
            args[:3] == ("nft", "-f", "/dev/stdin")
            and "masquerade" in kwargs["input_text"]
            and not cancelled
        ):
            cancelled.append(True)
            raise asyncio.CancelledError
        return result

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert (await adapter.probe(config()))["ready"]
        ns.run = interrupt_allow
        with pytest.raises(asyncio.CancelledError):
            await adapter.committed(config())
        assert cancelled
        assert ns.kernel_policy is None
        assert ns.network.policy_committed is None
        assert ns.network.policy_proof is None

    asyncio.run(scenario())


def test_candidate_transition_facts_ready_without_connected_claim(container):
    ns, _, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert (await adapter.probe(config()))["ready"]
        facts = await adapter.transition_facts(config())
        assert facts.available and facts.protected_egress and facts.interface == "wg-mullvad"
        current = await adapter.observe(config())
        assert current["ready"] and not current["connected"]
        assert ns.kernel_policy is None
        await adapter.committed(config())
        assert (await adapter.observe(config()))["connected"]

    asyncio.run(scenario())


def test_deleted_provider_interface_revokes_open_allowance(container):
    ns, native, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        assert (await adapter.probe(config()))["ready"]
        await adapter.committed(config())
        native.interface = False
        current = await adapter.observe(config())
        assert not current["connected"] and not current["ready"]
        assert ns.kernel_policy is None

    asyncio.run(scenario())


@pytest.mark.parametrize("provider_id", ["mullvad", "pia", "proton"])
def test_actual_provider_owned_completion_configured_killswitch_uses_candidate_proof(
    container, monkeypatch, provider_id
):
    from exitlane import core
    from exitlane.providers import mullvad, pia, proton
    from exitlane.services import killswitch

    ns, native, _, adapter = container
    native.interface_name = "wg-" + provider_id
    candidate = replace(config(), provider_id=provider_id, interface=native.interface_name)
    provider = {"mullvad": mullvad.Mullvad, "pia": pia.Pia, "proton": proton.Proton}[provider_id](
        wireguard=adapter
    )
    settings = {killswitch.SETTING_CONFIGURED: True, killswitch.SETTING_TRANSITION: True}
    receipts = []
    monkeypatch.setattr(core, "setting", lambda name, default=None: settings.get(name, default))
    monkeypatch.setattr(core, "set_setting", lambda name, value: settings.__setitem__(name, value))
    monkeypatch.setattr(killswitch, "configuration", lambda: (("wg-office",), ()))

    class ReceiptBackend:
        async def apply(self, ruleset):
            receipts.append(ruleset)

        async def installed(self):
            return True

        async def remove(self):
            raise AssertionError("Configured killswitch must remain installed")

    complete = killswitch.complete_provider_transition

    async def real_completion(facts):
        return await complete(facts, backend=ReceiptBackend())

    async def disconnected_facts():
        return killswitch.TunnelFacts(False, reason="candidate_not_committed")

    monkeypatch.setattr(killswitch, "complete_provider_transition", real_completion)
    monkeypatch.setattr(provider, "network_facts", disconnected_facts)

    async def scenario():
        await adapter.start(candidate, ("wg-office",))
        assert (await adapter.probe(candidate))["ready"]
        assert not (await adapter.observe(candidate))["connected"]
        callback = (
            provider._complete_owned_transition
            if provider_id == "mullvad"
            else provider._complete_transition
        )
        assert await callback(candidate)
        assert ns.kernel_policy is None
        assert receipts and f'oifname "{candidate.interface}" accept' in receipts[-1]
        assert settings[killswitch.SETTING_TRANSITION] is False
        await adapter.committed(candidate)
        assert (await adapter.observe(candidate))["connected"]

    asyncio.run(scenario())


def test_provider_config_symlink_cannot_redirect_other_interface_teardown(container):
    ns, native, _, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        path = adapter._path("wg-mullvad")
        other = path.with_name("wg-pia.conf")
        path.rename(other)
        path.symlink_to(other)
        before = len(native.calls)
        with pytest.raises(
            ProviderWireGuardError, match="^container_provider_teardown_config_invalid$"
        ):
            await adapter.stop_interface("wg-mullvad")
        assert not any(call[:2] == ("wg-quick", "down") for call in native.calls[before:])
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_provider_source_output_guard_precedes_kernel_start_and_retains_history(container):
    ns, _, _, adapter = container

    async def scenario():
        original_runner = adapter.runner

        async def check_start(*args, **kwargs):
            if args[0] not in ("nft", "cat") and args[:3] not in (
                ("ip", "-4", "-j"),
                ("ip", "-6", "-j"),
            ):
                assert ns.network.source_addresses == ("10.67.12.34",)
                assert ns.network.probe_interface == "wg-mullvad"
            return await original_runner(*args, **kwargs)

        adapter.runner = check_start
        await adapter.start(config(), ("wg-office",))
        adapter.runner = original_runner
        assert ns.kernel_policy is None
        rules = ns.network.output_expressions()
        assert rules == [
            [
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                        "right": "10.67.12.34",
                    }
                },
                {
                    "match": {
                        "op": "==",
                        "left": {"meta": {"key": "oifname"}},
                        "right": "wg-mullvad",
                    }
                },
                {"accept": None},
            ],
            [
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                        "right": "10.67.12.34",
                    }
                },
                {"drop": None},
            ],
        ]
        assert all("dport" not in json.dumps(rule) for rule in rules)
        await adapter.stop_interface("wg-mullvad")
        assert ns.network.source_addresses == ("10.67.12.34",)
        assert ns.network.probe_interface is None
        assert ns.network.output_expressions() == [rules[-1]]
        assert ns.kernel_policy is None

    asyncio.run(scenario())


def test_probe_failure_retains_only_encrypted_candidate_output(container):
    ns, _, state, adapter = container

    async def scenario():
        await adapter.start(config(), ("wg-office",))
        state["tcp"] = False
        assert (await adapter.probe(config()))["ready"] is False
        assert ns.kernel_policy is None
        assert ns.network.probe_interface == "wg-mullvad"
        state["tcp"] = True
        assert (await adapter.observe(config()))["connected"] is False
        assert ns.kernel_policy is None
        await adapter.disarm(("wg-office",), "wg-mullvad")
        assert ns.network.probe_interface is None
        assert ns.network.source_addresses == ("10.67.12.34",)

    asyncio.run(scenario())
