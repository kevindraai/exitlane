"""Parent ingress ownership and sole-live-worker policy boundaries."""

import asyncio
import base64
import json
from types import SimpleNamespace

import pytest
from test_container_runtime import Namespace

from exitlane.container_entrypoint import ContainerController, ContainerEntrypoint, EntrypointError
from exitlane.container_runtime import ContainerLifecycleError
from exitlane.providers.wireguard_keys import _public_key_for_private
from exitlane.services.provider_wireguard import EgressConfig


def test_already_guarded_activation_does_not_reset_worker_proof():
    ns = Namespace()
    ns.guard_exists = True
    network = ns.network
    candidate, proof, committed = object(), object(), object()
    network.policy_epoch = 72
    network.policy_candidate, network.policy_proof, network.policy_committed = (
        candidate,
        proof,
        committed,
    )
    asyncio.run(network.activate_already_guarded(network.observe_guard))
    assert network.active
    assert network.policy_epoch == 72
    assert network.policy_candidate is candidate
    assert network.policy_proof is proof
    assert network.policy_committed is committed
    assert not any(
        command[0] in {"guard"} or command[:2] == ("nft", "-f") for command in ns.commands
    )


def test_already_guarded_activation_fails_before_creation_on_unproven_guard():
    ns = Namespace()

    async def refuse():
        raise ContainerLifecycleError("container_guard_unproven")

    with pytest.raises(ContainerLifecycleError, match="guard_unproven"):
        asyncio.run(ns.network.activate_already_guarded(refuse))
    assert not ns.exists


def test_parent_owned_ifindex_observation_has_no_policy_cache_dependency():
    ns = Namespace()
    asyncio.run(ns.network.activate())
    ns.bad_observation = True
    assert asyncio.run(ns.network.observe_owned_ingress()) is True
    ns.ifindex += 1
    with pytest.raises(ContainerLifecycleError, match="ownership_changed"):
        asyncio.run(ns.network.observe_owned_ingress())


class Maintenance:
    def __init__(self):
        self.identities = ()
        self.active = True
        self.calls = []

    async def observed(self, identities):
        self.calls.append(("observed", identities))

    async def arm(self, identities):
        self.identities = identities
        self.calls.append(("arm", identities))

    async def release(self):
        self.calls.append(("release",))


def test_first_run_controller_has_no_fabricated_ingress():
    maintenance = Maintenance()
    controller = ContainerController(SimpleNamespace(), maintenance)
    assert controller.network is None
    asyncio.run(controller.observe_policy())
    assert maintenance.calls == [("observed", ())]


@pytest.mark.parametrize("phase", ["fresh_initialization", "interrupted_publication"])
def test_empty_namespace_reset_does_not_read_unpublished_pair(phase):
    calls = []

    async def absent(*argv, **kwargs):
        calls.append(argv)
        return 1, "", ""

    def unpublished():
        pytest.fail("reset must not inspect the unpublished pair: " + phase)

    state = SimpleNamespace(validate=unpublished)
    maintenance = Maintenance()
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.state = state
    entry.controller = ContainerController(state, maintenance, runner=absent)
    asyncio.run(entry.reset())
    assert [command[-1] for command in calls] == ["wg-mullvad", "wg-pia", "wg-proton"]
    assert maintenance.calls == [("observed", ())]


def test_ingress_revoked_lease_refuses_before_file_or_network_access():
    controller = ContainerController(SimpleNamespace(), Maintenance(), operation_valid=lambda: False)
    with pytest.raises(EntrypointError, match="lease_revoked"):
        asyncio.run(controller.ingress({"action": "activate", "interface": "wg-office"}))


def test_new_namespace_reset_observes_persisted_ingress_maintenance_selectors():
    from exitlane.container_recovery import IngressIdentity

    maintenance = Maintenance()
    maintenance.identities = (IngressIdentity("wg-office", "10.77.0.0/24"),)
    controller = ContainerController(SimpleNamespace(), maintenance)
    asyncio.run(controller.reset_policy())
    assert maintenance.calls == [("observed", maintenance.identities)]


def test_ingress_observe_cannot_release_maintenance_after_lease_revocation(monkeypatch, tmp_path):
    from exitlane.container_runtime import IngressConfig

    ns = Namespace()
    valid = True
    maintenance = Maintenance()
    controller = ContainerController(
        SimpleNamespace(layout=SimpleNamespace(wireguard=tmp_path)), maintenance,
        operation_valid=lambda: valid,
    )
    controller.network = ns.network
    monkeypatch.setattr(IngressConfig, "from_file", lambda _path: ns.network.config)

    async def observed(**kwargs):
        nonlocal valid
        valid = False

    async def owned():
        return True

    monkeypatch.setattr(controller, "observe_policy", observed)
    monkeypatch.setattr(ns.network, "observe_owned_ingress", owned)
    with pytest.raises(EntrypointError, match="lease_revoked"):
        asyncio.run(controller.ingress({"action": "observe", "interface": ns.network.config.interface}))
    assert ("release",) not in maintenance.calls


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"action": "shell", "interface": "wg-office"},
        {"action": "activate", "interface": "../host"},
        {"action": "activate", "interface": "wg-office", "config": "secret"},
    ],
)
def test_ingress_rpc_rejects_raw_config_and_hostile_names(payload):
    controller = ContainerController(SimpleNamespace(), Maintenance())
    with pytest.raises(EntrypointError, match="config_invalid"):
        asyncio.run(controller.ingress(payload))


def provider_config():
    key = base64.b64encode(bytes(range(32))).decode()
    peer = base64.b64encode(bytes(range(1, 33))).decode()
    return EgressConfig(
        "mullvad",
        "synthetic-generation",
        "wg-mullvad",
        key,
        "10.64.0.2/32",
        peer,
        "192.0.0.9",
        "10.64.0.1",
    )


@pytest.mark.parametrize("mismatch", [None, "public", "peer", "address", "index", "kind"])
def test_reset_removes_only_generation_proven_provider_interface(mismatch):
    config = provider_config()
    calls = []
    reads = 0

    async def runner(*argv, **_kwargs):
        nonlocal reads
        calls.append(argv)
        if argv[:5] == ("ip", "-j", "-d", "link", "show"):
            if argv[-1] != "wg-mullvad":
                return 1, "", ""
            return (
                0,
                json.dumps(
                    [
                        {
                            "ifname": "wg-mullvad",
                            "ifindex": 7,
                            "linkinfo": {
                                "info_kind": "dummy" if mismatch == "kind" else "wireguard"
                            },
                        }
                    ]
                ),
                "",
            )
        if argv[:3] == ("wg", "show", "wg-mullvad"):
            output = {
                "public-key": _public_key_for_private(config.private_key),
                "peers": config.peer_public_key,
                "endpoints": f"{config.peer_public_key}\t{config.endpoint_address}:51820",
            }[argv[-1]]
            if mismatch == "public" and argv[-1] == "public-key":
                output = config.peer_public_key
            if mismatch == "peer" and argv[-1] == "peers":
                output = "synthetic-other-peer"
            return 0, output, ""
        if argv[:4] == ("ip", "-4", "-j", "address"):
            return (
                0,
                json.dumps(
                    [
                        {
                            "addr_info": [
                                {
                                    "family": "inet",
                                    "prefixlen": 32,
                                    "local": "10.64.0.3" if mismatch == "address" else "10.64.0.2",
                                }
                            ]
                        }
                    ]
                ),
                "",
            )
        if argv[:4] == ("ip", "-j", "link", "show"):
            reads += 1
            return 0, json.dumps([{"ifindex": 8 if mismatch == "index" else 7}]), ""
        return 0, "", ""

    state = SimpleNamespace(
        validate=lambda: SimpleNamespace(intents=(SimpleNamespace(config=config),))
    )
    controller = ContainerController(state, Maintenance(), runner=runner)
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.controller, entry.state = controller, state
    if mismatch:
        with pytest.raises(EntrypointError):
            asyncio.run(entry.reset())
        assert not any(command[:3] == ("ip", "link", "delete") for command in calls)
    else:
        asyncio.run(entry.reset())
        assert ("ip", "link", "delete", "dev", "wg-mullvad") in calls
    assert config.private_key not in str(calls)


def test_reopen_preserves_worker_policy_and_releases_only_maintenance():
    calls = []

    class Controller:
        async def observe_policy(self):
            calls.append("observe")

        network = SimpleNamespace()

    controller = Controller()

    async def observe_ingress():
        calls.append("ifindex")
        return True

    controller.network.observe_owned_ingress = observe_ingress
    entry = ContainerEntrypoint.__new__(ContainerEntrypoint)
    entry.controller, entry.maintenance = controller, Maintenance()
    entry.supervisor = SimpleNamespace(maintenance=True)
    asyncio.run(entry.reopen())
    assert calls == ["observe", "ifindex"]
    assert entry.maintenance.calls == [("release",)]
    assert entry.ready is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("uid", 1000),
        ("capabilities", (1 << 12) | (1 << 21)),
        ("capabilities", 0),
        ("no_new_privileges", 0),
        ("root_readonly", False),
        ("data_mount", False),
        ("run_private", False),
        ("tmp_private", False),
        ("tun", False),
        ("tools", False),
        ("ipv4_forwarding", "0"),
        ("ipv6_forwarding", "1"),
        ("ping_group_range", "0 2147483647"),
        ("runtime", "native"),
    ],
)
def test_production_preflight_rejects_privilege_and_image_contract_mismatch(field, value):
    from exitlane.container_entrypoint import _validate_preflight

    facts = {
        "uid": 0,
        "capabilities": 1 << 12,
        "no_new_privileges": 1,
        "ipv4_forwarding": "1",
        "ipv6_forwarding": "0",
        "ping_group_range": "0 0",
        "tun": True,
        "tools": True,
        "root_readonly": True,
        "data_mount": True,
        "run_private": True,
        "tmp_private": True,
        "runtime": "container",
    }
    _validate_preflight(facts)
    facts[field] = value
    with pytest.raises(EntrypointError, match="container_preflight_failed"):
        _validate_preflight(facts)
