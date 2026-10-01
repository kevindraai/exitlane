"""Real provider API contracts; fake transport only, no lifecycle factory patch."""

import base64
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/qualification"))
spec = importlib.util.spec_from_file_location(
    "container_host_providers", ROOT / "scripts/qualification/container_host_providers.py"
)
providers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(providers)
IDENTIFIER = "0b0dcc00-ff11-4333-aaaa-012345678901"
PRIVATE = base64.b64encode(b"synthetic-proton-private-fixture".ljust(32, b"!")).decode()
PUBLIC = base64.b64encode(bytes(range(32))).decode()
PEER_PUBLIC = base64.b64encode(bytes(range(32, 64))).decode()
PROFILE_ID = "a" * 24


class MemoryReceipts:
    def __init__(self):
        self.values = {}

    def write(self, name, value):
        self.values[name] = json.loads(json.dumps(value))
        return {"filename": name, "sha256": "b" * 64}


class FakeHarness:
    def __init__(self):
        self.config = {"run_id": IDENTIFIER}
        self.container = "owned-container"
        self.peer = object()
        self.active = "mullvad"
        self.connected = True
        self.commands = []
        self.api_calls = []
        self.pressure = []
        self.last_packet_evidence = None
        self.fail_action = None
        self.authenticated = True
        self.wrong_topology = False
        self.fail_blocked_proof = False
        self.registry_extra = False
        self.pre_operation_delivery = []

    def assert_disposable(self):
        pass

    def assert_owned(self, kind, name):
        assert kind == "container" and name == self.container

    def api(self, path, *, method, body, timeout):
        assert timeout == 90
        self.api_calls.append((path, method, body))
        if path == "/api/auth/session":
            return {"status": 200, "body": {"authenticated": self.authenticated}}
        if path.endswith("/authenticate"):
            assert path == "/api/vpn/providers/pia/authenticate" and set(body) == {
                "username",
                "password",
            }
            return {"status": 200, "body": {"ok": True}}
        if path == "/api/vpn/providers/proton/profiles":
            return {
                "status": 200,
                "body": {
                    "ok": True,
                    "profile": {"id": PROFILE_ID, "endpoint": "192.0.0.9", "port": 51820},
                },
            }
        if path == "/api/vpn/providers":
            return {
                "status": 200,
                "body": {
                    "active_provider_id": self.active,
                    "providers": [
                        {
                            "id": name,
                            "status": {"connected": self.connected and name == self.active},
                        }
                        for name in [
                            *providers.DIRECT,
                            *(["nordvpn"] if self.registry_extra else []),
                        ]
                    ],
                },
            }
        provider, action = path.split("/")[-2:]
        if action == "status":
            return {
                "status": 200,
                "body": {
                    "provider": {"id": provider, "active": provider == self.active},
                    "status": {
                        "connected": self.connected,
                        "is_active": provider == self.active,
                        "tunnel_interface": providers.DIRECT[provider][0]
                        if self.connected
                        else None,
                        "latency_endpoint": "192.0.0.9",
                    },
                },
            }
        if self.fail_action == action:
            return {
                "status": 200,
                "body": {"ok": False, "success": False, "error": "unknown-" + PRIVATE},
            }
        if action == "activate":
            self.active = provider
            return {"status": 200, "body": {"ok": True, "active_provider_id": provider}}
        assert provider == self.active
        self.connected = action == "connect"
        return {"status": 200, "body": {"ok": True, "success": True}}

    def command(self, host, arguments, *, data):
        assert host is self.peer
        self.commands.append((arguments, data))
        if arguments == ["wg", "genkey"]:
            output = PRIVATE + "\n"
        elif arguments == ["wg", "pubkey"]:
            assert data == PRIVATE + "\n"
            output = PUBLIC + "\n"
        elif arguments[-1] == "status":
            assert json.loads(data) == {"run_id": IDENTIFIER}
            output = json.dumps(
                {
                    "run_id": IDENTIFIER,
                    "names": {},
                    "links": {},
                    "peers": {
                        role: {"endpoint": endpoint, "public_key": PEER_PUBLIC, "port": 51820}
                        for role, endpoint in providers.ENDPOINTS.items()
                    },
                }
            )
        else:
            assert arguments == ["/usr/bin/python3", providers.PEER_SCRIPT, "proton"]
            assert json.loads(data) == {"run_id": IDENTIFIER, "public_key": PUBLIC, "peer": "a"}
            output = '{"registered":true}'
        return {"code": 0, "stdout": output}

    def docker(self, *arguments):
        interface, address = providers.DIRECT[self.active]
        if "address" in arguments:
            return {
                "stdout": json.dumps(
                    [{"addr_info": [{"family": "inet", "local": address, "prefixlen": 32}]}]
                )
            }
        assert arguments == ("exec", self.container, "wg", "show", interface, "endpoints")
        endpoint = "8.8.8.8" if self.wrong_topology else "192.0.0.9"
        return {"stdout": PEER_PUBLIC + "\t" + endpoint + ":51820\n"}

    def wait(self, probe, stage, timeout):
        assert timeout == 30 and stage.startswith("d6-")
        if not probe():
            raise RuntimeError("synthetic-readiness-failed-" + PRIVATE)

    def packet_phase(self, phase, captures, *, operation, blocked, require_recovery):
        self.pressure.append((phase, captures, blocked, require_recovery))
        self.last_packet_evidence = {"phase": phase, "sender": {"attempts": [1]}, "captures": {}}
        self.pre_operation_delivery.append(self.connected)
        if blocked and self.connected:
            raise RuntimeError("legitimate-pre-disconnect-provider-delivery")
        operation()
        return {
            "receipt": {"phase": phase, "accepted": not (blocked and self.fail_blocked_proof)},
            **self.last_packet_evidence,
        }


def qualification():
    h, receipts = FakeHarness(), MemoryReceipts()
    return (
        providers.ProviderQualification(h, ["continuous-seven-point-witness"], receipts=receipts),
        h,
        receipts,
    )


def test_pia_actual_credential_pair_and_connected_switch_packet_contract():
    from exitlane.providers.pia import validate_credentials

    value, h, receipts = qualification()
    assert value.authenticate_pia()["commercial_account_used"] is False
    credential = next(body for path, _method, body in h.api_calls if path.endswith("/authenticate"))
    assert validate_credentials(credential["username"], credential["password"])
    result = value.switch("pia")
    assert result["result"] == "PACKET_COMPONENT_PASS"
    assert ("/api/vpn/providers/pia/activate", "POST", None) in h.api_calls
    assert h.pressure[-1][2:] == (False, True)
    assert credential["password"] not in json.dumps(receipts.values)


def test_proton_normal_profile_production_parser_and_public_only_registration():
    from exitlane.providers.proton_profile import parse_profile

    value, h, receipts = qualification()
    before = dict(os.environ)
    result = value.import_proton(peer="a")
    imported = next(body for path, _method, body in h.api_calls if path.endswith("/profiles"))
    parsed = parse_profile(imported["config"])
    assert parsed.private_key == PRIVATE and parsed.address == "10.66.0.2/32"
    assert (
        parsed.dns_address == "10.66.0.1"
        and parsed.endpoint_host == "192.0.0.9"
        and parsed.endpoint_port == 51820
    )
    assert parsed.peer_public_key == PEER_PUBLIC
    assert set(imported) == {"config", "display_name", "country_code"}
    assert result["profile_id"] == PROFILE_ID
    registration = next(data for arguments, data in h.commands if arguments[-1] == "proton")
    assert PRIVATE not in registration
    assert PRIVATE not in str([arguments for arguments, _data in h.commands])
    assert PRIVATE not in json.dumps(receipts.values)
    assert dict(os.environ) == before
    assert value.activate("proton")["result"] == "PACKET_COMPONENT_PASS"


def test_disconnected_selection_then_target_connect_then_disconnect_are_real_api_actions():
    value, h, _receipts = qualification()
    h.connected = False
    assert value.select("pia")["result"] == "PACKET_COMPONENT_PASS"
    assert h.pressure[-1][2:] == (True, False)
    assert value.connect("pia", target="a.synthetic-a")["result"] == "PACKET_COMPONENT_PASS"
    assert ("/api/vpn/providers/pia/connect", "POST", {"target": "a.synthetic-a"}) in h.api_calls
    assert value.disconnect("pia")["result"] == "PACKET_COMPONENT_PASS"
    assert ("/api/vpn/providers/pia/disconnect", "POST", None) in h.api_calls
    assert h.pressure[-1][2:] == (True, False)
    assert h.pressure[-2][2:] == (False, False)
    phases = [phase for phase, _captures, _blocked, _recovery in h.pressure]
    assert len(set(phases)) == len(phases) and all(len(phase) <= 31 for phase in phases)


def test_disconnect_allows_prior_provider_delivery_then_requires_strict_blocked_epoch():
    value, h, receipts = qualification()
    result = value.disconnect("mullvad")
    assert h.pre_operation_delivery == [True, False]
    assert [pressure[2:] for pressure in h.pressure] == [(False, False), (True, False)]
    assert result["phase"] != result["blocked_phase"]
    assert result["packets"]["filename"] != result["blocked_packets"]["filename"]
    assert len([path for path, method, _body in h.api_calls if method == "POST"]) == 1
    assert receipts.values[result["blocked_packets"]["filename"]]["receipt"]["accepted"] is True


def test_disconnect_transition_success_without_blocked_proof_cannot_pass_or_repeat_mutation():
    value, h, receipts = qualification()
    h.fail_blocked_proof = True
    with pytest.raises(providers.ProviderEvidenceError, match="provider_packet_stage_failed"):
        value.disconnect("mullvad")
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")][
        -1
    ]
    assert metadata["result"] == "FAILED" and metadata["packets"]
    assert "blocked_packets" not in metadata and metadata["failed_packets"]
    assert not any(
        data.get("result") == "PACKET_COMPONENT_PASS" for data in receipts.values.values()
    )
    assert len([path for path, method, _body in h.api_calls if method == "POST"]) == 1


def test_nord_inventory_cannot_be_accepted_as_container_provider_boundary():
    value, h, _receipts = qualification()
    h.registry_extra = True
    with pytest.raises(providers.ProviderEvidenceError, match="provider_registry_boundary_invalid"):
        value._selected("mullvad", True)


def test_actual_registry_filters_nord_and_denies_access_via_runtime_capability():
    from exitlane.providers.catalog import provider_registry
    from exitlane.providers.registry import ProviderRegistry
    from exitlane.runtime import RuntimeCapabilities, RuntimeCapabilityUnavailable

    capabilities = RuntimeCapabilities(
        providers=("mullvad", "pia", "proton"), runtime_name="container"
    )
    registry = ProviderRegistry(
        provider_registry.all(), default_id="mullvad", capabilities=lambda: capabilities
    )
    assert {item.id for item in registry.all()} == set(providers.DIRECT)
    with pytest.raises(RuntimeCapabilityUnavailable, match="runtime_capability_unavailable"):
        registry.get("nordvpn")


@pytest.mark.parametrize("action", ["activate", "connect", "disconnect"])
def test_failed_api_operation_cannot_be_packet_pass_or_retried(action):
    value, h, receipts = qualification()
    h.fail_action = action
    with pytest.raises(
        providers.ProviderEvidenceError, match="provider_packet_stage_failed"
    ) as error:
        getattr(value, action)("mullvad")
    assert PRIVATE not in str(error.value)
    assert len([path for path, method, _body in h.api_calls if method == "POST"]) == 1
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")]
    assert metadata[-1]["result"] == "FAILED"
    assert any(name.endswith("-failed-packets.json") for name in receipts.values)
    assert PRIVATE not in json.dumps(receipts.values)


def test_wrong_public_endpoint_topology_prevents_pass_even_when_api_succeeds():
    value, h, receipts = qualification()
    h.wrong_topology = True
    with pytest.raises(providers.ProviderEvidenceError):
        value.switch("pia")
    assert not any(
        data.get("result") == "PACKET_COMPONENT_PASS" for data in receipts.values.values()
    )


def test_no_provider_mutation_without_authenticated_appliance():
    value, h, _receipts = qualification()
    h.authenticated = False
    with pytest.raises(providers.ProviderEvidenceError, match="provider_authentication_required"):
        value.authenticate_pia()
    assert not h.commands and not h.pressure
    assert not any(method == "POST" for _path, method, _body in h.api_calls)


def test_foreign_peer_and_arbitrary_target_fail_before_mutation():
    value, h, _receipts = qualification()
    with pytest.raises(providers.ProviderEvidenceError, match="peer_invalid"):
        value.import_proton(peer="foreign")
    with pytest.raises(providers.ProviderEvidenceError, match="target_invalid"):
        value.connect("pia", target="; arbitrary shell")
    assert h.commands == []
    assert not any(method == "POST" for _path, method, _body in h.api_calls)


def test_module_has_no_runtime_or_provider_factory_patch():
    source = (ROOT / "scripts/qualification/container_host_providers.py").read_text()
    assert "api_factory =" not in source and ".wireguard =" not in source
    assert "sitecustomize" not in source and "setenv" not in source
