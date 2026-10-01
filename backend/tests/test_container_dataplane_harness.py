"""D3 host preflight fails before resource creation without rejecting builtin networks."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "scripts/qualification"
spec = importlib.util.spec_from_file_location(
    "container_dataplane_harness", DIRECTORY / "container_dataplane.py"
)
harness = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(DIRECTORY))
try:
    spec.loader.exec_module(harness)
finally:
    sys.path.remove(str(DIRECTORY))


@pytest.fixture
def preflight(monkeypatch, tmp_path):
    instance = object.__new__(harness.DataplaneHarness)
    resolvers = tmp_path / "resolv.conf"
    resolvers.write_text("nameserver 10.200.0.53\n")
    monkeypatch.setattr(harness, "Path", lambda _path: resolvers)
    state = {"routes": [{"dst": "default"}], "networks": []}
    calls = []

    def docker(*args):
        calls.append(args)
        if args == ("network", "ls", "--quiet"):
            return SimpleNamespace(stdout="network-id" if state["networks"] else "")
        assert args == ("network", "inspect", "network-id")
        return SimpleNamespace(stdout=json.dumps(state["networks"]))

    instance.docker = docker
    monkeypatch.setattr(
        harness.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(state["routes"])),
    )
    return instance, state, calls, resolvers


def test_builtin_networks_without_ipam_are_accepted(preflight):
    instance, state, calls, _ = preflight
    state["networks"] = [
        {"Name": "host", "Driver": "host", "IPAM": {"Config": None}},
        {"Name": "none", "Driver": "null", "IPAM": {"Config": None}},
        {"Name": "bridge", "Driver": "bridge", "IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}},
    ]
    instance.preflight()
    assert all(call[1] != "create" for call in calls)


@pytest.mark.parametrize("config", [None, "invalid", [{}], [{"Subnet": None}]])
def test_unknown_or_malformed_custom_ipam_fails_closed(preflight, config):
    instance, state, calls, _ = preflight
    state["networks"] = [{"Name": "custom", "Driver": "bridge", "IPAM": {"Config": config}}]
    with pytest.raises(TypeError, match="validate existing Docker network"):
        instance.preflight()
    assert all(call[1] != "create" for call in calls)


@pytest.mark.parametrize("destination", ["1.1.1.0/24", "192.0.0.9/32", "fd88::/64", "fd99::1/128"])
def test_host_route_overlap_fails_before_creation(preflight, destination):
    instance, state, calls, _ = preflight
    state["routes"].append({"dst": destination})
    with pytest.raises(RuntimeError, match="overlaps"):
        instance.preflight()
    assert all(call[1] != "create" for call in calls)


def test_existing_docker_subnet_overlap_fails(preflight):
    instance, state, _, _ = preflight
    state["networks"] = [
        {"Name": "custom", "Driver": "bridge", "IPAM": {"Config": [{"Subnet": "192.0.0.0/24"}]}}
    ]
    with pytest.raises(RuntimeError, match="overlaps"):
        instance.preflight()


def test_host_dns_overlap_fails_before_docker_call(preflight):
    instance, _, calls, resolvers = preflight
    resolvers.write_text("nameserver 1.1.1.1\n")
    with pytest.raises(RuntimeError, match="DNS resolver"):
        instance.preflight()
    assert not calls


def test_host_stub_dns_unknown_upstream_fails_before_docker_call(preflight):
    instance, _, calls, resolvers = preflight
    resolvers.write_text("nameserver 127.0.0.53\n")
    with pytest.raises(RuntimeError, match="stub DNS upstream"):
        instance.preflight()
    assert not calls


def test_dns_control_binds_unprotected_management_source_and_omits_capture_marker():
    instance = object.__new__(harness.DataplaneHarness)
    instance.roles = {"unsafe": "owned-control"}
    commands = []

    def python(role, source, *, check):
        commands.append((role, source, check))
        return SimpleNamespace(returncode=0)

    instance.python = python
    assert instance.dns_response(
        "10.77.0.1", "udp", "proxy-control", role="unsafe", bind="192.0.0.5"
    )
    role, source, check = commands[0]
    assert role == "owned-control" and check is False
    assert "s.bind(('192.0.0.5',0))" in source
    assert "synthetic-control.invalid" in source
    assert "eld3-" not in source
    compile(source, "synthetic-dns-control", "exec")


def test_existing_docker_ipv6_subnet_overlap_fails(preflight):
    instance, state, _, _ = preflight
    state["networks"] = [
        {"Name": "custom", "Driver": "bridge", "IPAM": {"Config": [{"Subnet": "fd99::/48"}]}}
    ]
    with pytest.raises(RuntimeError, match="overlaps"):
        instance.preflight()


def test_target_dual_stack_listeners_receive_ipv4_and_ipv6_independently():
    import ast
    import socket

    tree = ast.parse(harness.TARGET)
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "listeners"
    )
    namespace = {"socket": socket}
    exec(  # noqa: S102 - execute only repository-owned listener function AST
        compile(ast.Module(body=[function], type_ignores=[]), "actual-target-listeners", "exec"),
        namespace,
    )
    udp4, udp6, tcp4 = namespace["listeners"](udp_port=0, tcp_port=0)
    try:
        assert udp6.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
        port = udp4.getsockname()[1]
        for family, destination, listener, marker in (
            (socket.AF_INET, "127.0.0.1", udp4, b"ipv4-control"),
            (socket.AF_INET6, "::1", udp6, b"ipv6-control"),
        ):
            with socket.socket(family, socket.SOCK_DGRAM) as sender:
                sender.sendto(marker, (destination, port))
            listener.settimeout(1)
            assert listener.recv(128) == marker
        with socket.create_connection(("127.0.0.1", tcp4.getsockname()[1]), timeout=1):
            tcp4.settimeout(1)
            accepted, _ = tcp4.accept()
            accepted.close()
    finally:
        for listener in (udp4, udp6, tcp4):
            listener.close()


def test_fixture_canonical_settings_satisfy_real_management_routing(monkeypatch):
    import ast
    import ipaddress

    from exitlane.services import killswitch, management_routing

    source = (DIRECTORY / "container_dataplane_fixture.py").read_text()
    tree = ast.parse(source)
    settings_call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "core"
        and node.func.attr == "set_settings"
    )
    instance = SimpleNamespace(
        network=SimpleNamespace(
            config=SimpleNamespace(interface="wg-office", address="10.77.0.1/24")
        )
    )
    settings = eval(
        compile(ast.Expression(body=settings_call.args[0]), "actual-fixture-settings", "eval"),
        {"self": instance, "ipaddress": ipaddress, "killswitch": killswitch},
    )
    monkeypatch.setattr(
        management_routing.core, "setting", lambda key, default=None: settings.get(key, default)
    )
    (destination,) = management_routing.configured_protected_destinations()
    assert str(destination.network) == "10.77.0.0/24"
    assert destination.expected_device == "wg-office"


def test_fixture_late_handshake_budget_is_bounded_and_reaches_real_command(monkeypatch):
    import asyncio

    from exitlane import core

    fixture_spec = importlib.util.spec_from_file_location(
        "d3_budget_fixture", DIRECTORY / "container_dataplane_fixture.py"
    )
    module = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(module)
    instance = object.__new__(module.Fixture)
    calls = []

    async def connect(target, *, timeout):
        calls.append((target, timeout))
        return {"ok": True}

    async def status():
        return {"ok": True}

    instance.providers = {
        provider: SimpleNamespace(connect=connect) for provider in ("mullvad", "pia", "proton")
    }
    instance.apis = {}
    instance.lock = asyncio.Lock()
    instance.status = status
    monkeypatch.setattr(core, "setting", lambda _key, default=None: "mullvad")
    assert asyncio.run(instance.command({"command": "connect", "timeout": 15}))["ok"]
    assert calls == [("nl-ams-wg-a", 15)]
    with pytest.raises(ValueError, match="invalid command"):
        asyncio.run(instance.command({"command": "connect", "timeout": 16}))
    assert len(calls) == 1


def test_local_source_probes_do_not_contaminate_client_delivery_phase():
    instance = object.__new__(harness.DataplaneHarness)
    instance.roles = {"client": "synthetic-client", "appliance": "synthetic-appliance"}
    instance.source_known = instance.pia_source_known = True
    calls = []
    instance.python = lambda *args, **kwargs: calls.append((args, kwargs))
    instance.phase("outer-switch-paused")
    assert calls[0][1]["data"] == "outer-switch-paused"
    assert len(calls) == 3
    for args, _kwargs in calls[1:]:
        assert args[0] == "synthetic-appliance"
        assert "exitlane-d3-protected-outer-switch-paused-source:" in args[1]
        assert "exitlane-d3-protected-outer-switch-paused:" not in args[1]


def test_fixture_snapshot_uses_actual_operation_api(monkeypatch):
    import asyncio

    from exitlane import core
    from exitlane.services import vpn_operations

    fixture_spec = importlib.util.spec_from_file_location(
        "d3_snapshot_fixture", DIRECTORY / "container_dataplane_fixture.py"
    )
    module = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(module)
    instance = object.__new__(module.Fixture)
    instance.providers = {"mullvad": object()}
    instance.network = SimpleNamespace(policy_candidate=None, policy_epoch=7, policy_committed=None)
    monkeypatch.setattr(core, "setting", lambda key, default=None: "mullvad" if key == "vpn.provider_id" else default)
    monkeypatch.setattr(vpn_operations, "active_snapshot", lambda: None)
    result = asyncio.run(instance.command({"command": "snapshot"}))
    assert result["ok"] and result["operation_state"] == "idle"
    assert result["candidate_provider"] is None
    assert not result["candidate_committed"]


@pytest.mark.parametrize("fault", ["transport", "fixture", "pending", "unguarded"])
def test_failed_rollback_requires_completed_transaction_and_retained_guard(fault):
    result = {"ok": False, "error_code": "provider_switch_failed", "http_status": 400}
    snapshot = {"ok": True, "operation_state": "idle", "outer_transition": True, "candidate_committed": False}
    harness.validate_rollback_receipt(result, snapshot, source_loss=True)
    if fault == "transport":
        result.update(error_code="synthetic_http_unreachable", http_status=0)
    elif fault == "fixture":
        result["error_code"] = "synthetic_operation_failed"
    elif fault == "pending":
        snapshot["operation_state"] = "switching"
    else:
        snapshot["outer_transition"] = False
    with pytest.raises(AssertionError):
        harness.validate_rollback_receipt(result, snapshot, source_loss=True)
