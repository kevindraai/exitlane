"""Bounded D6 state operations without infrastructure or commercial credentials."""

import ast
import asyncio
import importlib.util
import json
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/qualification"))
try:
    spec = importlib.util.spec_from_file_location(
        "d6_state", ROOT / "scripts/qualification/container_host_state_matrix.py"
    )
    state = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(state)
finally:
    sys.path.remove(str(ROOT / "scripts/qualification"))

FIRST, SECOND = "sha256:" + "a" * 64, "sha256:" + "b" * 64


class Remote:
    def __init__(self):
        self.calls = []

    def run(self, source, *, data=None, **kwargs):
        self.calls.append((source, data))
        return ""


class Harness:
    def __init__(self):
        self.candidate = Remote()
        self.peer = Remote()
        self.config = {
            "run_id": str(uuid.uuid4()),
            "candidate": {"address": "192.168.99.10"},
            "revision": "c" * 40,
        }
        self.prefix = "exitlane-d6-synthetic"
        self.container, self.network, self.volume = (
            self.prefix + "-app",
            self.prefix + "-net",
            self.prefix + "-state",
        )
        self.image = FIRST
        self.cookie = "synthetic-session-only"
        self.revoked = False
        self.calls, self.phases = [], []
        self.command_inputs = []
        self.ingress_identity = {
            "interface": "wg-office",
            "server_public_fingerprint": "c" * 64,
            "client_public_fingerprint": "d" * 64,
        }
        self.interval = 10
        self.intent_value = {
            "schema": 1,
            "selected_provider": "mullvad",
            "intents": [{"provider": "mullvad", "status": "active", "generation": "synthetic-1"}],
        }
        self.identity = 1
        self.gateway = "172.18.0.1"
        self.network_id = "old-network"
        self.mounted = {"Destination": "/data", "Type": "volume", "Name": self.volume}
        self.endpoints = None
        self.oom = {
            "oom_kill_before": 2,
            "oom_kill_after": 3,
            "injector_exit": -9,
            "claim": "owned_cgroup_oom_only",
        }

    def assert_disposable(self):
        self.calls.append(("disposable",))

    def assert_owned(self, kind, name):
        self.calls.append(("owned", kind, name))
        if kind == "container":
            return {
                "Image": self.image,
                "Id": str(self.identity),
                "Mounts": [self.mounted],
                "HostConfig": {"Memory": 2 * 1024**3, "MemorySwap": 4 * 1024**3},
            }
        if kind == "network":
            return {
                "Id": self.network_id,
                "Containers": self.endpoints
                if self.endpoints is not None
                else {str(self.identity): {}},
                "IPAM": {"Config": [{"Gateway": self.gateway}]},
            }
        return {"Name": self.volume}

    def pair(self):
        return {
            "schema": 1,
            "key": "synthetic-key-digest",
            "manifest": "synthetic-manifest-digest",
            "users": 1,
        }

    def packet_phase(self, name, captures, *, operation, **kwargs):
        self.phases.append((name, kwargs))
        operation()
        return {
            "receipt": {
                "accepted": True,
                "phase": name,
                "expected_state": (
                    "blocked"
                    if kwargs.get("blocked")
                    else "provider_or_block_with_fresh_recovery"
                    if kwargs.get("require_recovery")
                    else "provider_or_block_transition"
                ),
            }
        }

    def create(self, image):
        self.identity += 1
        self.image = image

    def docker(self, *args, data=None, **kwargs):
        self.calls.append((args, data, kwargs))
        if args[:2] == ("image", "inspect"):
            return {
                "stdout": json.dumps(
                    [
                        {
                            "Id": args[-1]
                            if args[-1].startswith("sha256:")
                            else FIRST
                            if "-state-base:" in args[-1]
                            else SECOND,
                            "Architecture": "amd64",
                            "Os": "linux",
                            "Config": {
                                "Labels": {
                                    "org.exitlane.qualification.replacement": "schema1-mechanism-only",
                                    "org.opencontainers.image.revision": self.config["revision"],
                                    "org.opencontainers.image.source": "https://github.com/kevindraai/exitlane",
                                    "org.exitlane.runtime": "container",
                                    "org.exitlane.schema": "1:1",
                                    "org.exitlane.support": "experimental",
                                }
                            },
                        }
                    ]
                ),
                "code": 0,
            }
        if args[:2] == ("network", "inspect"):
            return {"stdout": json.dumps([self.assert_owned("network", self.network)]), "code": 0}
        if args[:2] == ("network", "create"):
            self.gateway = args[args.index("--gateway") + 1]
            self.network_id = "new-network"
        if args[0] == "rm":
            self.endpoints = {}
        if args[0] == "exec" and "memory.events" in args[-1]:
            return {"stdout": json.dumps(self.oom), "code": 0}
        if args[0] == "exec" and "server_public_fingerprint" in args[-1]:
            return {"stdout": json.dumps(self.ingress_identity), "code": 0}
        if args[0] == "exec" and "local_public_fingerprint" in args[-1]:
            return {"stdout": json.dumps(self.intent_value), "code": 0}
        if args[0] == "exec" and "current_general_settings" in args[-1]:
            return {"stdout": str(self.interval), "code": 0}
        if "exitlane.container_cli" in args:
            if "status" in args:
                value = {"state": "ready", "worker_running": True}
            elif "backup" in args:
                value = {"name": "synthetic.elbackup"}
            else:
                if data == "synthetic-wrong-passphrase-only\n":
                    return {"code": 1, "stdout": "", "stderr": "container_control_failed"}
                self.interval = 10
                self.revoked = True
                value = {"restored": True}
            return {"code": 0, "stdout": json.dumps(value)}
        return {"stdout": "{}", "code": 0}

    def command(self, host, args, **kwargs):
        self.calls.append(("command", args))
        self.command_inputs.append((args, kwargs.get("data")))
        if args[-1] == "ownership":
            return {
                "stdout": json.dumps(
                    {
                        "run_id": self.config["run_id"],
                        "role": "client",
                        "namespace": "ed6-"
                        + self.config["run_id"].replace("-", "")[:10]
                        + "-client",
                        "namespace_inode": [1, 2],
                        "interface_ifindexes": {"wg-client": 42},
                    }
                ),
                "code": 0,
            }
        return {"stdout": json.dumps([{"dst": "172.17.0.0/16"}]), "code": 0}

    def api(self, path, **kwargs):
        self.calls.append(("api", path, kwargs))
        if path == "/api/auth/session":
            return {"status": 200, "body": {"authenticated": not self.revoked, "setup_complete": False}}
        if path == "/api/settings" and self.revoked:
            return {"status": 401}
        if path == "/api/ingress/wireguard/config":
            return {
                "status": 200,
                "body": {"available": True, "configuration": "synthetic-client-profile-only"},
            }
        if path == "/api/settings" and kwargs.get("method") == "PUT":
            self.interval = kwargs["body"]["general"]["provider_refresh_interval_seconds"]
        return {"status": 200, "body": {"success": True}}

    def wait(self, probe, stage, **kwargs):
        assert probe()

    def healthy(self):
        return True

    def network_snapshot(self):
        return {"rules": "synthetic-stable-facts", "state_pair": self.pair()}


@pytest.fixture
def qualification():
    h = Harness()
    return state.StateQualification(h, [], image=FIRST, provider="mullvad")


def test_same_volume_recreation_proves_new_identity_and_epoch_hooks(qualification):
    events = []
    qualification.epoch_hook = lambda *v: events.append(v)
    qualification.container_recreation()
    assert qualification.h.identity == 2 and qualification.image == FIRST
    assert events == [("container", True), ("container", False)]
    args = [v[0] for v in qualification.h.calls if isinstance(v[0], tuple)]
    assert ("rm", qualification.h.container) in args
    assert not any(v[:2] == ("volume", "rm") for v in args)


@pytest.mark.parametrize("fault", ["image", "volume", "endpoint"])
def test_foreign_resource_refused_before_stop(qualification, fault):
    if fault == "image":
        qualification.h.image = SECOND
    elif fault == "volume":
        qualification.h.mounted["Name"] = "unrelated-volume"
    else:
        qualification.h.endpoints = {"unrelated": {}}
    with pytest.raises(state.QualificationError):
        qualification.container_recreation()
    assert not any(
        v[0] == ("stop", "--time", "15", qualification.h.container) for v in qualification.h.calls
    )


def test_second_digest_is_label_only_and_previous_digest_restored(qualification):
    qualification.image_replacement()
    builds = [v for v in qualification.h.calls if isinstance(v[0], tuple) and v[0][0] == "build"]
    assert len(builds) == 1
    assert (
        "--network=none" in builds[0][0]
        and "BASE=" + qualification.h.prefix + "-state-base:fixture" in builds[0][0]
    )
    assert "COPY" not in builds[0][1] and "RUN" not in builds[0][1]
    assert qualification.image == FIRST and qualification.h.identity == 3


def test_bridge_changes_gateway_and_retains_volume(qualification):
    qualification.bridge_recreation()
    assert qualification.h.gateway.startswith("172.28.")
    assert qualification.h.network_id == "new-network"
    assert qualification.h.mounted["Name"] == qualification.h.volume


def test_provider_deletion_requires_owned_key_and_ifindex_before_delete(qualification):
    qualification.delete_interface("wg-mullvad")
    call = [v for v in qualification.h.calls if isinstance(v[0], tuple) and v[0][0] == "exec"][-1]
    source = call[0][-1]
    assert "s.validate()" in source and "public!=expected or inspect()!=index" in source
    assert source.index("public!=expected") < source.index("['ip','link','delete'")
    with pytest.raises(state.QualificationError):
        qualification.delete_interface("eth0")


def test_provider_deletion_has_separate_strict_absent_epoch(qualification):
    qualification.interface_deletion()
    names = [v[0].rsplit("-", 1)[0] for v in qualification.h.phases]
    assert names == ["state-provider-delete", "state-provider-absent", "state-provider-recovery"]
    assert qualification.h.phases[0][1]["require_recovery"] is False
    assert qualification.h.phases[1][1]["blocked"] is True
    assert (
        "api",
        "/api/vpn/providers/mullvad/reconnect",
        {"method": "POST", "body": {}, "timeout": 90},
    ) in qualification.h.calls


def test_cli_secret_only_on_stdin_and_generated_basename(qualification):
    qualification.cli("restore", "synthetic-test-passphrase", name="synthetic.elbackup")
    args, data, _ = qualification.h.calls[-1]
    assert "synthetic-test-passphrase" not in str(args)
    assert data == "synthetic-test-passphrase\n"
    assert args[-4:] == ("--name", "synthetic.elbackup", "--confirm", "RESTORE EXITLANE")
    with pytest.raises(state.QualificationError):
        qualification.cli("restore", "synthetic-test-passphrase", name="../arbitrary")


def test_cli_restore_last_revokes_cookie_preserves_pair(qualification):
    qualification.backup_restore("synthetic-test-passphrase")
    assert qualification.h.cookie == ""
    assert [v[0].rsplit("-", 1)[0] for v in qualification.h.phases] == [
        "state-cli-backup",
        "state-restore-canary",
        "state-cli-wrong-passphrase",
        "state-cli-restore",
    ]


def test_restore_revocation_accepts_public_first_run_provider_reads(qualification):
    from exitlane import main

    assert main.is_setup_provider_api_route("GET", "/api/vpn/providers") is True
    assert ("GET", "/api/settings") not in main.PUBLIC_API_ROUTES | main.SETUP_API_ROUTES
    assert qualification.h.api("/api/vpn/providers")["status"] == 200
    qualification.backup_restore("synthetic-test-passphrase")
    assert qualification.h.api("/api/vpn/providers")["status"] == 200
    assert qualification.h.api("/api/auth/session") == {
        "status": 200, "body": {"authenticated": False, "setup_complete": False}}
    assert qualification.h.cookie == ""
    calls = [c[1] for c in qualification.h.calls if c[0] == "api"]
    assert calls[-4:] == ["/api/auth/session", "/api/settings", "/api/vpn/providers", "/api/auth/session"]


@pytest.mark.parametrize("session,protected", [
    ({"status": 200, "body": {"authenticated": True}}, {"status": 401}),
    ({"status": 200, "body": {"authenticated": False}}, {"status": 200}),
    ({"status": 200, "body": {"authenticated": False}}, {"status": 503}),
    ({"status": 401, "body": {"authenticated": False}}, {"status": 401}),
    ({"status": 200, "body": {}}, {"status": 401}),
    ({"status": 200, "body": {"authenticated": "false"}}, {"status": 403}),
])
def test_restore_requires_both_actual_unauthenticated_session_and_protected_refusal(
    qualification, session, protected
):
    original = qualification.h.api

    def changed(path, **kwargs):
        if qualification.h.revoked:
            if path == "/api/auth/session":
                return session
            if path == "/api/settings":
                return protected
        return original(path, **kwargs)

    qualification.h.api = changed
    with pytest.raises(state.QualificationError, match="qualification_state_session_not_revoked"):
        qualification.backup_restore("synthetic-test-passphrase")
    assert qualification.h.cookie == "synthetic-session-only"
    receipts = [data["receipt"]["state"] for _, data in qualification.h.candidate.calls
                if isinstance(data, dict) and "receipt" in data]
    assert receipts[-1] == "FAIL"


def test_real_kernel_oom_counter_required_and_swap_restored(qualification):
    qualification.oom_injector()
    updates = [
        v[0] for v in qualification.h.calls if isinstance(v[0], tuple) and v[0][0] == "update"
    ]
    assert updates == [
        ("update", "--memory-swap", str(2 * 1024**3), qualification.h.container),
        ("update", "--memory-swap", str(4 * 1024**3), qualification.h.container),
    ]
    assert qualification.h.oom["claim"] == "owned_cgroup_oom_only"


def test_actual_emitted_oom_parent_and_child_programs_compile(qualification):
    qualification.oom_injector()
    calls = [
        v
        for v in qualification.h.calls
        if isinstance(v[0], tuple) and v[0][0] == "exec" and "memory.events" in v[0][-1]
    ]
    program = calls[0][0][-1]
    compile(program, "actual-docker-oom-parent", "exec")
    tree = ast.parse(program)
    assigned = next(
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "code" for t in node.targets)
    )
    compile(assigned, "actual-docker-oom-child", "exec")


def test_unchanged_oom_counter_is_failure_and_restores_swap(qualification):
    qualification.h.oom["oom_kill_after"] = 2
    with pytest.raises(state.QualificationError, match="qualification_oom_not_observed"):
        qualification.oom_injector()
    assert qualification.h.calls[-1][0] == (
        "update",
        "--memory-swap",
        str(4 * 1024**3),
        qualification.h.container,
    )


def test_phase_failure_retains_fixed_fail_receipt_without_retry(qualification):
    def failure():
        raise RuntimeError("synthetic-private-detail")

    with pytest.raises(RuntimeError):
        qualification.phase("state-synthetic-failure", failure)
    receipts = [
        v[1]["receipt"]
        for v in qualification.h.candidate.calls
        if isinstance(v[1], dict) and "receipt" in v[1]
    ]
    assert [v["state"] for v in receipts] == ["RUNNING", "FAIL"]
    assert "synthetic-private-detail" not in str(receipts)
    with pytest.raises(state.QualificationError):
        qualification.phase("state-synthetic-failure", lambda: None)


@pytest.mark.parametrize("fault", ["accepted", "phase", "expected_state", "missing"])
def test_negative_packet_receipt_never_records_pass(qualification, fault):
    original = qualification.h.packet_phase

    def corrupt(*args, **kwargs):
        value = original(*args, **kwargs)
        if fault == "missing":
            return {}
        value["receipt"][fault] = False if fault == "accepted" else "mismatch"
        return value

    qualification.h.packet_phase = corrupt
    with pytest.raises(state.QualificationError, match="packet_receipt_invalid"):
        qualification.phase("state-negative-receipt", lambda: None)
    receipts = [
        data["receipt"]["state"]
        for _, data in qualification.h.candidate.calls
        if isinstance(data, dict) and "receipt" in data
    ]
    assert receipts == ["RUNNING", "FAIL"]


def test_recreation_rejects_changed_provider_generation(qualification):
    original = qualification.h.create

    def changed(image):
        original(image)
        qualification.h.intent_value["intents"][0]["generation"] = "synthetic-2"

    qualification.h.create = changed
    with pytest.raises(state.QualificationError, match="recreation_invalid"):
        qualification.container_recreation()


def test_restore_canary_changes_actual_setting_then_recovers_original(qualification):
    qualification.backup_restore("synthetic-test-passphrase")
    changes = [
        c
        for c in qualification.h.calls
        if c[0] == "api" and c[1] == "/api/settings" and c[2].get("method") == "PUT"
    ]
    assert changes[0][2]["body"] == {"general": {"provider_refresh_interval_seconds": 11}}
    assert qualification.h.interval == 10


def test_actual_pressure_phases_unique_between_instances_and_receipts(qualification):
    one = qualification.phase("state-unique", lambda: None)
    other = state.StateQualification(qualification.h, [], image=FIRST, provider="mullvad")
    two = other.phase("state-unique", lambda: None)
    phases = [one["receipt"]["phase"], two["receipt"]["phase"]]
    assert phases[0] != phases[1]
    assert all(state.re.fullmatch(r"state-unique-[a-f0-9]{8}", phase) for phase in phases)
    receipts = [
        data["receipt"]
        for _, data in qualification.h.candidate.calls
        if isinstance(data, dict) and "receipt" in data
    ]
    assert [r["phase"] for r in receipts] == [phases[0], phases[0], phases[1], phases[1]]
    with pytest.raises(state.QualificationError, match="phase_reused"):
        qualification.phase("state-unique", lambda: None)


def test_phase_grammar_bounded_before_operation(qualification):
    seen = []
    for name in ("x" * 32, "arbitrary;command", "", None):
        with pytest.raises(state.QualificationError, match="phase_invalid"):
            qualification.phase(name, lambda: seen.append(True))
    assert seen == [] and qualification.h.phases == []
    result = qualification.phase("x" * 31, lambda: None)
    assert len(result["receipt"]["phase"]) == 40


def test_oom_secondary_receipt_uses_actual_unique_pressure_phase(qualification):
    result = qualification.oom_injector()
    receipts = [
        data["receipt"]
        for _, data in qualification.h.candidate.calls
        if isinstance(data, dict) and "receipt" in data
    ]
    assert len(receipts) == 3
    assert {r["phase"] for r in receipts} == {result["receipt"]["phase"]}
    assert receipts[-1]["facts"]["oom"]["claim"] == "owned_cgroup_oom_only"


def test_deleted_cached_owned_ingress_refuses_adoption_and_maps_real_api_reload_failure(
    monkeypatch, tmp_path
):
    from types import SimpleNamespace

    from fastapi import HTTPException

    from exitlane import main
    from exitlane.container_entrypoint import ContainerController
    from exitlane.container_runtime import ContainerWireGuardLifecycle, IngressConfig
    from exitlane.services import wireguard

    config = IngressConfig(
        "wg-office", "10.77.0.1/24", "A" * 43 + "=", "B" * 43 + "=", "10.77.0.2/32", 51820
    )
    commands, guards = [], []

    async def runner(*argv, **kwargs):
        commands.append(argv)
        if argv[:3] == ("ip", "-j", "link"):
            return 1, "", "synthetic missing owned interface"
        pytest.fail("unexpected network mutation")

    class Maintenance:
        async def arm(self, identities):
            guards.append(identities)

    controller = ContainerController(
        SimpleNamespace(layout=SimpleNamespace(wireguard=tmp_path)), Maintenance(), runner=runner
    )
    network = ContainerWireGuardLifecycle(config, runner=runner)
    network.active = True
    network.owned_ifindex = 42
    controller.network = network
    monkeypatch.setattr(IngressConfig, "from_file", classmethod(lambda cls, path: config))
    monkeypatch.setattr(wireguard, "WG_DIR", tmp_path)
    old = {"wg-office": "synthetic-old-server", "synthetic_router": "synthetic-old-client"}
    for name, content in old.items():
        (tmp_path / (name + ".conf")).write_text(content)

    async def create(**kwargs):
        for name in old:
            (tmp_path / (name + ".conf")).write_text("synthetic-new-unused")
        return {"interface": "wg-office"}

    async def activate(interface):
        await controller.ingress({"action": "activate", "interface": interface})

    monkeypatch.setattr(wireguard, "create", create)
    monkeypatch.setattr(main, "activate_wireguard_interface", activate)
    monkeypatch.setattr(main, "wireguard_generation_lock", asyncio.Lock)
    monkeypatch.setattr(main.provider_registry, "direct_egress_providers", list)
    monkeypatch.setattr(
        main,
        "setting",
        lambda key, default=None: "wg-office" if key == "wireguard_interface" else default,
    )
    with pytest.raises(HTTPException) as failure:
        asyncio.run(
            main.create_wireguard_ingress(
                main.WireGuard(
                    endpoint="192.168.99.10",
                    interface="wg-office",
                    subnet="10.77.0.0/24",
                    client="synthetic_router",
                    dns="10.64.0.1",
                    port=51820,
                ),
                None,
            )
        )
    assert failure.value.status_code == 500 and failure.value.detail == "wireguard_reload_failed"
    assert len(guards) == 2  # Primary attempt and bounded rollback activation.
    assert commands == [("ip", "-j", "link", "show", "dev", "wg-office")] * 2
    assert network.active is True and network.owned_ifindex == 42
    assert all(
        (tmp_path / (name + ".conf")).read_text() == content for name, content in old.items()
    )


def test_ingress_deleted_recovery_recreates_namespace_preserving_keys_without_api_generation(
    qualification,
):
    original = dict(qualification.h.ingress_identity)
    qualification.interface_deletion(ingress=True)
    assert qualification.h.identity == 2 and qualification.image == FIRST
    assert qualification.h.ingress_identity == original
    assert [name.rsplit("-", 1)[0] for name, _ in qualification.h.phases] == [
        "state-ingress-delete",
        "state-ingress-absent",
        "state-ingress-recovery",
    ]
    assert qualification.h.phases[1][1]["blocked"] is True
    assert qualification.h.phases[2][1]["require_recovery"] is True
    apis = [c for c in qualification.h.calls if c[0] == "api"]
    assert apis == [("api", "/api/ingress/wireguard/config", {})]
    transfers = [c for c in qualification.h.calls if c[0] == "command" and c[1][-1] == "client"]
    assert len(transfers) == 1 and "synthetic-client-profile-only" not in str(transfers[0])
    supplied = json.loads(
        next(data for args, data in qualification.h.command_inputs if args[-1] == "client")
    )
    assert supplied == {
        "run_id": qualification.h.config["run_id"],
        "endpoint": "192.168.99.10:51820",
        "configuration": "synthetic-client-profile-only",
    }
    program = next(
        c[0][-1]
        for c in qualification.h.calls
        if isinstance(c[0], tuple) and c[0][0] == "exec" and "server_public_fingerprint" in c[0][-1]
    )
    compile(program, "actual-ingress-identity", "exec")
    assert "client_public!=c.public_key" in program and "p['Peer']['PublicKey']!=server" in program


def test_ingress_recreation_refuses_changed_public_keypair(qualification):
    original = qualification.h.create

    def changed(image):
        original(image)
        qualification.h.ingress_identity["client_public_fingerprint"] = "e" * 64

    qualification.h.create = changed
    with pytest.raises(state.QualificationError, match="ingress_keys_changed"):
        qualification.interface_deletion(ingress=True)


@pytest.mark.parametrize(
    "detail,expected",
    [
        ("management_routing_failed", "management_routing_failed"),
        ("wireguard_reload_failed", "wireguard_reload_failed"),
        ("synthetic-secret-never-log", None),
        ([{"input": "synthetic-secret-never-log"}], None),
    ],
)
def test_api_failure_receipt_keeps_only_bounded_status_static_code(qualification, detail, expected):
    def failure():
        qualification.api_failure(
            "ingress_post",
            {
                "status": 503,
                "body": {"detail": detail, "configuration": "synthetic-secret-never-log"},
            },
        )
        raise state.QualificationError("qualification_state_ingress_recovery_failed")

    with pytest.raises(state.QualificationError):
        qualification.phase("state-diagnostic", failure)
    receipts = [
        data["receipt"]
        for _, data in qualification.h.candidate.calls
        if isinstance(data, dict) and "receipt" in data
    ]
    facts = receipts[-1]["facts"]["api_failure"]
    assert facts == {
        "operation": "ingress_post",
        "http_status": 503,
        "error_code": expected,
        "detail_type": type(detail).__name__,
    }
    assert "synthetic-secret-never-log" not in str(receipts)


def test_ingress_sync_rejects_changed_router_owned_ifindex(qualification):
    original = qualification.h.command
    reads = []

    def changed(host, args, **kwargs):
        value = original(host, args, **kwargs)
        if args[-1] == "ownership":
            reads.append(True)
            if len(reads) == 2:
                facts = json.loads(value["stdout"])
                facts["interface_ifindexes"]["wg-client"] += 1
                value["stdout"] = json.dumps(facts)
        return value

    qualification.h.command = changed
    with pytest.raises(state.QualificationError, match="client_ownership_changed"):
        qualification.interface_deletion(ingress=True)


@pytest.mark.parametrize(
    "stderr,expected",
    [
        ("container_control_failed\n", "container_control_failed"),
        ("synthetic-private-detail", None),
    ],
)
def test_cli_nonzero_retains_bounded_error_before_transport_discards_output(
    qualification, stderr, expected
):
    args_seen = []

    def failure(*args, data=None, **kwargs):
        args_seen.append((args, kwargs))
        assert kwargs["check"] is False and kwargs["timeout"] == 225
        return {"code": 1, "stderr": stderr, "stdout": "synthetic-private-detail"}

    qualification.h.docker = failure
    with pytest.raises(state.QualificationError, match="qualification_state_cli_failed"):
        qualification.phase(
            "state-restore-error",
            lambda: qualification.cli(
                "restore", "synthetic-passphrase-test", name="synthetic.elbackup"
            ),
        )
    receipts = [
        data["receipt"]
        for _, data in qualification.h.candidate.calls
        if isinstance(data, dict) and "receipt" in data
    ]
    assert receipts[-1]["facts"]["cli_failure"] == {
        "command": "restore",
        "exit_code": 1,
        "stderr_code": expected,
    }
    assert "synthetic-private-detail" not in str(receipts)
    assert "synthetic-passphrase-test" not in str(args_seen)


def test_actual_cli_parser_accepts_state_and_generation_flag_orders(qualification):
    from exitlane.container_cli import parse_arguments

    qualification.cli("restore", "synthetic-test-passphrase", name="synthetic.elbackup")
    args, _stdin, _kwargs = qualification.h.calls[-1]
    state_arguments = list(args[args.index("restore") :])
    generation_arguments = [
        "restore",
        "--name",
        "synthetic.elbackup",
        "--confirm",
        "RESTORE EXITLANE",
        "--passphrase-stdin",
    ]
    one, two = parse_arguments(state_arguments), parse_arguments(generation_arguments)
    assert vars(one) == vars(two)
    assert one.confirm == "RESTORE EXITLANE" and one.passphrase_stdin is True


@pytest.mark.parametrize("phrase", ["synthetic-test\rhidden", "synthetic-test\0hidden"])
def test_cli_refuses_control_characters_before_process(qualification, phrase):
    with pytest.raises(state.QualificationError, match="cli_invalid"):
        qualification.cli("backup", phrase)
    assert not qualification.h.calls
