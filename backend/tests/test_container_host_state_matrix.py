"""Bounded D6 state operations without infrastructure or commercial credentials."""

import ast
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
        self.calls, self.phases = [], []
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
                value = {"restored": True}
            return {"code": 0, "stdout": json.dumps(value)}
        return {"stdout": "{}", "code": 0}

    def command(self, host, args, **kwargs):
        self.calls.append(("command", args))
        return {"stdout": json.dumps([{"dst": "172.17.0.0/16"}]), "code": 0}

    def api(self, path, **kwargs):
        self.calls.append(("api", path, kwargs))
        if path == "/api/settings" and kwargs.get("method") == "PUT":
            self.interval = kwargs["body"]["general"]["provider_refresh_interval_seconds"]
        return (
            {"status": 401}
            if path == "/api/vpn/providers"
            else {"status": 200, "body": {"success": True}}
        )

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
