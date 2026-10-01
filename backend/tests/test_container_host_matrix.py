"""Restart driver orchestration with no SSH, Docker or infrastructure calls."""

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/qualification"))
spec = importlib.util.spec_from_file_location(
    "container_host_matrix", ROOT / "scripts/qualification/container_host_matrix.py"
)
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
IDENTIFIER = "0b0dcc00-ff11-4333-aaaa-012345678901"
COOKIE = "exitlane_session=synthetic_fixture_cookie_only_123456789"


@pytest.fixture(autouse=True)
def local_fixture_uid(monkeypatch):
    monkeypatch.setattr(matrix, "_ROOT_UID", os.geteuid())


def handle(role, number, *, candidate=False):
    identifier = f"{number:032x}"
    value = {
        "kind": "capture",
        "role": role,
        "root": "/run/exitlane-d6-" + identifier,
        "unit": "exitlane-d6-capture-" + identifier + ".service",
        "interfaces": ["uplink"],
    }
    if candidate:
        value.update(host="candidate", namespace=role == "candidate-namespace", container_pid=123)
    else:
        suffix = {"client": "client", "provider-a": "a", "provider-b": "b", "target": "target"}
        value["namespace"] = (
            None
            if role == "wan"
            else "ed6-" + IDENTIFIER.replace("-", "")[:10] + "-" + suffix[role]
        )
    return value


def captures():
    return [handle(role, number) for number, role in enumerate(sorted(matrix.EXTERNAL_ROLES), 1)]


class FakeHarness:
    def __init__(self, *, auth=True, failure=None, allow=True):
        self.config = {
            "run_id": IDENTIFIER,
            "image": "sha256:" + "a" * 64,
            "revision": "b" * 40,
            "allow_host_restart": allow,
        }
        self.auth = auth
        self.failure = failure
        self.events = []
        self.receipts = []
        self.last_packet_evidence = None
        self.candidate = object()
        self.cookie = COOKIE
        self.phases = {}
        self.next_handle = 100

    def preflight(self):
        self.events.append("preflight")

    def api(self, path):
        assert path == "/api/auth/session"
        self.events.append("authentication")
        return {"status": 200, "body": {"authenticated": self.auth}}

    def network_snapshot(self):
        self.events.append("network-snapshot")
        return {"rules": [], "state_pair": {"manifest": "synthetic-public-digest"}}

    def evidence(self, value):
        self.events.append(("evidence", value["role"]))
        return {
            "phase": self.phases.get(value["unit"], "prior"),
            "captures": {"uplink": {"ready": True, "polls": 2, "samples": []}},
        }

    def control(self, value, phase, *, stop=False):
        self.events.append(("control", value["role"], stop))
        self.phases[value["unit"]] = phase

    def command(self, host, arguments):
        assert host is self.candidate
        assert arguments[:2] == ["systemctl", "show"]
        self.events.append("namespace-fully-stopped")
        return {"stdout": "dead\n"}

    def wait(self, probe, stage, timeout):
        assert timeout <= 20
        assert probe(), stage

    def configure_daemon_mode(self, enabled):
        self.events.append(("daemon-preparation", enabled))

    def packet_phase(self, phase, observers, *, fault):
        assert observers == captures()
        self.events.append(("pressure-and-fault", fault))
        self.last_packet_evidence = {
            "phase": phase,
            "sender": {"attempts": ["synthetic-numbered-packet"]},
            "captures": {"wan": {"samples": []}},
        }
        if self.failure == fault:
            raise RuntimeError("secret-cookie-must-not-appear-" + COOKIE)
        self.receipts.append({"stage": fault, "state_pair_preserved": True})
        return {"receipt": {"phase": phase, "accepted": True}, **self.last_packet_evidence}

    def candidate_capture(self, *, namespace):
        self.next_handle += 1
        role = "candidate-namespace" if namespace else "candidate-host"
        self.events.append(("new-epoch", role))
        return handle(role, self.next_handle, candidate=True)

    def archive_candidate_capture(self, value):
        self.events.append(("archive", value["role"]))
        return {"path": "/var/lib/exitlane-qualification/owned-epoch", "sha256": "c" * 64}


def runner(tmp_path, harness=None, epochs=None):
    harness = harness or FakeHarness()
    return matrix.RestartMatrix(
        harness, matrix.Receipts(tmp_path / "receipts"), captures(), epochs or []
    )


def test_all_restart_rows_remain_only_component_pass_with_outstanding_full_d6(tmp_path):
    value = runner(tmp_path)
    result = value.run("all")
    assert all(status == "PACKET_COMPONENT_PASS" for status in result["stages"].values())
    assert result["result"] == "PARTIAL" and result["d6"] == "OUTSTANDING"
    assert result["production_support"] is False
    assert all(status == "OUTSTANDING" for status in result["other_components"].values())
    assert set(result["other_components"]) >= {
        "pia_runtime",
        "proton_runtime",
        "backup_restore",
        "ipv6_attempts",
        "docker_bridge_recreation",
    }
    phases = [value.state["stages"][stage]["phase"] for stage in matrix.STAGES]
    assert len(set(phases)) == len(phases)
    assert all(len(phase) <= 31 and "_" not in phase for phase in phases)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in value.receipts.root.iterdir())
    assert value.receipts.root.stat().st_mode & 0o777 == 0o700
    assert COOKIE not in "".join(path.read_text() for path in value.receipts.root.glob("*.json"))


def test_resumes_next_pending_row_without_repeating_completed_fault(tmp_path):
    first = runner(tmp_path)
    first.run("next")
    second = runner(tmp_path)
    result = second.run("next")
    assert result["stages"]["parent_crash"] == "PACKET_COMPONENT_PASS"
    assert result["stages"]["container_restart"] == "PACKET_COMPONENT_PASS"
    assert ("pressure-and-fault", "parent_crash") not in second.harness.events
    assert ("pressure-and-fault", "container_restart") in second.harness.events


def test_failed_stage_preserves_packet_metadata_and_does_not_retry(tmp_path):
    h = FakeHarness(failure="parent_crash")
    value = runner(tmp_path, h)
    with pytest.raises(matrix.MatrixError, match="matrix_stage_failed"):
        value.run("all")
    state = matrix.private_json(value.receipts.root / "matrix.json")
    assert state["stages"]["parent_crash"]["status"] == "FAILED"
    assert state["stages"]["container_restart"]["status"] == "PENDING"
    evidence = matrix.private_json(value.receipts.root / "parent_crash-failed-packets.json")
    assert evidence["sender"]["attempts"] == ["synthetic-numbered-packet"]
    assert COOKIE not in json.dumps(state)
    fresh = runner(tmp_path)
    with pytest.raises(matrix.MatrixError, match="requires_inspection"):
        fresh.run("all")
    assert fresh.harness.events == []


def test_no_host_operation_without_authentication_or_authorization(tmp_path):
    for name, h in [
        ("unauthenticated", FakeHarness(auth=False)),
        ("unauthorized", FakeHarness(allow=False)),
    ]:
        (tmp_path / name).mkdir()
        value = runner(tmp_path / name, h)
        with pytest.raises(matrix.MatrixError):
            value.run()
        assert not any(
            isinstance(event, tuple)
            and event[0] in {"pressure-and-fault", "daemon-preparation", "control"}
            for event in h.events
        )


def test_namespace_fd_fully_released_before_preparation_and_pressure(tmp_path):
    epochs = [
        handle("candidate-namespace", 77, candidate=True),
        handle("candidate-host", 78, candidate=True),
    ]
    value = runner(tmp_path, epochs=epochs)
    value.run("all")
    h = value.harness
    for event in [("daemon-preparation", False), ("daemon-preparation", True)]:
        index = h.events.index(event)
        assert "namespace-fully-stopped" in h.events[:index]
        next_pressure = next(
            i
            for i in range(index + 1, len(h.events))
            if isinstance(h.events[i], tuple) and h.events[i][0] == "pressure-and-fault"
        )
        assert h.events[index + 1 : next_pressure].count("authentication") >= 1
    first_pressure = h.events.index(("pressure-and-fault", "parent_crash"))
    assert h.events.index("namespace-fully-stopped") < first_pressure
    reboot = h.events.index(("pressure-and-fault", "host_reboot"))
    assert h.events.index(("archive", "candidate-host")) < reboot
    assert ("new-epoch", "candidate-host") in h.events[reboot + 1 :]


def test_reboot_refuses_missing_archive_helper_before_fault(tmp_path):
    h = FakeHarness()
    h.archive_candidate_capture = None
    value = runner(tmp_path, h, [handle("candidate-host", 78, candidate=True)])
    for _ in range(4):
        value.run()
    with pytest.raises(matrix.MatrixError):
        value.run("host_reboot")
    assert ("pressure-and-fault", "host_reboot") not in h.events


def test_unaccepted_packet_receipt_cannot_claim_component_pass(tmp_path):
    h = FakeHarness()
    h.packet_phase = lambda *_args, **_kw: {"receipt": {"accepted": False}}
    value = runner(tmp_path, h)
    with pytest.raises(matrix.MatrixError):
        value.run()
    assert value.state["stages"]["parent_crash"]["status"] == "FAILED"


def test_identity_change_and_interruption_refuse_resume_without_any_host_calls(tmp_path):
    value = runner(tmp_path)
    value.run()
    changed = runner(tmp_path)
    changed.harness.config["revision"] = "c" * 40
    with pytest.raises(matrix.MatrixError, match="identity_mismatch"):
        changed.run()
    assert changed.harness.events == []
    value.state["stages"]["container_restart"] = {"status": "RUNNING"}
    value.receipts.write("matrix.json", value.state)
    interrupted = runner(tmp_path)
    with pytest.raises(matrix.MatrixError, match="requires_inspection"):
        interrupted.run()
    assert interrupted.harness.events == []


def test_root_private_input_rejects_symlink_fifo_public_mode_and_duplicate_json(tmp_path):
    path = tmp_path / "input.json"
    path.write_text('{"cookie":"one","cookie":"two"}')
    path.chmod(0o600)
    with pytest.raises(matrix.MatrixError):
        matrix.private_json(path)
    path.write_text("{}")
    path.chmod(0o644)
    with pytest.raises(matrix.MatrixError):
        matrix.private_json(path)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(matrix.MatrixError):
        matrix.private_json(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(matrix.MatrixError):
        matrix.private_json(fifo)


def test_handles_and_session_are_exact_run_bound_not_arbitrary_commands():
    assert matrix.session_cookie({"run_id": IDENTIFIER, "cookie": COOKIE}, IDENTIFIER) == COOKIE
    value = {"run_id": IDENTIFIER, "captures": captures(), "candidate_epochs": []}
    assert matrix.validate_handles(value, IDENTIFIER)[0] == captures()
    for invalid in (
        {"run_id": "foreign", "cookie": COOKIE},
        {"run_id": IDENTIFIER, "cookie": COOKIE + "\r\nInjected:true"},
        {"run_id": IDENTIFIER, "cookie": COOKIE, "secret": "extra"},
    ):
        with pytest.raises(matrix.MatrixError):
            matrix.session_cookie(invalid, IDENTIFIER)
    value["captures"][0]["unit"] = "foreign.service"
    with pytest.raises(matrix.MatrixError):
        matrix.validate_handles(value, IDENTIFIER)


def test_secret_can_only_reach_harness_memory_not_argv_environment_or_outputs(
    tmp_path, monkeypatch, capsys
):
    config = tmp_path / "config.json"
    handles = tmp_path / "captures.json"
    session = tmp_path / "session.json"
    for path, value in [
        (config, {}),
        (handles, {"run_id": IDENTIFIER, "captures": captures(), "candidate_epochs": []}),
        (session, {"run_id": IDENTIFIER, "cookie": COOKIE}),
    ]:
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    h = FakeHarness()
    monkeypatch.setattr(matrix, "HostHarness", lambda _config: h)
    monkeypatch.setattr(matrix.os, "geteuid", lambda: 0)
    argv = [
        "--config",
        str(config),
        "--captures",
        str(handles),
        "--session",
        str(session),
        "--receipts-dir",
        str(tmp_path / "receipts"),
    ]
    before = dict(os.environ)
    assert matrix.main(argv) == 0
    assert h.cookie == COOKIE and COOKIE not in str(argv)
    assert dict(os.environ) == before
    output = capsys.readouterr()
    assert COOKIE not in output.out + output.err
    assert "OUTSTANDING" in output.out


def test_parallel_driver_cannot_acquire_receipt_authority(tmp_path):
    receipts = matrix.Receipts(tmp_path / "receipts")
    with (
        receipts.lock(),
        pytest.raises(matrix.MatrixError, match="already_running"),
        receipts.lock(),
    ):
        pytest.fail("parallel restart driver accepted")


def test_receipts_refuse_foreign_symlink_without_writing_target(tmp_path):
    receipts = matrix.Receipts(tmp_path / "receipts")
    target = tmp_path / "unrelated.json"
    target.write_text('{"untouched":true}')
    target.chmod(0o600)
    (receipts.root / "matrix.json").symlink_to(target)
    with pytest.raises(matrix.MatrixError):
        receipts.write("matrix.json", {"replacement": True})
    assert target.read_text() == '{"untouched":true}'
    assert not list(receipts.root.glob(".matrix.json.*"))


def test_unprivileged_cli_refuses_before_any_file_or_host_access(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(matrix.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(
        matrix, "HostHarness", lambda _config: pytest.fail("unprivileged host access")
    )
    args = [
        "--config",
        str(tmp_path / "absent"),
        "--captures",
        str(tmp_path / "absent"),
        "--session",
        str(tmp_path / "absent"),
        "--receipts-dir",
        str(tmp_path / "absent"),
    ]
    assert matrix.main(args) == 77
    assert "matrix_root_required" in capsys.readouterr().err


def test_private_input_rejects_other_owner_even_with_correct_mode(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    path.write_text("{}")
    path.chmod(0o600)
    facts = path.stat()
    monkeypatch.setattr(
        matrix.os,
        "fstat",
        lambda _fd: SimpleNamespace(
            st_mode=facts.st_mode, st_uid=matrix._ROOT_UID + 1, st_size=facts.st_size
        ),
    )
    with pytest.raises(matrix.MatrixError, match="matrix_input_unsafe"):
        matrix.private_json(path)
