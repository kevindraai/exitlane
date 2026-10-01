"""Real CLI/state projection/signal program contracts; fake transport only."""

import importlib.util
import json
import threading
from pathlib import Path

import pytest
from test_container_host_failures import FailureHarness
from test_container_host_providers import MemoryReceipts

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "container_host_generation", ROOT / "scripts/qualification/container_host_generation.py"
)
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)
BACKUP = "20261001T000000Z-012345abcdef.elbackup"
PASSPHRASE = "synthetic-generation-fixture-only"
ACTIVE = {
    "provider": "mullvad",
    "status": "active",
    "generation": "baseline-generation",
    "interface": "wg-mullvad",
    "endpoint": "192.0.0.9",
    "public_key": "synthetic-public-only",
    "peer_public_key": "synthetic-peer-public-only",
}


class Harness(FailureHarness):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.pending = False
        self.killed = threading.Event()
        self.refused = False
        self.control_missing = False
        self.bad_identity = False
        self.same_keys = True
        self.session_revoked = True
        self.api_wrong_success = False
        self.restore_called = False
        self.secret_values = []
        self.transport_wrapper = False
        self.healthy_pending_management = False

    def api(self, path, *, method, body, timeout):
        if method == "POST":
            assert path == "/api/vpn/providers/pia/activate" and body is None and timeout == 180
            self.pending = True
            self.candidate_started.set()
            assert self.killed.wait(1)
            if self.transport_wrapper:
                return {"status": 0, "body": None, "headers": {}, "cookies": []}
            if self.api_wrong_success:
                return {"status": 200, "body": {"ok": True}}
            return {"status": 503, "body": {"detail": "provider_switch_failed"}}
        if self.restore_called and path == "/api/auth/session":
            assert timeout == 30
            return {"status": 200, "body": {"authenticated": not self.session_revoked}}
        return super().api(path, method=method, body=body, timeout=timeout)

    def docker(self, *arguments, check=True, data=None, timeout=40):
        if arguments[-6:] == ("ip", "-j", "link", "show", "dev", "wg-pia"):
            assert check is False
            return {"code": 1, "stdout": ""}
        if arguments[-1] == generation.INVENTORY_PROGRAM:
            assert check is False
            inventory = {"selected_provider": "mullvad", "intents": [dict(ACTIVE)]}
            if self.pending:
                inventory["intents"] = [
                    {
                        "provider": "pia",
                        "status": "pending",
                        "generation": "candidate-generation",
                        "interface": "wg-pia",
                        "endpoint": "192.0.0.10",
                    }
                ]
            elif self.restore_called and not self.same_keys:
                inventory["intents"][0]["generation"] = "different-generation"
            return {"code": 0, "stdout": json.dumps(inventory)}
        if arguments[-1] == generation.KILL_PROGRAM:
            self.calls.append((arguments, data))
            assert json.loads(data) == {"pid": self.worker[0], "start": self.worker[1]}
            assert arguments[:2] == ("exec", "-i")
            if self.bad_identity:
                self.killed.set()
                return {"code": 1, "stdout": "qualification_worker_identity_unproven"}
            self.refused = True
            self.killed.set()
            if self.healthy_pending_management:
                self.worker = [20, "1300"]
            return {"code": 0, "stdout": "qualification_signal_sent\n"}
        if "exitlane.container_cli" in arguments:
            self.calls.append((arguments, data))
            command = arguments[arguments.index("exitlane.container_cli") + 1]
            if command == "backup":
                assert "--passphrase-stdin" in arguments and data.endswith("\n") and timeout == 180
                self.secret_values.append(data.strip())
                self.worker = [19, "1200"]
                output = {"name": BACKUP}
            elif command == "status":
                if self.control_missing:
                    return {"code": 1, "stdout": "", "stderr": "container_control_failed"}
                ready = not self.refused or self.healthy_pending_management
                output = {
                    "state": "ready" if ready else "recovery_required",
                    "available": ready,
                    "recovery_required": False,
                    "worker_running": ready,
                }
            elif command == "restore":
                assert data.strip() == self.secret_values[0]
                assert arguments[-5:] == (
                    "--name",
                    BACKUP,
                    "--confirm",
                    "RESTORE EXITLANE",
                    "--passphrase-stdin",
                )
                self.restore_called = True
                self.pending = self.refused = False
                self.connected = True
                output = {"restored": True}
            return {"code": 0, "stdout": json.dumps(output)}
        return super().docker(*arguments, check=check)

    def healthy(self):
        return self.restore_called and not self.pending

    def network_snapshot(self):
        return {
            "rules": ["actual-fixture-public-snapshot"],
            "interfaces": [],
            "firewall": ["provider-blocked"],
        }

    def wait(self, probe, stage, timeout):
        assert stage.startswith("d6-") and timeout in {10, 30, 60, 120}
        if stage == "d6-pia-pending-zero-handshake":
            assert self.candidate_started.wait(1)
        if not probe():
            raise RuntimeError("synthetic-bounded-gate-failed")


def qualification():
    h, receipts = Harness(), MemoryReceipts()
    value = generation.GenerationQualification(h, ["external-captures"], receipts=receipts)
    prep = value.failures.prepare_catalogs(mullvad="a", pia="b")
    h.worker = [18, "1100"]
    return value, h, receipts, prep


def test_actual_pending_crash_root_cli_restore_preserves_generation_keys_and_revokes_session():
    value, h, receipts, prep = qualification()
    result = value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    assert result["result"] == "PACKET_COMPONENT_PASS" and result["full_d6_result"] == "OUTSTANDING"
    assert result["signal"] == {"sent": True, "exit": 0}
    assert result["pending_inventory"]["intents"][0]["status"] == "pending"
    assert result["restored_inventory"]["intents"] == [ACTIVE]
    assert result["old_session_revoked"] is True
    assert [phase[2:] for phase in h.pressure] == [(False, False), (True, False), (False, True)]
    assert h.fault_calls == [("b", "handshake_off")]
    for secret in h.secret_values:
        assert secret not in str([arguments for arguments, _stdin in h.calls])
        assert secret not in json.dumps(receipts.values)
    assert (
        sum("exitlane.container_cli" in argv and "restore" in argv for argv, _stdin in h.calls) == 1
    )


def test_documented_http_transport_wrapper_and_healthy_management_do_not_promote_pending():
    value, h, receipts, prep = qualification()
    h.transport_wrapper = h.healthy_pending_management = True
    result = value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    assert result["api_response"] == {
        "http_status": 0,
        "body_present": False,
        "ok": None,
        "success": None,
        "error_code": None,
    }
    assert result["api_interrupted"] == {"transport_interrupted": True, "status": 0}
    assert result["pending_state"]["control"]["state"] == "ready"
    assert result["pending_state"]["control"]["worker_running"] is True
    assert result["pending_state"]["pia_interface"] == "absent"
    assert result["pending_state"]["inventory"] == result["pending_inventory"]
    assert result["blocked"]["blocked"] is True
    assert PASSPHRASE not in json.dumps(receipts.values)


def test_rejected_api_response_is_projected_before_validation_without_arbitrary_body_text():
    value, h, receipts, prep = qualification()
    h.api_wrong_success = True
    with pytest.raises(generation.FailureEvidenceError):
        value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")][
        -1
    ]
    assert metadata["api_response"]["http_status"] == 200 and metadata["api_response"]["ok"] is True
    assert metadata["diagnostic"]["code"] == "generation_expected_interruption_unproven"
    assert "crash" in metadata["diagnostic"]["functions"]
    assert (
        generation.GenerationQualification._api_projection(
            {
                "status": 200,
                "body": {"ok": False, "error_code": PASSPHRASE, "configuration": PASSPHRASE},
            }
        )["error_code"]
        is None
    )


@pytest.mark.parametrize(
    "condition",
    ["control_missing", "bad_identity", "api_wrong_success", "same_keys", "session_revoked"],
)
def test_no_component_pass_when_pending_refusal_signal_restore_or_session_proof_fails(condition):
    value, h, receipts, prep = qualification()
    setattr(h, condition, condition not in {"same_keys", "session_revoked"})
    with pytest.raises(generation.FailureEvidenceError, match="failure_component_failed"):
        value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")][
        -1
    ]
    assert metadata["result"] == "FAILED"
    assert not any(
        data.get("result") == "PACKET_COMPONENT_PASS" for data in receipts.values.values()
    )
    assert h.fault_calls == [("b", "handshake_off")]
    for secret in h.secret_values:
        assert secret not in json.dumps(receipts.values)


def test_emitted_readonly_state_and_identity_pinned_kill_programs_compile_without_state_mutation():
    compile(generation.INVENTORY_PROGRAM, "<inventory>", "exec")
    compile(generation.KILL_PROGRAM, "<kill>", "exec")
    assert ".validate()" in generation.INVENTORY_PROGRAM
    assert "i.config.private_key)" in generation.INVENTORY_PROGRAM  # derive public key only
    assert "private_key=" not in generation.INVENTORY_PROGRAM
    assert "parts[19]" in generation.KILL_PROGRAM and "pcmd[1:4]" in generation.KILL_PROGRAM
    assert "signal.SIGKILL" in generation.KILL_PROGRAM
    assert (
        ".write" not in generation.INVENTORY_PROGRAM
        and "DELETE" not in generation.INVENTORY_PROGRAM
    )
    assert (
        "h.fault(" not in (ROOT / "scripts/qualification/container_host_generation.py").read_text()
    )


def test_cli_rejects_backup_path_before_process_and_uses_no_passphrase_argv():
    value, h, _receipts, _prep = qualification()
    with pytest.raises(generation.FailureEvidenceError, match="backup_name_invalid"):
        value._cli("restore", name="../other.elbackup", passphrase="synthetic-test-only")
    assert not h.calls


@pytest.mark.parametrize(
    "passphrase",
    [
        None,
        123,
        "short",
        "x" * 1025,
        "synthetic-test\nsecret",
        "synthetic-test\rsecret",
        "synthetic-test\0secret",
    ],
)
def test_invalid_caller_passphrase_is_rejected_before_any_request_state_read_or_mutation(
    passphrase,
):
    h, receipts = Harness(), MemoryReceipts()
    value = generation.GenerationQualification(h, ["external-captures"], receipts=receipts)
    with pytest.raises(
        generation.FailureEvidenceError, match="generation_passphrase_invalid"
    ) as error:
        value.run(catalog_preparation=None, passphrase=passphrase)
    assert str(error.value) == "generation_passphrase_invalid"
    assert not h.calls and not h.api_calls and not h.fault_calls and not receipts.values


def test_caller_retains_recovery_phrase_when_control_fails_without_driver_disclosure():
    value, h, receipts, prep = qualification()
    h.control_missing = True
    phrase = PASSPHRASE
    with pytest.raises(generation.FailureEvidenceError) as error:
        value.run(catalog_preparation=prep, passphrase=phrase)
    assert phrase == PASSPHRASE and h.secret_values == [phrase]
    assert phrase not in str(error.value) and phrase not in json.dumps(receipts.values)
    assert phrase not in str([arguments for arguments, _stdin in h.calls])


def test_pending_guard_refuses_changed_generation_or_automatic_promotion_even_when_management_ready():
    value, h, _receipts, _prep = qualification()
    expected = {
        "selected_provider": "mullvad",
        "intents": [
            {
                "provider": "pia",
                "status": "pending",
                "generation": "candidate-generation",
                "interface": "wg-pia",
                "endpoint": "192.0.0.10",
            }
        ],
    }
    h.pending = h.refused = h.healthy_pending_management = True
    h.worker = [20, "1300"]
    assert value._pending_safe(expected, [18, "1100"])
    changed = json.loads(json.dumps(expected))
    changed["intents"][0]["generation"] = "different-generation"
    value._inventory = lambda: changed
    with pytest.raises(generation.FailureEvidenceError, match="generation_baseline_invalid"):
        value._pending_safe(expected, [18, "1100"])
    changed["intents"][0]["generation"] = "candidate-generation"
    changed["intents"][0]["status"] = "active"
    with pytest.raises(generation.FailureEvidenceError, match="generation_baseline_invalid"):
        value._pending_safe(expected, [18, "1100"])


def test_pending_blocked_packet_failure_never_claims_pass_or_auto_restores():
    value, h, receipts, prep = qualification()
    h.reject_steady = True
    with pytest.raises(generation.FailureEvidenceError):
        value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    assert not h.restore_called
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")][
        -1
    ]
    assert metadata["result"] == "FAILED" and metadata["transition"]
    assert PASSPHRASE not in json.dumps(receipts.values)


def test_pending_readiness_tolerates_exact_transient_control_unavailability_then_reads_stable_state():
    value, h, _receipts, _prep = qualification()
    h.pending = h.refused = True
    expected = value._inventory()
    original_cli = value._cli
    calls = []

    def transient(command):
        calls.append(command)
        if len(calls) == 1:
            raise generation.FailureEvidenceError("generation_control_unavailable")
        return original_cli(command)

    value._cli = transient
    assert value._pending_safe(expected, [18, "1100"]) is False
    assert value.last_control_status == {"probe": "control_temporarily_unavailable"}
    assert value._pending_safe(expected, [18, "1100"])["inventory"] == expected
    assert calls == ["status", "status"]
    assert not h.fault_calls and not h.restore_called


def test_permanent_control_unavailability_fails_existing_bounded_gate_and_preserves_pending_evidence():
    value, h, receipts, prep = qualification()
    h.control_missing = True
    with pytest.raises(generation.FailureEvidenceError, match="failure_component_failed"):
        value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")][
        -1
    ]
    assert metadata["result"] == "FAILED"
    assert metadata["next_gate"] == "pending_startup_safe"
    assert metadata["last_control_status"] == {"probe": "control_temporarily_unavailable"}
    assert metadata["pending_inventory"]["intents"][0]["status"] == "pending"
    assert not h.restore_called and h.fault_calls == [("b", "handshake_off")]


def test_pending_readiness_does_not_hide_malformed_control_or_other_known_errors():
    value, _h, _receipts, _prep = qualification()

    def malformed(_command):
        return {"state": "ready", "worker_running": "true"}

    value._cli = malformed
    with pytest.raises(
        generation.FailureEvidenceError, match="generation_control_contract_invalid"
    ):
        value._pending_safe({}, [18, "1100"])

    def other(_command):
        raise generation.FailureEvidenceError("generation_control_contract_invalid")

    value._cli = other
    with pytest.raises(
        generation.FailureEvidenceError, match="generation_control_contract_invalid"
    ):
        value._pending_safe({}, [18, "1100"])


def test_blocked_startup_is_polled_before_inventory_then_stable_pending_is_verified():
    value, h, _receipts, _prep = qualification()
    h.pending = h.refused = True
    expected = value._inventory()
    original_cli, original_inventory = value._cli, value._inventory
    states = [
        {"state": "blocked", "available": True, "recovery_required": False, "worker_running": False}
    ]
    value._cli = lambda command: states.pop(0) if states else original_cli(command)
    value._inventory = lambda: pytest.fail(
        "blocked startup must not inspect transitional inventory"
    )
    assert value._pending_safe(expected, [18, "1100"]) is False
    assert value.last_control_status == {
        "state": "blocked",
        "available": True,
        "recovery_required": False,
        "worker_running": False,
    }
    value._inventory = original_inventory
    assert value._pending_safe(expected, [18, "1100"])["inventory"] == expected
    assert not h.fault_calls


def test_permanent_documented_blocked_state_times_out_without_restore_or_false_component_pass():
    value, h, receipts, prep = qualification()
    original_cli = value._cli

    def blocked(command, **kwargs):
        if command == "status":
            return {
                "state": "blocked",
                "available": True,
                "recovery_required": False,
                "worker_running": False,
            }
        return original_cli(command, **kwargs)

    value._cli = blocked
    with pytest.raises(generation.FailureEvidenceError, match="failure_component_failed"):
        value.run(catalog_preparation=prep, passphrase=PASSPHRASE)
    metadata = [data for name, data in receipts.values.items() if name.endswith("-metadata.json")][
        -1
    ]
    assert metadata["result"] == "FAILED" and metadata["last_control_status"]["state"] == "blocked"
    assert not h.restore_called and h.fault_calls == [("b", "handshake_off")]


def test_unknown_status_state_is_not_classified_as_a_documented_startup_transient():
    value, _h, _receipts, _prep = qualification()
    value._cli = lambda _command: {
        "state": "invented",
        "available": True,
        "recovery_required": False,
        "worker_running": False,
    }
    with pytest.raises(
        generation.FailureEvidenceError, match="generation_control_contract_invalid"
    ):
        value._pending_safe({}, [18, "1100"])
