"""No infrastructure: actual tuple decoding and bounded coordinator contracts."""

import copy
import errno
import json
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/qualification"))
import container_host_output as output
from container_host_sender import packet

RUN = "0b0dcc00-ff11-4333-aaaa-012345678901"
PHASE = "output-synthetic"


def pcap(*packets, stamp=3):
    raw = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65575, 276)
    for body in packets:
        frame = b"\x08\x00" + b"\0" * 18 + body
        raw += struct.pack("<IIII", stamp, 0, len(frame), len(frame)) + frame
    return raw


def facts():
    return {
        "ready": True,
        "errors": [],
        "gaps": [],
        "drops": 0,
        "invalid_packets": 0,
        "ifindex": 9,
        "polls": 100,
        "max_poll_gap_ns": 1000,
        "start_ns": 1,
        "end_ns": 10**10,
        "last_poll_ns": 10**10,
        "samples": [],
        "calibration": [
            {
                "kind": k,
                "protocol": p,
                "ifindex": 9,
                "phase": "calibration",
                "sequence": 1,
                "observed_ns": 2 * 10**9,
                "source": "10.77.0.2",
                "destination": "1.1.1.1",
            }
            for k, p in output.STREAMS
        ],
    }


def attempt_receipt(phase=PHASE):
    return {
        "phase": phase,
        "start_ns": 3 * 10**9,
        "end_ns": 4 * 10**9,
        "namespace": [4, 100],
        "eth0_ifindex": 9,
        "attempts": [
            {"kind": k, "protocol": p, "sequence": n, "sent_ns": 3 * 10**9, "result": "submitted"}
            for n in range(1, 4)
            for k, p in output.STREAMS
        ],
    }


def handles():
    values = []
    roles = ["candidate-host", "candidate-namespace", "wan", "provider-a", "provider-b", "target"]
    for n, role in enumerate(roles):
        token = f"{n:032x}"
        h = {
            "role": role,
            "kind": "capture",
            "root": "/run/exitlane-d6-" + token,
            "unit": "exitlane-d6-capture-" + token + ".service",
        }
        if role.startswith("candidate-"):
            h.update(
                host="candidate",
                namespace=role.endswith("namespace"),
                container_pid=123,
                interfaces=["eth0", "wg-office"]
                if role.endswith("namespace")
                else ["eth0", "ed6-bridge"],
            )
        else:
            h.update(
                host="peer",
                namespace=None
                if role == "wan"
                else "ed6-"
                + RUN.replace("-", "")[:10]
                + "-"
                + {"provider-a": "a", "provider-b": "b", "target": "target"}[role],
                interfaces=["eth0"]
                if role == "wan"
                else ["pa", "pb", "uplink"]
                if role == "target"
                else ["wg-peer", "target"],
            )
        values.append(h)
    return values


def test_empty_syn_and_rst_are_detected_without_payload_marker():
    raw = packet("10.64.0.2", PHASE, 1, "protected", "tcp")[:40]
    for flag in (2, 4):
        value = bytearray(raw)
        value[33] = flag
        value[2:4] = struct.pack("!H", len(value))
        result = output.scan_pcap(pcap(bytes(value)), 2 * 10**9, 4 * 10**9)
        assert len(result["tuples"]) == 1 and result["tuples"][0]["destination_port"] == 7778
        assert "exitlane" not in json.dumps(result)


@pytest.mark.parametrize("kind,protocol", output.STREAMS)
def test_all_five_probe_tuples_are_detected(kind, protocol):
    raw = packet("10.65.0.2", PHASE, 1, kind, protocol, dns="10.65.0.1")
    result = output.scan_pcap(pcap(raw), 2 * 10**9, 4 * 10**9)
    assert result["tuples"][0]["protocol"] == protocol


def test_quoted_icmp_error_identifies_the_unmarked_original_dns_tuple():
    quote = packet("10.66.0.2", PHASE, 1, "dns", "tcp", dns="10.66.0.1")[:28]
    outer = bytearray(packet("10.66.0.2", PHASE, 1, "protected", "icmp")[:20])
    outer[12:16] = bytes([172, 16, 0, 1])
    outer[16:20] = bytes([10, 66, 0, 2])
    outer[2:4] = struct.pack("!H", len(outer) + 8 + len(quote))
    result = output.scan_pcap(
        pcap(bytes(outer) + b"\x03\x03" + b"\0" * 6 + quote), 2 * 10**9, 4 * 10**9
    )
    assert result["tuples"][0]["quoted"] is True and result["tuples"][0]["destination_port"] == 53


def test_control_plane_and_encrypted_outer_packets_are_excluded():
    raw = bytearray(packet("10.64.0.2", PHASE, 1, "protected", "udp"))
    raw[16:20] = bytes([192, 0, 0, 9])
    raw[22:24] = struct.pack("!H", 51820)
    assert output.scan_pcap(pcap(bytes(raw)), 2 * 10**9, 4 * 10**9)["tuples"] == []


@pytest.mark.parametrize("change", ["truncated", "fragment", "bad_header"])
def test_incomplete_pcap_cannot_prove_zero(change):
    raw = bytearray(packet("10.64.0.2", PHASE, 1, "protected", "udp"))
    if change == "fragment":
        raw[6:8] = struct.pack("!H", 0x2000)
    value = pcap(bytes(raw))
    if change == "truncated":
        value = value[:-1]
    if change == "bad_header":
        value = b"x" + value[1:]
    with pytest.raises(output.OutputEvidenceError):
        output.scan_pcap(value, 2 * 10**9, 4 * 10**9)


@pytest.mark.parametrize(
    "field,value",
    [
        ("ready", False),
        ("drops", 1),
        ("gaps", ["interface_lost"]),
        ("max_poll_gap_ns", 1000000001),
        ("end_ns", 3 * 10**9),
        ("calibration", []),
        ("ifindex", 0),
    ],
)
def test_observer_holes_and_uncalibrated_zeros_are_rejected(field, value):
    record = facts()
    record[field] = value
    with pytest.raises(output.OutputEvidenceError):
        output.validate_observer(record, 3 * 10**9, 4 * 10**9)


def test_wrong_capture_generation_calibration_rejected():
    record = facts()
    record["calibration"][0]["ifindex"] = 999
    with pytest.raises(output.OutputEvidenceError, match="output_sample_invalid"):
        output.validate_observer(record, 3 * 10**9, 4 * 10**9)


def test_syscall_manifest_requires_all_fifteen_numbered_real_attempts():
    value = attempt_receipt()
    value["attempts"].pop()
    with pytest.raises(output.OutputEvidenceError, match="output_attempts_missing"):
        output.validate_output(value, {}, {}, expected="blocked")


def test_unknown_errno_is_not_a_proven_kernel_refusal():
    value = attempt_receipt()
    value["attempts"][0].update(result="refused", errno=errno.EBADF)
    with pytest.raises(output.OutputEvidenceError, match="output_attempts_invalid"):
        output.validate_output(value, {}, {}, expected="blocked")


def empty_evidence():
    pcaps = {h["role"]: {i: {"tuples": []} for i in h["interfaces"]} for h in handles()}
    observations = {h["role"] + ":" + i: facts() for h in handles() for i in h["interfaces"]}
    return observations, pcaps


def test_plaintext_syn_on_any_forbidden_plane_fails_even_without_marker():
    for role in ("wan", "target", "provider-a", "candidate-host", "candidate-namespace"):
        observations, pcaps = empty_evidence()
        interface = next(iter(pcaps[role]))
        pcaps[role][interface]["tuples"] = [{"protocol": "tcp"}]
        with pytest.raises(output.OutputEvidenceError, match="output_plaintext_detected"):
            output.validate_output(attempt_receipt(), observations, pcaps, expected="blocked")


def test_optional_positive_requires_all_five_actual_provider_samples():
    observations, pcaps = empty_evidence()
    with pytest.raises(output.OutputEvidenceError, match="output_positive_delivery_missing"):
        output.validate_output(
            attempt_receipt(),
            observations,
            pcaps,
            expected="provider_or_block",
            require_delivery=True,
            capture_windows={p: [3 * 10**9, 4 * 10**9] for p in observations},
        )
    observations["provider-a:wg-peer"]["samples"] = [
        {
            "phase": PHASE,
            "kind": k,
            "protocol": p,
            "sequence": 1,
            "observed_ns": 3 * 10**9,
            "ifindex": 9,
            "source": "10.64.0.2",
            "destination": "1.1.1.1",
        }
        for k, p in output.STREAMS
    ]
    output.validate_output(
        attempt_receipt(),
        observations,
        pcaps,
        expected="provider_or_block",
        require_delivery=True,
        capture_windows={p: [3 * 10**9, 4 * 10**9] for p in observations},
    )


def test_empty_omitted_topology_is_not_negative_proof():
    with pytest.raises(output.OutputEvidenceError, match="output_topology_incomplete"):
        output.validate_output(attempt_receipt(), {}, {}, expected="blocked")


@pytest.mark.parametrize(
    "change", ["missing_role", "empty_interfaces", "wrong_namespace", "duplicate_unit"]
)
def test_false_topology_cannot_be_passed_as_empty_observations(change):
    values = handles()
    if change == "missing_role":
        values.pop()
    if change == "empty_interfaces":
        values[0]["interfaces"] = []
    if change == "wrong_namespace":
        values[-1]["namespace"] = "unrelated-guest"
    if change == "duplicate_unit":
        values[1]["unit"] = values[0]["unit"]
    with pytest.raises(output.OutputEvidenceError):
        output.validate_handles(values, RUN)


def test_fixed_remote_programs_compile_without_untrusted_imports_or_device_binding():
    program = output._program(
        [
            output.OutputEvidenceError,
            output._require,
            output.checksum,
            output.dns_query,
            output.packet,
            output.inject,
        ]
    )
    compile(program, "<injector>", "exec")
    compile(output.PUBLIC_STATE, "<public-inventory>", "exec")
    assert (
        "SO_BINDTODEVICE" not in program
        and "setconf" not in program
        and "route replace" not in program
    )
    assert "private_key" not in output.PUBLIC_STATE and "NET_RAW" not in output.PUBLIC_STATE


class Harness:
    container = "owned-disposable"

    def __init__(self):
        self.config = {"run_id": RUN, "image": "sha256:" + "a" * 64}
        self.phases = {}
        self.events = []

    def assert_disposable(self):
        self.events.append("disposable")

    def assert_owned(self, kind, name):
        self.events.append("ownership")
        return {"State": {"Pid": 123}, "Image": "sha256:" + "b" * 64}

    def measure_clock(self, *, token):
        assert token == "a" * 64
        after = bool(self.phases)
        stamp = 6 * 10**9 if after else 10**9
        return {
            "reference_boot_id": RUN,
            "measurement": {
                "local_before_ns": stamp,
                "local_after_ns": stamp + 1000,
                "reference_ns": stamp + 500,
            },
        }

    def evidence(self, handle):
        return {
            "phase": self.phases.get(handle["unit"], "prior"),
            "captures": {name: facts() for name in handle["interfaces"]},
        }

    def control(self, handle, phase, **kwargs):
        self.phases[handle["unit"]] = phase

    def wait(self, probe, stage, timeout):
        assert probe() and timeout <= 20


class Receipts:
    def __init__(self):
        self.values = []

    def write(self, name, value):
        self.values.append(copy.deepcopy(value))


class Driver(output.OutputQualification):
    def _pin_topology(self):
        return {"candidate_uplink": "eth0", "peer_uplink": "eth0", "docker_bridge": "ed6-bridge"}

    def capture_source(self, provider):
        result = super().capture_source(provider)
        self.unmarked_controls = {
            h["role"] + ":" + i: {"tcp_syn", "tcp_rst", "icmp_quote"}
            for h in self.captures
            for i in h["interfaces"]
            if i != "wg-office"
        }
        self.unmarked_ifindexes = {p: 9 for p in self.unmarked_controls}
        return result

    def _state(self):
        return {
            "sources": ["10.64.0.2"],
            "selected_provider": "mullvad",
            "intents": [
                {
                    "provider": "mullvad",
                    "status": "active",
                    "source": "10.64.0.2/32",
                    "generation": "actual-active-generation",
                    "endpoint": "192.0.0.9",
                }
            ],
        }

    def _inject(self, receipt, phase):
        return attempt_receipt(phase)

    def _pcaps(self, handle, start, end):
        return {
            name: {"tuples": [], "sha256": "a" * 64, "path": handle["root"] + "/" + name + ".pcap"}
            for name in handle["interfaces"]
        }


def test_bounded_run_reuses_clock_and_capture_controls_without_mutating_product():
    h, receipts = Harness(), Receipts()
    q = Driver(h, handles(), receipts=receipts)
    source = q.capture_source("mullvad")
    result = q.run(source, clock_token="a" * 64)
    assert result["result"] == "OUTPUT_COMPONENT_PASS"
    assert (
        result["production_support"] is False
        and "kernel_reply_forms_outstanding" in result["limitations"]
    )
    assert "a" * 64 not in json.dumps(result["clock_alignment"])
    assert result["source"]["generation"] == "actual-active-generation"


def test_forged_source_and_invalid_topology_fail_before_operation():
    h, receipts = Harness(), Receipts()
    q = Driver(h, handles(), receipts=receipts)
    source = q.capture_source("mullvad")
    source["source"] = "10.65.0.2"
    with pytest.raises(output.OutputEvidenceError):
        q.run(
            source,
            clock_token="a" * 64,
            operation=lambda: pytest.fail("mutation before validation"),
        )


def test_operation_failure_retains_private_static_failure_without_secret_text():
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")

    def failure():
        raise RuntimeError("synthetic-secret-never-print")

    with pytest.raises(output.OutputEvidenceError, match="output_evidence_unproven") as caught:
        q.run(source, clock_token="a" * 64, operation=failure)
    assert "synthetic-secret" not in str(caught.value)
    assert q.receipts.values[-1]["result"] == "FAIL"
    assert "synthetic-secret" not in json.dumps(q.receipts.values)


def test_injector_checks_namespace_and_never_accepts_setup_failure_as_send_refusal(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(output.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        output.Path,
        "stat",
        lambda path: SimpleNamespace(
            st_dev=4, st_ino=100 if str(path) == "/proc/self/ns/net" else 999
        ),
    )
    monkeypatch.setattr(output.socket, "if_nametoindex", lambda name: 2)

    class BrokenSocket:
        def setsockopt(self, *arguments):
            raise OSError(errno.EPERM, "synthetic-private-detail")

        def close(self):
            pass

    monkeypatch.setattr(output.socket, "socket", lambda *arguments: BrokenSocket())
    with pytest.raises(output.OutputEvidenceError, match="output_syscall_unproven") as caught:
        output.inject(
            {
                "source": "10.64.0.2",
                "dns": "10.64.0.1",
                "phase": PHASE,
                "namespace": [4, 100],
                "eth0_ifindex": 2,
            }
        )
    assert "synthetic-private-detail" not in str(caught.value)


def test_actual_injector_submits_all_protocols_with_freebind_and_no_forced_device(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(output.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        output.Path,
        "stat",
        lambda path: SimpleNamespace(
            st_dev=4, st_ino=100 if str(path) == "/proc/self/ns/net" else 999
        ),
    )
    monkeypatch.setattr(output.socket, "if_nametoindex", lambda name: 2)
    monkeypatch.setattr(output.time, "sleep", lambda seconds: None)
    events = []

    class Socket:
        def setsockopt(self, *arguments):
            events.append(("option", arguments))

        def settimeout(self, seconds):
            assert seconds == 0.3

        def bind(self, address):
            assert address == ("10.64.0.2", 0)

        def connect(self, address):
            events.append(("tcp", address))

        def sendall(self, body):
            events.append(("body", len(body)))

        def sendto(self, body, address):
            events.append(("sendto", address))
            return len(body)

        def close(self):
            pass

    monkeypatch.setattr(output.socket, "socket", lambda *arguments: Socket())
    result = output.inject(
        {
            "source": "10.64.0.2",
            "dns": "10.64.0.1",
            "phase": PHASE,
            "namespace": [4, 100],
            "eth0_ifindex": 2,
        }
    )
    assert len(result["attempts"]) == 15 and all(
        i["result"] == "submitted" for i in result["attempts"]
    )
    assert [v for kind, v in events if kind == "option"] == [(output.socket.SOL_IP, 15, 1)] * 15
    assert ("tcp", ("10.64.0.1", 53)) in events and ("tcp", ("1.1.1.1", 7778)) in events


def test_namespace_mismatch_stops_before_opening_any_probe_socket(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(output.os, "geteuid", lambda: 0)
    monkeypatch.setattr(output.Path, "stat", lambda path: SimpleNamespace(st_dev=4, st_ino=100))
    monkeypatch.setattr(
        output.socket, "socket", lambda *args: pytest.fail("probe opened in foreign namespace")
    )
    with pytest.raises(output.OutputEvidenceError, match="output_namespace_unproven"):
        output.inject(
            {
                "source": "10.64.0.2",
                "dns": "10.64.0.1",
                "phase": PHASE,
                "namespace": [4, 999],
                "eth0_ifindex": 2,
            }
        )


def test_remote_injector_is_root_host_only_and_contains_fresh_owned_label_and_pinned_fd_checks():
    class Remote:
        def run(self, source, *, data, timeout):
            compile(source, "<host-namespace-wrapper>", "exec")
            compile(data["program"], "<owned-namespace-injector>", "exec")
            assert "verified['Config']['Labels'].get('org.exitlane.qualification.run')" in source
            assert "os.open('/proc/'+str(pid)+'/ns/net'" in source
            assert "pass_fds=(fd,)" in source and "--net=/proc/self/fd/" in source
            assert data["run_id"] == RUN and timeout == 30
            return json.dumps(attempt_receipt(data["phase"]))

    h = Harness()
    h.candidate = Remote()
    value = output.OutputQualification(h, handles(), receipts=Receipts())._inject(
        {"source": "10.64.0.2", "running_image": "sha256:" + "b" * 64}, PHASE
    )
    assert value["phase"] == PHASE


def test_retired_real_generation_remains_a_bound_source_without_rewriting_state():
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    q._state = lambda: {
        "sources": ["10.64.0.2", "10.65.0.2"],
        "selected_provider": "pia",
        "intents": [],
    }
    result = q.run(source, clock_token="a" * 64, expected="provider_or_block")
    assert result["source"]["generation"] == "actual-active-generation"
    assert result["result"] == "OUTPUT_COMPONENT_PASS"


def test_source_missing_from_exact_live_guard_fails_before_requested_operation():
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    q._state = lambda: {"sources": [], "selected_provider": "pia", "intents": []}
    with pytest.raises(output.OutputEvidenceError, match="output_source_unproven"):
        q.run(source, clock_token="a" * 64, operation=lambda: pytest.fail("unguarded source"))


def test_remote_pcap_reader_is_regular_root_private_nofollow_nonblocking_and_bounded():
    class Remote:
        def run(self, source, *, data, output_limit):
            compile(source, "<pcap-projection>", "exec")
            assert "os.O_NOFOLLOW|os.O_NONBLOCK" in source
            assert "stat.S_ISREG" in source and "stat.S_IMODE(f.st_mode)==0o600" in source
            assert "raw=stream.read(f.st_size)" in source
            assert output_limit <= 8 * 1024 * 1024
            return "{}"

    h = Harness()
    h.peer = Remote()
    output.OutputQualification(h, handles(), receipts=Receipts())._pcaps(handles()[-1], 1, 2)


def test_acceptance_failure_receipt_keeps_static_reason_stage_and_original_raw_paths():
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    original = q._pcaps

    def dirty(handle, start, end):
        value = original(handle, start, end)
        if handle["role"] == "wan":
            value["eth0"]["tuples"] = [{"protocol": "tcp"}]
        return value

    q._pcaps = dirty
    with pytest.raises(output.OutputEvidenceError):
        q.run(source, clock_token="a" * 64)
    failure = q.receipts.values[-1]
    assert (
        failure["error"] == "output_plaintext_detected" and failure["stage"] == "output_acceptance"
    )
    assert failure["pcaps"]["wan"]["eth0"]["path"].endswith("/eth0.pcap")
    assert len(failure["last_captures"]) == 6


@pytest.mark.parametrize(
    "field,value",
    [
        ("phase", "wrong"),
        ("sequence", 0),
        ("observed_ns", 0),
        ("observed_ns", 4 * 10**9),
        ("source", None),
        ("destination", "invalid"),
        ("ifindex", True),
    ],
)
def test_calibration_identity_timestamp_and_addresses_are_real_evidence(field, value):
    record = facts()
    record["calibration"][0][field] = value
    with pytest.raises(output.OutputEvidenceError):
        output.validate_observer(record, 3 * 10**9, 4 * 10**9)


@pytest.mark.parametrize(
    "field,value",
    [("observed_ns", 2 * 10**9), ("ifindex", 99), ("sequence", 4), ("phase", "unrelated")],
)
def test_positive_delivery_rejects_wrong_window_generation_or_identity(field, value):
    observations, pcaps = empty_evidence()
    samples = [
        {
            "phase": PHASE,
            "kind": k,
            "protocol": p,
            "sequence": 1,
            "observed_ns": 3 * 10**9,
            "ifindex": 9,
            "source": "10.64.0.2",
            "destination": "1.1.1.1",
        }
        for k, p in output.STREAMS
    ]
    samples[0][field] = value
    observations["provider-a:wg-peer"]["samples"] = samples
    with pytest.raises(output.OutputEvidenceError):
        output.validate_output(
            attempt_receipt(),
            observations,
            pcaps,
            expected="provider_or_block",
            require_delivery=True,
            capture_windows={p: [3 * 10**9, 4 * 10**9] for p in observations},
        )


@pytest.mark.parametrize("tags", [1, 2, 3])
def test_sll2_tagged_control_forms_are_parsed_or_explicitly_rejected(tags):
    raw = output.calibration_packets("10.64.0.2", PHASE)[0]
    frame = b"\x81\x00" + b"\0" * 18
    frame += (
        b"".join(struct.pack("!HH", 135, 0x0800 if n == tags - 1 else 0x88A8) for n in range(tags))
        + raw
    )
    value = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65575, 276)
        + struct.pack("<IIII", 3, 0, len(frame), len(frame))
        + frame
    )
    if tags == 3:
        with pytest.raises(output.OutputEvidenceError, match="output_link_unsupported"):
            output.scan_pcap(value, 2 * 10**9, 4 * 10**9)
    else:
        assert output.scan_pcap(value, 2 * 10**9, 4 * 10**9)["tuples"][0]["form"] == "tcp_syn"


def test_raw_calibration_constructs_checksum_valid_empty_forms():
    packets = output.calibration_packets("10.64.0.2", "calibration")
    result = output.scan_pcap(pcap(*packets), 2 * 10**9, 4 * 10**9)
    assert {t["form"] for t in result["tuples"]} == {"tcp_syn", "tcp_rst", "icmp_quote"}
    for raw in packets:
        assert output.checksum(raw[:20]) == 0
        assert len(raw) == struct.unpack("!H", raw[2:4])[0]
        if raw[9] == 6:
            assert (
                output.checksum(raw[12:20] + struct.pack("!BBH", 0, 6, len(raw) - 20) + raw[20:])
                == 0
            )
        else:
            assert output.checksum(raw[20:]) == 0


def test_running_digest_is_distinct_from_base_image_and_rechecked_before_probes():
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    assert (
        source["image"] == "sha256:" + "a" * 64 and source["running_image"] == "sha256:" + "b" * 64
    )
    q.h.assert_owned = lambda *args: {"State": {"Pid": 123}, "Image": "sha256:" + "c" * 64}
    with pytest.raises(output.OutputEvidenceError, match="output_image_changed"):
        q.run(source, clock_token="a" * 64, operation=lambda: pytest.fail("changed image"))


def test_marker_calibration_alone_cannot_prove_unmarked_controls_sensitive():
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    q.unmarked_controls = {}
    with pytest.raises(output.OutputEvidenceError, match="output_unmarked_calibration_missing"):
        q.run(source, clock_token="a" * 64, operation=lambda: pytest.fail("uncalibrated raw forms"))


def test_reply_packets_are_real_peer_to_candidate_requests_not_response_programs():
    frames = output.kernel_packets("10.64.0.2", PHASE)
    assert all(
        raw[12:16] == bytes([10, 64, 0, 1]) and raw[16:20] == bytes([10, 64, 0, 2])
        for raw in frames
    )
    assert frames[0][20] == 8 and frames[1][33] == 2
    program = output._program(
        [
            output.OutputEvidenceError,
            output._require,
            output.checksum,
            output.dns_query,
            output.packet,
            output.kernel_packets,
            output.inject_kernel_requests,
        ]
    )
    compile(program, "<kernel-peer-request>", "exec")
    assert "recv" not in program and "NET_ADMIN" not in program


def kernel_evidence():
    obs, raw = empty_evidence()
    phase = "kernel-output-synthetic"
    sample = {
        "kind": "protected",
        "protocol": "icmp",
        "phase": phase,
        "sequence": 1,
        "ifindex": 9,
        "observed_ns": 3 * 10**9,
        "source": "10.64.0.2",
        "destination": "10.64.0.1",
    }
    obs["provider-a:wg-peer"]["samples"] = [sample]
    raw["provider-a"]["wg-peer"]["tuples"] = [
        {"form": "icmp_reply", "source": "10.64.0.2", "destination": "10.64.0.1"},
        {
            "form": "tcp_rst",
            "source": "10.64.0.2",
            "destination": "10.64.0.1",
            "source_port": 7778,
            "destination_port": 30001,
        },
    ]
    windows = {p: [3 * 10**9, 4 * 10**9] for p in obs}
    return obs, raw, windows


def test_true_kernel_echo_and_rst_require_reverse_source_and_correlated_marker():
    obs, raw, windows = kernel_evidence()
    source = {"source": "10.64.0.2", "endpoint": "192.0.0.9"}
    output.validate_kernel_replies(source, "kernel-output-synthetic", obs, raw, windows)
    raw["provider-a"]["wg-peer"]["tuples"][1]["source"] = "10.64.0.1"
    with pytest.raises(output.OutputEvidenceError, match="output_kernel_reply_unproven"):
        output.validate_kernel_replies(source, "kernel-output-synthetic", obs, raw, windows)


def test_reply_counter_or_userspace_placeholder_is_not_kernel_proof():
    obs, raw, windows = kernel_evidence()
    obs["provider-a:wg-peer"]["samples"] = []
    with pytest.raises(output.OutputEvidenceError, match="output_kernel_reply_unproven"):
        output.validate_kernel_replies(
            {"source": "10.64.0.2", "endpoint": "192.0.0.9"},
            "kernel-output-synthetic",
            obs,
            raw,
            windows,
        )


def test_arbitrary_calibrated_bridge_or_wan_cannot_replace_actual_owned_topology():
    class TopologyHarness(Harness):
        network = "owned-network"
        candidate = object()
        peer = object()

        def __init__(self):
            super().__init__()
            self.config["candidate"] = {"address": "172.16.0.123"}

        def assert_owned(self, *args):
            return {"Options": {"com.docker.network.bridge.name": "ed6-actual"}, "Id": "a" * 64}

        def command(self, host, argv):
            return {"code": 0, "stdout": json.dumps([{"dev": "eth0"}])}

    q = output.OutputQualification(TopologyHarness(), handles(), receipts=Receipts())
    with pytest.raises(output.OutputEvidenceError, match="output_topology_incomplete"):
        q._pin_topology()


def test_kernel_reply_coordinator_uses_real_peer_namespace_and_closed_port_readback():
    class Peer:
        def run(self, source, *, data, timeout):
            compile(source, "<kernel-host-wrapper>", "exec")
            compile(data["program"], "<kernel-requests>", "exec")
            assert data["namespace"] == "ed6-" + RUN.replace("-", "")[:10] + "-a"
            assert data["source"] == "10.64.0.2" and data["ifindex"] == 9
            assert "pass_fds=(fd,)" in source and "os.O_NOFOLLOW" in source
            return json.dumps(
                {"start_ns": 3 * 10**9, "end_ns": 4 * 10**9, "kernel_request_count": 2}
            )

    class KernelHarness(Harness):
        peer = Peer()

        def __init__(self):
            super().__init__()
            self.clock_count = 0

        def command(self, host, argv, **kwargs):
            action = argv[-1]
            if action == "ownership":
                value = {
                    "run_id": RUN,
                    "role": "a",
                    "namespace": "ed6-" + RUN.replace("-", "")[:10] + "-a",
                    "namespace_inode": [4, 100],
                    "interface_ifindexes": {"wg-peer": 9},
                }
            elif action == "status":
                value = {
                    "peers": {
                        "a": {
                            "endpoint": "192.0.0.9",
                            "public_key": "public-fixture-only",
                            "port": 51820,
                        }
                    }
                }
            else:
                pytest.fail("unrelated peer command")
            return {"code": 0, "stdout": json.dumps(value)}

        def docker(self, *argv):
            if "ss" in argv:
                return {"code": 0, "stdout": ""}
            if "wg" in argv:
                return {"code": 0, "stdout": "public-fixture-only\t192.0.0.9:51820\n"}
            pytest.fail("unexpected candidate command")

        def evidence(self, handle):
            value = super().evidence(handle)
            if handle["role"] == "provider-a" and value["phase"].startswith("kernel-output-"):
                value["captures"]["wg-peer"]["samples"] = [
                    {
                        "kind": "protected",
                        "protocol": "icmp",
                        "phase": value["phase"],
                        "sequence": 1,
                        "ifindex": 9,
                        "observed_ns": 3 * 10**9,
                        "source": "10.64.0.2",
                        "destination": "10.64.0.1",
                    }
                ]
            return value

        def measure_clock(self, *, token):
            self.clock_count += 1
            stamp = (1 if self.clock_count == 1 else 6) * 10**9
            return {
                "reference_boot_id": RUN,
                "measurement": {
                    "local_before_ns": stamp,
                    "local_after_ns": stamp + 1000,
                    "reference_ns": stamp + 500,
                },
            }

    class KernelDriver(Driver):
        def _pcaps(self, handle, start, end):
            raw = super()._pcaps(handle, start, end)
            if handle["role"] == "provider-a":
                raw["wg-peer"]["tuples"] = kernel_evidence()[1]["provider-a"]["wg-peer"]["tuples"]
            return raw

    q = KernelDriver(KernelHarness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    result = q.kernel_reply(source, clock_token="a" * 64)
    assert result["result"] == "KERNEL_REPLY_COMPONENT_PASS"
    assert result["scope"] == ["kernel_icmp_echo_reply", "kernel_closed_port_tcp_rst"]
    assert result["production_support"] is False


@pytest.mark.parametrize("fault", ["missing_controls", "wrong_ifindex"])
def test_kernel_reply_cannot_inject_before_actual_raw_sensitivity_proof(fault):
    q = Driver(Harness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    if fault == "missing_controls":
        q.unmarked_controls = {}
    else:
        q.unmarked_ifindexes["wan:eth0"] = 999
    with pytest.raises(output.OutputEvidenceError, match="output_unmarked_calibration_missing"):
        q.kernel_reply(source, clock_token="a" * 64)


def test_nat_rewritten_plaintext_source_does_not_make_forbidden_plane_zero():
    raw = packet("172.28.0.20", PHASE, 1, "protected", "tcp")[:40]
    raw = raw[:2] + struct.pack("!H", 40) + raw[4:]
    scan = output.scan_pcap(pcap(raw), 2 * 10**9, 4 * 10**9)
    observations, pcaps = empty_evidence()
    pcaps["wan"]["eth0"] = scan
    assert scan["tuples"][0]["source"] == "172.28.0.20"
    with pytest.raises(output.OutputEvidenceError, match="output_plaintext_detected"):
        output.validate_output(attempt_receipt(), observations, pcaps, expected="provider_or_block")


@pytest.mark.parametrize("flag", [2, 4])
def test_marked_syn_or_rst_cannot_substitute_for_empty_segment_calibration(flag):
    raw = bytearray(packet("10.64.0.2", "calibration", 1, "protected", "tcp"))
    raw[33] = flag
    result = output.scan_pcap(pcap(bytes(raw)), 2 * 10**9, 4 * 10**9)
    assert result["tuples"][0]["form"] == "tcp" and result["tuples"][0]["empty_tcp"] is False
    # The packet remains forbidden on the normal uplink despite not providing
    # unmarked sensitivity calibration.
    observations, pcaps = empty_evidence()
    pcaps["wan"]["eth0"] = result
    with pytest.raises(output.OutputEvidenceError, match="output_plaintext_detected"):
        output.validate_output(attempt_receipt(), observations, pcaps, expected="provider_or_block")


def test_true_empty_controls_with_tcp_options_and_ethernet_padding_are_classified():
    raw = bytearray(output.calibration_packets("10.64.0.2", "calibration")[0])
    raw[32] = 0x60
    raw += b"\x01" * 4
    raw[2:4] = struct.pack("!H", 44)
    # A packet can carry link padding beyond its declared IP length; it is not
    # TCP payload and must not invalidate actual empty-SYN sensitivity.
    result = output.scan_pcap(pcap(bytes(raw) + b"\0" * 6), 2 * 10**9, 4 * 10**9)
    assert result["tuples"][0]["form"] == "tcp_syn" and result["tuples"][0]["empty_tcp"] is True


def test_malformed_tcp_header_length_never_becomes_an_empty_calibration():
    raw = bytearray(output.calibration_packets("10.64.0.2", "calibration")[0])
    raw[32] = 0xF0
    with pytest.raises(output.OutputEvidenceError, match="output_pcap_invalid"):
        output.scan_pcap(pcap(bytes(raw)), 2 * 10**9, 4 * 10**9)


def test_actual_calibration_ledger_remains_incomplete_if_syn_is_only_marked():
    class CalibrationHarness(Harness):
        def __init__(self):
            super().__init__()
            self.clock_count = 0

        def measure_clock(self, *, token):
            self.clock_count += 1
            stamp = (1 if self.clock_count == 1 else 6) * 10**9
            return {
                "reference_boot_id": RUN,
                "measurement": {
                    "local_before_ns": stamp,
                    "local_after_ns": stamp + 1000,
                    "reference_ns": stamp + 500,
                },
            }

    class CalibrationDriver(Driver):
        def _inject(self, receipt, phase, *, controls=False):
            return {"start_ns": 3 * 10**9, "end_ns": 4 * 10**9}

        def _pcaps(self, handle, start, end):
            control = output.calibration_packets("10.64.0.2", "calibration")
            raw = pcap(
                packet("10.64.0.2", "calibration", 1, "protected", "tcp"), control[1], control[2]
            )
            return {name: output.scan_pcap(raw, start, end) for name in handle["interfaces"]}

    q = CalibrationDriver(CalibrationHarness(), handles(), receipts=Receipts())
    source = q.capture_source("mullvad")
    q.unmarked_controls = {}
    q.unmarked_ifindexes = {}
    q.raw_calibration(source_receipt=source, clock_token="a" * 64)
    assert all("tcp_syn" not in forms for forms in q.unmarked_controls.values())
    with pytest.raises(output.OutputEvidenceError, match="output_unmarked_calibration_missing"):
        q.run(source, clock_token="a" * 64)


@pytest.mark.parametrize("source", ["10.64.0.2", "172.28.135.2"])
def test_constructed_raw_controls_bind_exact_source_before_every_send(monkeypatch, source):
    from types import SimpleNamespace

    monkeypatch.setattr(output.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        output.Path,
        "stat",
        lambda path: SimpleNamespace(
            st_dev=4, st_ino=100 if str(path) == "/proc/self/ns/net" else 999
        ),
    )
    monkeypatch.setattr(output.socket, "if_nametoindex", lambda name: 2)
    monkeypatch.setattr(output.time, "sleep", lambda seconds: None)
    events = []

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            events.append(("close", None))

        def bind(self, address):
            events.append(("bind", address))

        def sendto(self, raw, destination):
            assert events[0] == ("bind", (source, 0))
            assert raw[12:16] == output.ipaddress.IPv4Address(source).packed
            events.append(("send", destination))
            return len(raw)

    def create(*arguments):
        assert arguments == (
            output.socket.AF_INET,
            output.socket.SOCK_RAW,
            output.socket.IPPROTO_RAW,
        )
        return Socket()

    monkeypatch.setattr(output.socket, "socket", create)
    program = output._program(
        [
            output.OutputEvidenceError,
            output._require,
            output.checksum,
            output.dns_query,
            output.packet,
            output.calibration_packets,
            output.inject_controls,
        ]
    )
    namespace = {}
    exec(compile(program, "<actual-constructed-raw-controls>", "exec"), namespace)  # noqa: S102 - fixed reviewed program
    result = namespace["inject_controls"](
        {"source": source, "phase": "calibration", "namespace": [4, 100], "eth0_ifindex": 2}
    )
    assert events == [("bind", (source, 0))] + [("send", ("1.1.1.1", 0))] * 3 + [("close", None)]
    assert result["forms"] == ["tcp_syn", "tcp_rst", "icmp_quote"]
    # The socket has no setsockopt/SO_BINDTODEVICE seam: source routing remains
    # the real RPDB decision, not a forced successful provider interface.


@pytest.mark.parametrize(
    "stage,number",
    [
        ("bind", errno.EADDRNOTAVAIL),
        ("send", errno.EPERM),
        ("send", errno.EACCES),
        ("send", errno.ENETUNREACH),
    ],
)
def test_constructed_raw_control_refusal_never_returns_calibration_success(
    monkeypatch, stage, number
):
    from types import SimpleNamespace

    monkeypatch.setattr(output.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        output.Path,
        "stat",
        lambda path: SimpleNamespace(
            st_dev=4, st_ino=100 if str(path) == "/proc/self/ns/net" else 999
        ),
    )
    monkeypatch.setattr(output.socket, "if_nametoindex", lambda name: 2)
    events = []

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            events.append("closed")

        def bind(self, address):
            events.append("bind")
            if stage == "bind":
                raise OSError(number, "synthetic-error-detail")

        def sendto(self, raw, destination):
            events.append("send")
            raise OSError(number, "synthetic-error-detail")

    monkeypatch.setattr(output.socket, "socket", lambda *arguments: Socket())
    program = output._program(
        [
            output.OutputEvidenceError,
            output._require,
            output.checksum,
            output.dns_query,
            output.packet,
            output.calibration_packets,
            output.inject_controls,
        ]
    )
    namespace = {}
    exec(compile(program, "<actual-constructed-raw-controls>", "exec"), namespace)  # noqa: S102 - fixed reviewed program
    with pytest.raises(OSError) as caught:
        namespace["inject_controls"](
            {
                "source": "10.64.0.2",
                "phase": "calibration",
                "namespace": [4, 100],
                "eth0_ifindex": 2,
            }
        )
    assert caught.value.errno == number
    assert events == ["bind"] + (["send"] if stage == "send" else []) + ["closed"]
