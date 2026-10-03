"""Actual loopback certificate verification and mocked Docker boundary checks."""

from __future__ import annotations

import importlib.util
import json
import ssl
import subprocess
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts/qualification" / (name + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = load("container_tls_probe")
harness = load("container_tls")
IMAGE = "sha256:" + "a" * 64
REVISION = "b" * 40


def valid_receipt():
    return {
        "type": "provider-tls-loopback",
        "scope": probe.SCOPE,
        "result": "PASS",
        "code": None,
        "python": "3.13.5",
        "openssl": "OpenSSL 3.5.7 9 Jun 2026",
        "clients_sha256": {"mullvad": "a" * 64, "pia_api": "b" * 64},
        "checks": [
            {
                "client": client,
                "condition": condition,
                "result": "PASS",
                "http_requests": 1 if condition == "valid" else 0,
                "verify_code": probe.VERIFY_CODES.get(condition),
            }
            for condition in probe.CONDITIONS
            for client in probe.CLIENTS
        ],
    }


def image_facts():
    return {
        "Id": IMAGE,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "Labels": {
                "org.opencontainers.image.source": harness.SOURCE,
                "org.opencontainers.image.revision": REVISION,
                "org.opencontainers.image.version": "v0.3.0-rc.4",
                "org.exitlane.runtime": "container",
            }
        },
    }


def container_facts():
    return {
        "Image": IMAGE,
        "Mounts": [],
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": [],
            "PidMode": "",
            "Binds": [],
            "Devices": [],
            "PortBindings": {},
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,mode=0700,size=8m"},
            "PidsLimit": 32,
            "Memory": 134217728,
            "NanoCpus": 1000000000,
        },
    }


def test_real_tls_accepts_valid_and_rejects_all_nine_invalid_cases(tmp_path, monkeypatch):
    # One listener at production PIA's fixed port, never a commercial endpoint.
    # Qualification executes all shipped client/verifier code unchanged.
    monkeypatch.setenv("HTTPS_PROXY", "http://unused.invalid:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/synthetic/original/environment")
    monkeypatch.setattr(probe.tempfile, "tempdir", str(tmp_path))
    origin, ca = probe.mullvad.API_ORIGIN, probe.pia_api.CA_PATH
    checks = []
    probe.qualify(checks)
    assert checks == valid_receipt()["checks"]
    assert probe.os.environ["HTTPS_PROXY"] == "http://unused.invalid:9"
    assert probe.os.environ["SSL_CERT_FILE"] == "/synthetic/original/environment"
    assert probe.mullvad.API_ORIGIN == origin and probe.pia_api.CA_PATH == ca
    assert list(tmp_path.iterdir()) == []


def wrapped_error(client, code):
    certificate = ssl.SSLCertVerificationError(1, "synthetic verification failure")
    certificate.verify_code = code
    certificate.verify_message = "synthetic"
    kind = probe.mullvad.MullvadApiError if client == "mullvad" else probe.pia_api.PiaApiError
    wrapped = kind("provider_api_unavailable")
    transport = urllib.error.URLError(certificate)
    wrapped.__context__ = transport
    wrapped.__suppress_context__ = True
    return wrapped


@pytest.mark.parametrize("client", probe.CLIENTS)
@pytest.mark.parametrize("condition,code", list(probe.VERIFY_CODES.items()))
def test_suppressed_real_certificate_chain_is_required(client, condition, code):
    probe.validate_failure(client, condition, wrapped_error(client, code), 0, 0)


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("unknown transport failure"),
        TimeoutError("timed out"),
        ConnectionRefusedError("refused"),
        probe.pia_api.PiaApiError("provider_api_unavailable"),
    ],
)
def test_generic_network_failure_is_not_certificate_evidence(error):
    with pytest.raises(probe.ProbeError):
        probe.validate_failure("pia_public", "unknown_ca", error, 0, 0)


def test_wrong_verification_reason_cannot_pass():
    with pytest.raises(probe.ProbeError, match="certificate_rejection_unproven"):
        probe.validate_failure("mullvad", "expired", wrapped_error("mullvad", 20), 0, 0)


def test_invalid_certificate_http_and_positive_refusal_both_fail():
    error = wrapped_error("pia_public", 20)
    with pytest.raises(probe.ProbeError, match="received_http"):
        probe.validate_failure("pia_public", "unknown_ca", error, 0, 1)
    with pytest.raises(probe.ProbeError, match="positive_control_failed"):
        probe.validate_failure("pia_public", "valid", error, 0, 0)


def test_exception_cycles_are_bounded():
    error = RuntimeError("synthetic")
    error.__context__ = error
    assert probe.certificate_codes(error) == []


def test_failed_probe_emits_only_fixed_safe_error_and_partial_checks(monkeypatch, capsys):
    secret = "synthetic-do-not-log-private-material"

    def fail(checks):
        checks.append(valid_receipt()["checks"][0])
        raise RuntimeError(secret)

    monkeypatch.setattr(probe, "qualify", fail)
    assert probe.main() == 1
    output = capsys.readouterr()
    assert secret not in output.out + output.err
    receipt = harness.safe_probe_receipt(output.out)
    assert receipt["result"] == "FAIL" and len(receipt["checks"]) == 1


@pytest.mark.parametrize(
    "field,value",
    [("Id", "sha256:" + "c" * 64), ("Architecture", "arm64"), ("Os", "windows")],
)
def test_image_identity_must_match(field, value):
    facts = image_facts()
    facts[field] = value
    with pytest.raises(harness.QualificationError):
        harness.image_identity(facts, IMAGE, REVISION)


def test_source_labels_and_declared_volumes_are_enforced():
    facts = image_facts()
    facts["Config"]["Labels"]["org.opencontainers.image.revision"] = "c" * 40
    with pytest.raises(harness.QualificationError, match="source_mismatch"):
        harness.image_identity(facts, IMAGE, REVISION)
    facts = image_facts()
    facts["Config"]["Volumes"] = {"/data": {}}
    with pytest.raises(harness.QualificationError, match="volume_forbidden"):
        harness.image_identity(facts, IMAGE, REVISION)


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkMode", "bridge"),
        ("ReadonlyRootfs", False),
        ("Privileged", True),
        ("CapAdd", ["NET_ADMIN"]),
        ("PidMode", "host"),
        ("Binds", ["/var/run/docker.sock:/socket"]),
        ("Devices", ["/dev/net/tun"]),
        ("PortBindings", {"1337/tcp": [{}]}),
        ("SecurityOpt", []),
        ("Tmpfs", {}),
        ("PidsLimit", -1),
        ("Memory", 0),
    ],
)
def test_container_boundary_is_not_relaxed(field, value):
    facts = container_facts()
    facts["HostConfig"][field] = value
    with pytest.raises(harness.QualificationError):
        harness.container_contract(facts, IMAGE)


@pytest.mark.parametrize(
    "change",
    ["extra", "missing", "duplicate", "wrong_reason", "http_leak", "unexpected_output"],
)
def test_receipt_validation_rejects_unproven_or_unbounded_claims(change):
    value = valid_receipt()
    if change == "extra":
        value["private"] = "must-not-echo"
    elif change == "missing":
        value["checks"].pop()
    elif change == "duplicate":
        value["checks"][-1] = value["checks"][0]
    elif change == "wrong_reason":
        value["checks"][-1]["verify_code"] = 20
    elif change == "http_leak":
        value["checks"][-1]["http_requests"] = 1
    else:
        value["openssl"] = "raw private unexpected value"
    with pytest.raises(harness.QualificationError):
        harness.safe_probe_receipt(json.dumps(value))


def test_exact_image_execution_uses_stdin_and_always_cleans_own_container(tmp_path, monkeypatch):
    instance = harness.Harness(IMAGE, REVISION, tmp_path)
    calls = []

    def docker(*args, data=None, timeout=30):
        calls.append((args, data, timeout))
        if args[:2] == ("image", "inspect"):
            body = json.dumps([image_facts()])
        elif args[0] == "inspect":
            body = json.dumps([container_facts()])
        elif args[0] == "start":
            assert "def qualify" in data
            body = json.dumps(valid_receipt())
        else:
            body = ""
        return subprocess.CompletedProcess([], 0, body, "")

    monkeypatch.setattr(instance, "docker", docker)
    value = instance.run()
    assert value["result"] == "PASS" and value["source_revision"] == REVISION
    create = next(args for args, _, _ in calls if args[0] == "create")
    assert "--pull" in create and create[create.index("--pull") + 1] == "never"
    assert "--mount" not in create and "--publish" not in create
    assert create[-3:] == ("-I", "-B", "-")
    assert calls[-1][0] == ("rm", "--force", instance.name)


def test_timeout_cleans_only_owned_container(tmp_path, monkeypatch):
    instance = harness.Harness(IMAGE, REVISION, tmp_path)
    removed = []

    def docker(*args, **kwargs):
        if args[0] == "start":
            raise subprocess.TimeoutExpired("docker", 120)
        if args[0] == "rm":
            removed.append(args[-1])
        body = json.dumps([image_facts() if args[0] == "image" else container_facts()])
        return subprocess.CompletedProcess([], 0, body, "")

    monkeypatch.setattr(instance, "docker", docker)
    with pytest.raises(subprocess.TimeoutExpired):
        instance.run()
    assert removed == [instance.name]


def test_host_environment_does_not_inherit_credentials_or_docker_context(tmp_path, monkeypatch):
    instance = harness.Harness(IMAGE, REVISION, tmp_path)
    monkeypatch.setenv("DOCKER_HOST", "tcp://unexpected.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "https://private.invalid")

    def run(argv, **kwargs):
        assert argv[1:5] == [
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            str(tmp_path),
        ]
        assert "DOCKER_HOST" not in kwargs["env"] and "HTTPS_PROXY" not in kwargs["env"]
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(harness.subprocess, "run", run)
    instance.docker("inspect", IMAGE)


def test_failed_positive_control_retains_specific_fixed_code(monkeypatch, capsys):
    def fail(_checks):
        raise probe.ProbeError("tls_positive_control_failed")

    monkeypatch.setattr(probe, "qualify", fail)
    assert probe.main() == 1
    receipt = harness.safe_probe_receipt(capsys.readouterr().out)
    assert receipt["code"] == "tls_positive_control_failed" and receipt["checks"] == []
