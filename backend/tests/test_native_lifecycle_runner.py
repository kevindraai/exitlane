"""Guest qualification tooling fixtures: no installer, service or host mutation."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).resolve().parents[2] / "scripts/qualification"


@pytest.fixture
def runner(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(DIRECTORY))
    spec = importlib.util.spec_from_file_location(
        "qualification_runner_test", DIRECTORY / "native_lifecycle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT_UID", os.getuid())
    monkeypatch.setattr(module, "RUNS", tmp_path / "runs")
    monkeypatch.setattr(module, "ROOT", tmp_path / "root")
    module.ROOT.mkdir(mode=0o700)
    return module


def config():
    return {
        "run_id": "a" * 32,
        "hostname": "disposable",
        "machine_id": "b" * 32,
        "authorization_reference": "explicit disposable scope reference",
        "source": "/root/candidate",
        "source_sha": "c" * 40,
        "baseline": "/root/baseline",
        "baseline_sha": "d" * 40,
        "role": "clean",
    }


@pytest.fixture
def run(runner, monkeypatch):
    # Harness source is read-only; CI's checkout uid differs from appliance root.
    instance = runner.Run(config())
    instance.open()
    return instance


def receipt(run, runner, name, artifacts):
    for relative in artifacts:
        path = run.directory / relative
        if not path.exists():
            runner.private_bytes(path, b"synthetic-private")
    dependency = run.dependency(name)
    value = {
        "type": "native-guest-stage",
        "stage": name,
        "result": "PASS",
        "binding": run.binding,
        "harness": run.harness,
        "dependency": {
            "stage": dependency,
            "sha256": runner.digest(run.directory / (dependency + ".json")),
        }
        if dependency
        else None,
        "artifacts": {name: runner.digest(run.directory / name) for name in artifacts},
    }
    runner.private_write(run.directory / (name + ".json"), value)
    runner.private_write(run.directory / (name + ".started"), {"binding": run.binding})


def seeded_receipts(run, runner):
    receipt(run, runner, "candidate-install", {"candidate-install.log"})
    receipt(run, runner, "seed", {"fixture.json", "seed.snapshot", "api-seed.log"})


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "wide", "oversize"])
def test_private_read_rejects_unsafe_files(runner, tmp_path, kind):
    path = tmp_path / "secret"
    original = tmp_path / "original"
    runner.private_bytes(original, b"private")
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        runner.private_bytes(path, b"private")
        if kind == "wide":
            path.chmod(0o644)
    with pytest.raises((runner.QualificationError, OSError)):
        runner.private_read(path, maximum=3 if kind == "oversize" else 100)


def test_private_ancestor_rejects_symlink_and_writable_directory(runner, tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(runner.QualificationError, match="parent_invalid"):
        runner.private_bytes(alias / "file", b"secret")
    directory.chmod(0o777)
    with pytest.raises(runner.QualificationError, match="parent_invalid"):
        runner.private_bytes(directory / "file", b"secret")


def test_configuration_and_plan_never_execute(runner, tmp_path, monkeypatch, capsys):
    path = tmp_path / "config.json"
    runner.private_write(path, config())
    monkeypatch.setattr(sys, "argv", ["runner", "--config", str(path), "--stage", "seed"])
    monkeypatch.setattr(
        runner, "preflight", lambda *_: pytest.fail("plan attempted host inspection")
    )
    assert runner.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["executed"] is False and output["type"] == "plan-only"
    assert not runner.RUNS.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "../escape"),
        ("source_sha", "main"),
        ("source", "/root/../opt/exitlane"),
        ("role", "production"),
    ],
)
def test_configuration_rejects_ambiguous_scope(runner, tmp_path, field, value):
    path = tmp_path / "config.json"
    data = config()
    data[field] = value
    runner.private_write(path, data)
    with pytest.raises(runner.QualificationError):
        runner.configuration(path)


@pytest.mark.parametrize("artifact", ["fixture.json", "seed.snapshot", "candidate-install.log"])
def test_recursive_receipts_bind_immutable_artifacts(run, runner, artifact):
    seeded_receipts(run, runner)
    assert run.previous("seed")
    (run.directory / artifact).write_bytes(b"altered")
    with pytest.raises(runner.QualificationError, match="artifact_mismatch"):
        run.allowed("idempotence")


def test_dependency_receipt_cannot_be_rewritten(run, runner):
    seeded_receipts(run, runner)
    parent = run.directory / "candidate-install.json"
    data = json.loads(parent.read_text())
    data["scope"] = "different"
    parent.write_text(json.dumps(data))
    with pytest.raises(runner.QualificationError, match="dependency_invalid"):
        run.previous("seed")


def test_missing_receipt_artifact_does_not_pass(run, runner):
    receipt(run, runner, "candidate-install", set())
    with pytest.raises(runner.QualificationError, match="artifact_mismatch"):
        run.previous("candidate-install")


def test_any_incomplete_attempt_blocks_other_stage(run, runner):
    runner.private_write(run.directory / "seed.started", {"binding": run.binding})
    with pytest.raises(runner.QualificationError, match="prior_attempt_incomplete"):
        run.allowed("candidate-install")


def test_cookies_are_mutable_without_invalidating_seed(run, runner):
    seeded_receipts(run, runner)
    runner.private_bytes(run.directory / "cookies", b"old-session")
    (run.directory / "cookies").write_bytes(b"refreshed-session")
    assert run.previous("seed")
    run.allowed("idempotence")


@pytest.mark.parametrize("kind", ["hardlink", "fifo", "wide"])
def test_lock_refuses_unsafe_file(run, runner, kind):
    path = run.directory / "stage.lock"
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        runner.private_bytes(path, b"")
        if kind == "hardlink":
            os.link(path, run.directory / "alias")
        else:
            path.chmod(0o666)
    with pytest.raises((runner.QualificationError, OSError)):
        run.lock()


def test_lock_is_exclusive(run):
    descriptor = run.lock()
    try:
        with pytest.raises(BlockingIOError):
            run.lock()
    finally:
        os.close(descriptor)


def test_environment_discards_process_injection(runner, monkeypatch):
    for name in (
        "BASH_ENV",
        "PYTHONPATH",
        "TARGET",
        "EXITLANE_RUNTIME",
        "HTTPS_PROXY",
        "LD_PRELOAD",
    ):
        monkeypatch.setenv(name, "injected")
    clean = runner.environment()
    assert all(
        name not in clean
        for name in (
            "BASH_ENV",
            "PYTHONPATH",
            "TARGET",
            "EXITLANE_RUNTIME",
            "HTTPS_PROXY",
            "LD_PRELOAD",
        )
    )
    assert clean["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_fault_wrapper_reaches_real_err_handler_and_binds_marker(runner, tmp_path):
    # Execute a harmless fake installer solely to exercise Bash function scope /
    # ERR propagation. No real installer or service command is invoked.
    installer = tmp_path / "installer"
    installer.mkdir()
    marker = tmp_path / "fault-marker"
    (tmp_path / "exitlane.db").write_bytes(b"fake recovery")
    (installer / "install-debian.sh").write_text("""UPGRADE_MODE=1
UPGRADE_COMMITTED=0
RECOVERY_DIR="$1"
trap 'status=$?; printf rollback-observed; exit "$status"' ERR
start_service() { printf real-start-observed; }
commit_upgrade() { printf should-not-run; }
main() { start_service; commit_upgrade; }
""")
    result = subprocess.run(
        ["bash", "-c", runner.FAULT, "fixture", str(tmp_path), str(marker)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 97
    assert result.stdout == "real-start-observedrollback-observed"
    assert marker.read_bytes() == b"qualification_precommit_fault\n"


def test_timeout_kills_entire_child_group(run, runner, monkeypatch):
    calls = []

    class Process:
        pid = 456789
        returncode = None

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def communicate(self, **kwargs):
            raise subprocess.TimeoutExpired("mock", 0.1)

        def wait(self):
            calls.append("wait")
            self.returncode = -9

    def popen(argv, **kwargs):
        assert kwargs["start_new_session"] is True and kwargs["cwd"] == "/"
        assert kwargs["env"] == runner.environment()
        return Process()

    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    monkeypatch.setattr(runner.os, "killpg", lambda pid, signum: calls.append((pid, signum)))
    ticks = iter([0, 0, 0, 2])
    monkeypatch.setattr(runner.time, "monotonic", lambda: next(ticks))
    with pytest.raises(runner.QualificationError, match="child_timeout"):
        run.command(["mock"], "timeout-test", timeout=1)
    assert calls == [(456789, signal.SIGKILL), "wait"]


def test_source_rejects_ignored_content_and_symlinks(runner, tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)

    def git(argv):
        if argv[-1] == "HEAD":
            return "a" * 40
        if "status" in argv:
            assert "--ignored=matching" in argv
            return "!! untracked.env"
        return "b" * 40

    monkeypatch.setattr(runner, "read_command", git)
    with pytest.raises(runner.QualificationError, match="source_dirty"):
        runner.verify_source(str(source), "a" * 40)
    monkeypatch.setattr(runner, "read_command", lambda argv: "a" * 40 if argv[-1] == "HEAD" else "")
    (source / "linked-code").symlink_to(tmp_path)
    with pytest.raises(runner.QualificationError, match="source_invalid"):
        runner.verify_source(str(source), "a" * 40)


def test_rejected_restore_observes_routes_service_and_staging(runner, monkeypatch):
    (runner.ROOT / "etc").mkdir()
    (runner.ROOT / "tmp").mkdir()
    output = {"value": "unchanged"}
    calls = []

    def observe(argv):
        calls.append(argv)
        if argv[0] == "nft":
            return '{"nftables": []}'
        return "# variable generated timestamp\n" + output["value"]

    monkeypatch.setattr(runner, "read_command", observe)
    before = runner.rejected_restore_state()
    assert len(calls) == 8
    assert runner.rejected_restore_state() == before
    output["value"] = "changed"
    assert runner.rejected_restore_state() != before
    output["value"] = "unchanged"
    (runner.ROOT / "etc/.exitlane-prerestore-unexpected").mkdir()
    assert runner.rejected_restore_state() != before


def test_native_runtime_rejects_defaults_before_service_commands(runner, monkeypatch):
    target = runner.ROOT / "etc/default/exitlane"
    target.parent.mkdir(parents=True)
    target.write_text("EXITLANE_DATA_DIR=/different\n")
    target.chmod(0o600)
    monkeypatch.setattr(
        runner, "read_command", lambda *_: pytest.fail("unsafe config reached service checks")
    )
    with pytest.raises(runner.QualificationError, match="native_paths_required"):
        runner.native_runtime()


def mocked_clean_chain(run, runner, monkeypatch, *, mutate_defaults=False, mutate_rejected=False):
    """All native operations are fakes; exercise real stage ordering/receipts."""
    live = {"state_files": {"etc/default/exitlane": "unchanged"}}
    observations = {"version": 1}
    monkeypatch.setattr(runner, "installed", lambda *_: None)
    monkeypatch.setattr(runner, "healthy", lambda: None)
    monkeypatch.setattr(runner, "rejected_restore_state", lambda: observations["version"])
    monkeypatch.setattr(runner.state, "capture", lambda *_: json.loads(json.dumps(live)))
    monkeypatch.setattr(runner.state, "compare", lambda *_: [])

    def command(argv, label, **kwargs):
        runner.private_bytes(run.directory / (label + ".log"), b"mocked operation only")
        if label == "api-seed":
            runner.private_write(run.directory / "fixture.json", {"synthetic": True})
            runner.private_bytes(run.directory / "cookies", b"mutable synthetic cookie")
        if label == "backup-create":
            runner.private_bytes(run.directory / "backup.elb", b"synthetic encrypted stand-in")
        if label == "restore-valid" and mutate_defaults:
            live["state_files"]["etc/default/exitlane"] = "altered"
        if label == "restore-tampered" and mutate_rejected:
            observations["version"] = 2
        return run.directory / (label + ".log")

    monkeypatch.setattr(run, "command", command)
    for stage in ("candidate-install", "seed", "idempotence", "backup"):
        assert run.execute(stage)["result"] == "PASS"
    return live


def test_complete_mocked_clean_chain_records_sensitive_artifact_bindings(run, runner, monkeypatch):
    mocked_clean_chain(run, runner, monkeypatch)
    assert run.execute("restore")["result"] == "PASS"
    assert run.previous("restore")
    for stage in ("backup", "restore"):
        data = json.loads((run.directory / (stage + ".json")).read_text())
        assert {"fixture.json", "backup.elb", "passphrase"} <= data["artifacts"].keys()
        assert "cookies" not in data["artifacts"]
        assert "no protected dataplane or live provider proof" in data["scope"]
    with pytest.raises(runner.QualificationError, match="already_attempted"):
        run.execute("restore")


@pytest.mark.parametrize("artifact", ["backup.elb", "passphrase", "backup.snapshot"])
def test_backup_material_cannot_change_before_restore(run, runner, monkeypatch, artifact):
    mocked_clean_chain(run, runner, monkeypatch)
    (run.directory / artifact).write_bytes(b"replacement")
    with pytest.raises(runner.QualificationError, match="artifact_mismatch"):
        run.execute("restore")


def test_successful_restore_must_preserve_target_defaults(run, runner, monkeypatch):
    mocked_clean_chain(run, runner, monkeypatch, mutate_defaults=True)
    with pytest.raises(runner.QualificationError, match="restore_mutated_defaults"):
        run.execute("restore")
    assert not (run.directory / "restore.json").exists()
    with pytest.raises(runner.QualificationError, match="prior_attempt_incomplete"):
        run.allowed("seed")


def test_tamper_rejection_must_preserve_service_routing_and_staging(run, runner, monkeypatch):
    mocked_clean_chain(run, runner, monkeypatch, mutate_rejected=True)
    with pytest.raises(runner.QualificationError, match="rejected_restore_mutated_runtime"):
        run.execute("restore")
    assert not (run.directory / "restore-valid.log").exists()


def test_installed_inventory_rejects_symlink_root(runner, tmp_path):
    source = tmp_path / "source/backend/exitlane"
    source.mkdir(parents=True)
    (source / "code.py").write_text("pass\n")
    actual = runner.ROOT / "opt/exitlane/backend/exitlane"
    actual.parent.mkdir(parents=True)
    actual.symlink_to(source, target_is_directory=True)
    with pytest.raises(runner.QualificationError, match="installed_source_mismatch"):
        runner.installed(source.parents[1])


@pytest.mark.parametrize("change", [None, "stale", "extra", "missing", "symlink"])
def test_installed_package_is_exact_including_bundled_docs(runner, tmp_path, monkeypatch, change):
    source = tmp_path / "source"
    code = source / "backend/exitlane"
    copied = runner.ROOT / "opt/exitlane/backend/exitlane"
    packaged = runner.ROOT / "opt/exitlane/venv/lib/python3.13/site-packages/exitlane"

    def write(path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o644)

    for relative, content in {
        "__init__.py": "# source\n",
        "documentation.py": 'DOCUMENTS = (Document("id", "Title", "qa.md"),)\n',
        "static/app.js": "// real static source\n",
    }.items():
        for directory in (code, copied, packaged):
            write(directory / relative, content)
    write(source / "backend/pyproject.toml", '[project]\nversion="0.3.0rc4"\n')
    write(source / "backend/hatch_build.py", "# fixture build mapping only\n")
    for relative in ("LICENSE", "THIRD_PARTY_NOTICES.md", "docs/qa.md"):
        write(source / relative, "public source material\n")
        write(packaged / relative, "public source material\n")
    for name in (
        "exitlane.service",
        "exitlane-killswitch.service",
        "exitlane-provider-egress.service",
        "exitlane-management-routing.service",
        "exitlane-provider-install-nordvpn.service",
        "exitlane-speedtest-install.service",
        "wg-quick@.service.d/exitlane.conf",
    ):
        write(source / "systemd" / name, "synthetic unit\n")
        write(runner.ROOT / "etc/systemd/system" / name, "synthetic unit\n")
    for name in ("nordvpn", "speedtest"):
        write(source / "installer" / ("install-" + name + ".sh"), "synthetic helper\n")
        write(
            runner.ROOT / "usr/local/libexec" / ("exitlane-install-" + name), "synthetic helper\n"
        )
    monkeypatch.setattr(runner, "native_runtime", lambda: None)
    monkeypatch.setattr(
        runner,
        "read_command",
        lambda *_: json.dumps({"version": "0.3.0rc4", "file": str(packaged / "__init__.py")}),
    )
    if change == "stale":
        (packaged / "__init__.py").write_text("# wrong equal-version content\n")
    elif change == "extra":
        write(packaged / "untracked.py", "# unexpected\n")
    elif change == "missing":
        (packaged / "docs/qa.md").unlink()
    elif change == "symlink":
        (packaged / "__init__.py").unlink()
        (packaged / "__init__.py").symlink_to(code / "__init__.py")
    if change:
        with pytest.raises(
            runner.QualificationError,
            match="(installed_package_mismatch|installed_source_mismatch)",
        ):
            runner.installed(source)
    else:
        runner.installed(source)


@pytest.mark.parametrize(
    "entry", ["native_lifecycle.py", "native_lifecycle_state.py", "native_disaster.py"]
)
def test_harness_must_belong_to_exact_candidate(runner, tmp_path, entry):
    candidate = tmp_path / "candidate"
    location = candidate / "scripts/qualification" / entry
    location.parent.mkdir(parents=True)
    location.write_text("synthetic source")
    runner.verify_entrypoint(str(candidate), location)
    with pytest.raises(runner.QualificationError, match="harness_source_mismatch"):
        runner.verify_entrypoint(str(tmp_path / "other"), location)


def test_wrong_harness_fails_preflight_before_host_observation(runner, monkeypatch):
    monkeypatch.setattr(runner.socket, "gethostname", lambda: pytest.fail("observed host"))
    with pytest.raises(runner.QualificationError, match="harness_source_mismatch"):
        runner.preflight({"source": "/another/reviewed/candidate"})


def readiness_clock(runner, monkeypatch):
    clock = {"now": 0.0}
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(runner.time, "sleep", lambda delay: clock.update(now=clock["now"] + delay))
    return clock


def service_identity(number=1, active=True):
    return (
        "ActiveState=" + ("active" if active else "failed") + "\nSubState=running\n"
        f"MainPID={100 + number}\nInvocationID={number:032x}"
    )


def test_readiness_waits_through_connection_refusal(runner, monkeypatch):
    clock = readiness_clock(runner, monkeypatch)
    health = []

    def observe(argv, **kwargs):
        assert 0 < kwargs["timeout"] <= 2
        if argv[0] == "systemctl":
            return service_identity()
        health.append(clock["now"])
        if len(health) == 1:
            raise runner.QualificationError("qualification_observation_failed")
        return '{"ok":true}'

    monkeypatch.setattr(runner, "read_command", observe)
    runner.healthy(timeout=2)
    assert len(health) == 3 and clock["now"] > 0


@pytest.mark.parametrize("failure", ["connection", "service", "json"])
def test_readiness_deadline_cannot_be_health_pass(runner, monkeypatch, failure):
    clock = readiness_clock(runner, monkeypatch)

    def observe(argv, **kwargs):
        if argv[0] == "systemctl":
            return service_identity(active=failure != "service")
        if failure == "connection":
            raise runner.subprocess.TimeoutExpired("synthetic observation", kwargs["timeout"])
        return "invalid-json"

    monkeypatch.setattr(runner, "read_command", observe)
    with pytest.raises(runner.QualificationError, match="health_failed"):
        runner.healthy(timeout=1)
    assert clock["now"] == 1


def test_readiness_rejects_new_service_invocation_even_if_http_ok(runner, monkeypatch):
    readiness_clock(runner, monkeypatch)
    calls = iter([service_identity(1), service_identity(2)])
    monkeypatch.setattr(
        runner,
        "read_command",
        lambda argv, **kwargs: next(calls) if argv[0] == "systemctl" else '{"ok":true}',
    )
    with pytest.raises(runner.QualificationError, match="service_replaced"):
        runner.healthy()


def test_native_inet_changes_detected_but_counters_handles_are_volatile(runner, monkeypatch):
    nft = {
        "nftables": [
            {"metainfo": {"version": "synthetic"}},
            {"table": {"family": "inet", "name": "exitlane_restore", "handle": 7}},
            {
                "rule": {
                    "family": "inet",
                    "table": "exitlane_restore",
                    "chain": "forward",
                    "handle": 8,
                    "expr": [{"counter": {"packets": 2, "bytes": 5}}, {"drop": None}],
                }
            },
        ]
    }
    monkeypatch.setattr(runner, "read_command", lambda argv: json.dumps(nft))
    before = runner.nft_state()
    nft["nftables"][2]["rule"]["handle"] = 99
    nft["nftables"][2]["rule"]["expr"][0]["counter"] = {"packets": 3, "bytes": 15}
    assert runner.nft_state() == before
    nft["nftables"][2]["rule"]["expr"][1] = {"accept": None}
    assert runner.nft_state() != before


@pytest.mark.parametrize("value", ["invalid", "[]", '{"nftables":[1]}'])
def test_malformed_nft_observation_cannot_be_runtime_pass(runner, monkeypatch, value):
    monkeypatch.setattr(runner, "read_command", lambda argv: value)
    with pytest.raises((ValueError, runner.QualificationError)):
        runner.nft_state()
