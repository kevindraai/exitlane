from __future__ import annotations

import copy
import importlib
import json
import os
import sys
from pathlib import Path

import pytest


@pytest.fixture
def disaster(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts/qualification"))
    module = importlib.import_module("native_disaster")
    monkeypatch.setattr(module.native, "RUNS", tmp_path / "runs")
    return module


def config(number):
    return {
        "run_id": str(number) * 32,
        "hostname": f"synthetic-{number}",
        "machine_id": str(number) * 32,
        "authorization_reference": "synthetic fixture only",
        "source": "/synthetic/source",
        "source_sha": "a" * 40,
        "baseline": "/synthetic/baseline",
        "baseline_sha": "b" * 40,
        "role": "clean",
    }


def snapshot(module, *, source=False, restored=False):
    tables = {
        name: {"columns": ["id"], "rows": [], "complete_rows": []}
        for name in module.native.state.REQUIRED_TABLES
    }
    if source or restored:
        tables["users"]["rows"] = tables["users"]["complete_rows"] = ["synthetic-user"]
    if source:
        for name in module.native.state.REVOKED_TABLES:
            tables[name]["rows"] = tables[name]["complete_rows"] = ["synthetic-state"]
    return {
        "format": 1,
        "database": {"metadata": {"mode": 0o600}, "tables": tables},
        "state_files": {
            "etc/exitlane/secret.key": {
                "sha256": "source-key" if source or restored else "target-key"
            },
            "etc/default/exitlane": {"sha256": "source-defaults" if source else "target-defaults"},
        },
        "wireguard": {"synthetic": "preserved"},
    }


@pytest.fixture
def prepared(disaster, monkeypatch, tmp_path):
    native = disaster.native
    source = native.Run(config(1))
    source.open()
    for name, raw in {
        "backup.elb": b"synthetic encrypted backup fixture",
        "passphrase": b"synthetic private passphrase",
        "fixture.json": b'{"username":"synthetic-private-admin"}',
        "backup.snapshot": json.dumps(snapshot(disaster, source=True)).encode(),
    }.items():
        native.private_bytes(source.directory / name, raw)
    native.private_write(
        source.directory / "backup.json",
        {
            "type": "native-guest-stage",
            "stage": "backup",
            "result": "PASS",
            "binding": source.binding,
            "harness": source.harness,
            "artifacts": {name: native.digest(source.directory / name) for name in disaster.FILES},
        },
    )
    monkeypatch.setattr(source, "previous", lambda name: name == "backup")
    bundle = tmp_path / "bundle"
    disaster.export_bundle(source, bundle)
    target = native.Run(config(2))
    target.open()
    native.private_write(target.directory / "candidate-install.json", {"synthetic": True})
    monkeypatch.setattr(target, "previous", lambda name: name == "candidate-install")
    monkeypatch.setattr(native, "installed", lambda path: None)
    monkeypatch.setattr(native, "healthy", lambda: None)
    monkeypatch.setattr(
        native, "read_command", lambda argv: '{"setup_complete":false,"authenticated":false}'
    )
    monkeypatch.setattr(native, "rejected_restore_state", lambda: {"staging": []})
    observations = iter([snapshot(disaster), snapshot(disaster, restored=True)])
    monkeypatch.setattr(native.state, "capture", lambda root: next(observations))
    commands = []

    def cli(action, label):
        commands.append(action)
        native.private_bytes(target.directory / (label + ".log"), b"synthetic CLI pass")

    def api(action):
        commands.append(action)
        native.private_bytes(target.directory / ("api-" + action + ".log"), b"synthetic API pass")

    monkeypatch.setattr(target, "backup_cli", cli)
    monkeypatch.setattr(target, "api", api)
    return source, target, bundle, commands


def test_export_contains_only_portable_allowlist_and_bound_provenance(disaster, prepared):
    source, _, bundle, _ = prepared
    manifest, raw = disaster.load_bundle(bundle, source.harness)
    assert set(raw) == {*disaster.FILES, *disaster.EVIDENCE}
    assert manifest["config"] == source.config
    assert bundle.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in bundle.iterdir())
    with pytest.raises(FileExistsError):
        disaster.export_bundle(source, bundle)


@pytest.mark.parametrize(
    "mutation", ["extra", "symlink", "hardlink", "mode", "hash", "receipt", "identity", "exporter"]
)
def test_bundle_tampering_is_rejected(disaster, prepared, mutation):
    source, _, bundle, _ = prepared
    path = bundle / "passphrase"
    if mutation == "extra":
        disaster.native.private_bytes(bundle / "cookies", b"not transferable")
    elif mutation == "symlink":
        path.unlink()
        path.symlink_to(source.directory / "passphrase")
    elif mutation == "hardlink":
        path.unlink()
        os.link(source.directory / "passphrase", path)
    elif mutation == "mode":
        path.chmod(0o644)
    elif mutation == "hash":
        path.write_bytes(b"altered")
    elif mutation == "exporter":
        path = bundle / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["exporter_sha256"] = "incorrect harness"
        path.write_text(json.dumps(manifest))
    else:
        name = "source-backup.json" if mutation == "receipt" else "source-identity.json"
        record = json.loads((bundle / name).read_text())
        record["binding" if mutation == "receipt" else "config"] = "wrong-source"
        (bundle / name).write_text(json.dumps(record))
        manifest = json.loads((bundle / "manifest.json").read_text())
        manifest["artifacts"][name] = disaster.native.digest(bundle / name)
        (bundle / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises((disaster.native.QualificationError, OSError)):
        disaster.load_bundle(bundle, source.harness)


def test_disaster_checks_real_restore_order_and_retains_private_receipt(disaster, prepared):
    _, target, bundle, commands = prepared
    disaster.restore_bundle(target, bundle, "operator record: source powered off")
    assert commands == ["inspect", "verify", "restore", "disaster-login"]
    record = json.loads((target.directory / "disaster.json").read_text())
    assert record["result"] == "PASS"
    assert "native_disaster.py" in record["harness"]
    assert "no old-cookie, source-isolation" in record["scope"]
    assert record["artifacts"]["backup.elb"] == disaster.native.digest(bundle / "backup.elb")
    with pytest.raises(disaster.native.QualificationError):
        disaster.restore_bundle(target, bundle, "operator record")
    assert commands == ["inspect", "verify", "restore", "disaster-login"]


@pytest.mark.parametrize(
    "failure",
    [
        "isolation",
        "same-machine",
        "same-run",
        "source-sha",
        "role",
        "same-key",
        "existing-user",
        "no-install",
        "setup-complete",
    ],
)
def test_disaster_preconditions_fail_before_cli_and_started_marker(
    disaster, prepared, monkeypatch, failure
):
    source, target, bundle, commands = prepared
    reference = "operator record"
    if failure == "isolation":
        reference = "   "
    elif failure in {"same-machine", "same-run", "source-sha", "role"}:
        name = {
            "same-machine": "machine_id",
            "same-run": "run_id",
            "source-sha": "source_sha",
            "role": "role",
        }[failure]
        target.config[name] = (
            source.config[name]
            if failure.startswith("same-")
            else ("c" * 40 if failure == "source-sha" else "upgrade")
        )
    elif failure == "no-install":
        monkeypatch.setattr(target, "previous", lambda name: False)
    elif failure == "setup-complete":
        monkeypatch.setattr(
            disaster.native,
            "read_command",
            lambda argv: '{"setup_complete":true,"authenticated":false}',
        )
    else:
        before = snapshot(disaster)
        if failure == "same-key":
            before["state_files"]["etc/exitlane/secret.key"]["sha256"] = "source-key"
        else:
            before["database"]["tables"]["users"]["rows"] = ["existing-user"]
        monkeypatch.setattr(disaster.native.state, "capture", lambda root: before)
    with pytest.raises(disaster.native.QualificationError):
        disaster.restore_bundle(target, bundle, reference)
    assert not commands
    assert not (target.directory / "disaster.started").exists()


@pytest.mark.parametrize("failure", ["cli", "defaults", "session", "staging", "api"])
def test_failed_restore_retains_evidence_and_cannot_be_retried(
    disaster, prepared, monkeypatch, failure
):
    _, target, bundle, _commands = prepared
    if failure in {"cli", "api"}:

        def reject(*args):
            raise disaster.native.QualificationError("synthetic failure")

        monkeypatch.setattr(target, "backup_cli" if failure == "cli" else "api", reject)
    elif failure == "staging":
        observations = iter([{"staging": []}, {"staging": ["leftover plaintext"]}])
        monkeypatch.setattr(disaster.native, "rejected_restore_state", lambda: next(observations))
    else:
        after = copy.deepcopy(snapshot(disaster, restored=True))
        if failure == "defaults":
            after["state_files"]["etc/default/exitlane"]["sha256"] = "changed"
        else:
            after["database"]["tables"]["sessions"]["complete_rows"] = ["unrevoked"]
        observations = iter([snapshot(disaster), after])
        monkeypatch.setattr(disaster.native.state, "capture", lambda root: next(observations))
    with pytest.raises(disaster.native.QualificationError):
        disaster.restore_bundle(target, bundle, "operator source-isolation record")
    assert (target.directory / "disaster.started").exists()
    assert not (target.directory / "disaster.json").exists()
    assert (target.directory / "backup.elb").read_bytes() == (bundle / "backup.elb").read_bytes()
    with pytest.raises(disaster.native.QualificationError, match="prior_attempt_incomplete"):
        disaster.restore_bundle(target, bundle, "operator source-isolation record")


def test_default_plan_has_no_preflight_or_bundle_or_host_mutation(
    disaster, monkeypatch, tmp_path, capsys
):
    path = tmp_path / "config.json"
    disaster.native.private_write(path, config(2))
    bundle = tmp_path / "absent-bundle"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "native_disaster.py",
            "--config",
            str(path),
            "--action",
            "restore",
            "--bundle",
            str(bundle),
        ],
    )
    monkeypatch.setattr(
        disaster.native, "preflight", lambda value: pytest.fail("plan called preflight")
    )
    assert disaster.main() == 0
    assert json.loads(capsys.readouterr().out)["executed"] is False
    assert not bundle.exists()
    assert not disaster.native.RUNS.exists()
