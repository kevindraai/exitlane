#!/usr/bin/env python3
"""Export a private synthetic backup bundle, or restore it on a second clean guest.

Plan is the default. Run native_lifecycle.py candidate-install on the second guest
first. Export uses a completed backup receipt from the source run. Transfer only
the resulting private bundle through the separately authorized operator route.
Before restore, isolate the source and supply its operator evidence reference.
That reference records a prerequisite; this tool cannot verify network isolation
and never grants authority to mutate a guest. No provisioning or remote execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import native_lifecycle as native

FILES = ("backup.elb", "passphrase", "fixture.json", "backup.snapshot")
EVIDENCE = ("source-identity.json", "source-backup.json")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_directory(path):
    native.safe_ancestors(path)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        native.fail("qualification_bundle_directory_invalid")


def export_bundle(run, destination):
    """Only portable backup material and provenance leave the source run."""
    if not run.previous("backup"):
        native.fail("qualification_source_backup_missing")
    native.safe_ancestors(destination)
    destination.mkdir(mode=0o700)  # Refuse existing or partial exports.
    private_directory(destination)
    artifacts = {name: native.private_read(run.directory / name) for name in FILES}
    artifacts["source-identity.json"] = native.private_read(
        run.directory / "identity.json"
    )
    artifacts["source-backup.json"] = native.private_read(run.directory / "backup.json")
    for name, raw in artifacts.items():
        native.private_bytes(destination / name, raw)
    native.private_write(
        destination / "manifest.json",
        {
            "type": "native-synthetic-disaster-bundle",
            "config": run.config,
            "exporter_sha256": native.digest(Path(__file__)),
            "artifacts": {name: sha(raw) for name, raw in artifacts.items()},
        },
    )
    # Catch changed files during export instead of accepting a mixed generation.
    load_bundle(destination, run.harness)


def load_bundle(directory, harness):
    private_directory(directory)
    if {item.name for item in directory.iterdir()} != {
        *FILES,
        *EVIDENCE,
        "manifest.json",
    }:
        native.fail("qualification_bundle_contents_invalid")
    manifest = json.loads(native.private_read(directory / "manifest.json"))
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"type", "config", "artifacts", "exporter_sha256"}
        or manifest["type"] != "native-synthetic-disaster-bundle"
        or manifest["exporter_sha256"] != native.digest(Path(__file__))
        or not isinstance(manifest["artifacts"], dict)
        or set(manifest["artifacts"]) != {*FILES, *EVIDENCE}
    ):
        native.fail("qualification_bundle_manifest_invalid")
    raw = {name: native.private_read(directory / name) for name in (*FILES, *EVIDENCE)}
    if {name: sha(value) for name, value in raw.items()} != manifest["artifacts"]:
        native.fail("qualification_bundle_hash_mismatch")
    config = manifest["config"]
    if not isinstance(config, dict) or any(
        not isinstance(config.get(name), str) or not re.fullmatch(pattern, config[name])
        for name, pattern in (
            ("machine_id", r"[a-f0-9]{32}"),
            ("run_id", r"[a-f0-9]{32}"),
            ("source_sha", r"[a-f0-9]{40}"),
        )
    ):
        native.fail("qualification_bundle_source_identity_invalid")
    binding = sha(json.dumps(config, sort_keys=True).encode())
    identity = json.loads(raw["source-identity.json"])
    receipt = json.loads(raw["source-backup.json"])
    if identity != {"config": binding, "harness": harness, "type": "native-guest"}:
        native.fail("qualification_bundle_source_identity_invalid")
    if (
        receipt.get("type") != "native-guest-stage"
        or receipt.get("stage") != "backup"
        or receipt.get("result") != "PASS"
        or receipt.get("binding") != binding
        or receipt.get("harness") != harness
        or not isinstance(receipt.get("artifacts"), dict)
        or any(receipt["artifacts"].get(name) != sha(raw[name]) for name in FILES)
    ):
        native.fail("qualification_bundle_backup_receipt_invalid")
    return manifest, raw


def restore_bundle(run, bundle, isolation_reference):
    # Isolation must be established before the native CLI can activate duplicate
    # ingress identity. This is an operator assertion, not a network observation.
    if not isolation_reference or not 1 <= len(isolation_reference.strip()) <= 512:
        native.fail("qualification_source_isolation_reference_required")
    if run.config["role"] != "clean":
        native.fail("qualification_disaster_clean_target_required")
    run.allowed("seed")  # Requires fresh candidate-install and no partial attempt.
    manifest, raw = load_bundle(bundle, run.harness)
    if (
        manifest["config"]["machine_id"] == run.config["machine_id"]
        or manifest["config"]["run_id"] == run.config["run_id"]
        or manifest["config"]["source_sha"] != run.config["source_sha"]
    ):
        native.fail("qualification_disaster_source_target_identity_invalid")
    native.installed(run.config["source"])
    native.healthy()
    session = json.loads(
        native.read_command(
            [
                "curl",
                "--fail",
                "--silent",
                "--max-time",
                "10",
                "http://127.0.0.1:8787/api/auth/session",
            ]
        )
    )
    if (
        session.get("setup_complete") is not False
        or session.get("authenticated") is not False
    ):
        native.fail("qualification_disaster_unconfigured_target_required")
    before = native.state.capture(native.ROOT)
    source = json.loads(raw["backup.snapshot"])
    key = "etc/exitlane/secret.key"
    if (
        before["database"]["tables"]["users"]["rows"]
        or before["state_files"][key]["sha256"] == source["state_files"][key]["sha256"]
    ):
        native.fail("qualification_disaster_fresh_key_and_database_required")
    staging = native.rejected_restore_state()["staging"]
    # Once started, no overwrite/retry is permitted, including after import or CLI
    # failure. Preserve all evidence for a separately authorized recovery decision.
    native.private_write(
        run.directory / "disaster.started",
        {
            "binding": run.binding,
            "source_isolation_operator_reference": isolation_reference,
        },
    )
    native.private_write(run.directory / "disaster-before.snapshot", before)
    for name, value in raw.items():
        native.private_bytes(run.directory / name, value)
    native.private_write(run.directory / "disaster-manifest.json", manifest)
    for action in ("inspect", "verify", "restore"):
        run.backup_cli(action, "disaster-" + action)
    native.healthy()
    native.installed(run.config["source"])
    restored = run.snapshot("disaster-after")
    run.compare(source, restored, "restore")
    if (
        before["state_files"]["etc/default/exitlane"]
        != restored["state_files"]["etc/default/exitlane"]
    ):
        native.fail("qualification_disaster_target_defaults_changed")
    if staging != native.rejected_restore_state()["staging"]:
        native.fail("qualification_disaster_staging_not_cleaned")
    run.api("disaster-login")
    names = (
        *FILES,
        *EVIDENCE,
        "disaster.started",
        "disaster-before.snapshot",
        "disaster-after.snapshot",
        "disaster-manifest.json",
        "disaster-inspect.log",
        "disaster-verify.log",
        "disaster-restore.log",
        "api-disaster-login.log",
    )
    record = {
        "type": "native-disaster-stage",
        "result": "PASS",
        "binding": run.binding,
        "harness": {**run.harness, "native_disaster.py": native.digest(Path(__file__))},
        "candidate_install_receipt": native.digest(
            run.directory / "candidate-install.json"
        ),
        "artifacts": {
            name: sha(native.private_read(run.directory / name)) for name in names
        },
        "scope": "synthetic disaster restore; DB session revocation and fresh MFA login; no old-cookie, source-isolation, routed-client or live-provider proof",
    }
    native.private_write(run.directory / "disaster.json", record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--action", required=True, choices=("export", "restore"))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--source-isolation-reference")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        config = native.configuration(args.config)
        if not args.execute:
            print(
                json.dumps(
                    {"type": "plan-only", "action": args.action, "executed": False}
                )
            )
            return 0
        native.preflight(config)
        run = native.Run(config)
        run.open()
        descriptor = run.lock()
        try:
            if args.action == "export":
                export_bundle(run, args.bundle)
            else:
                restore_bundle(run, args.bundle, args.source_isolation_reference)
        finally:
            os.close(descriptor)
        print(
            json.dumps(
                {"type": "native-disaster", "action": args.action, "result": "PASS"}
            )
        )
        return 0
    except (
        native.QualificationError,
        native.state.SnapshotError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        AssertionError,
        subprocess.SubprocessError,
    ):
        print(
            "qualification_disaster_failed; retain private evidence; do not retry",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
