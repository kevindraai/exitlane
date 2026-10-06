#!/usr/bin/env python3
"""Plan-first, read-only native package/advisory collection. Never a release waiver."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import ast
import hashlib
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from native_security_apt import collect_apt
from native_security_evidence import (
    EvidenceError,
    canonical_bytes,
    classify_findings,
    digest_value,
    dpkg_projection,
    parse_dpkg_inventory,
    parse_os_release,
    worksheet,
)
from native_security_host import ReadOnlyHost

COLLECTOR_FILES = (
    "native_security.py",
    "native_security_host.py",
    "native_security_evidence.py",
    "native_security_apt.py",
)
DPKG_FORMAT = "${Package}\t${Architecture}\t${Version}\t${Status}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\n"
REQUIRED = {
    "os",
    "dpkg",
    "application",
    "collector",
    "python_os",
    "python_venv",
    "python_bootstrap",
    "python_bundled",
    "trivy",
    "audit_os",
    "audit_venv",
    "audit_bootstrap",
    "audit_bundled",
    "target_consistency",
}
PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
PACKAGE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+~:_-]{0,127}")


def cell_error(reason, status="incomplete"):
    return {"status": status, "reason": reason, "data": {}}


def public_packages(packages):
    if not isinstance(packages, list):
        raise EvidenceError("python_inventory_invalid")
    result, seen = [], set()
    for package in packages:
        if (
            set(package) != {"name", "version"}
            or not isinstance(package["name"], str)
            or not isinstance(package["version"], str)
            or not PACKAGE_NAME.fullmatch(package["name"])
            or not PACKAGE_VERSION.fullmatch(package["version"])
        ):
            raise EvidenceError("python_package_identity_invalid")
        name = re.sub(r"[-_.]+", "-", package["name"]).lower()
        identity = (name, package["version"])
        if identity in seen:
            continue
        if any(n == name for n, _ in seen):
            raise EvidenceError("python_package_version_ambiguous")
        seen.add(identity)
        result.append({"name": name, "version": package["version"]})
    return sorted(result, key=lambda item: item["name"])


def bundled_packages(manifests):
    packages = []
    for manifest in manifests:
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"parent", "sha256", "manifest"}
            or not PACKAGE_NAME.fullmatch(manifest["parent"])
            or not re.fullmatch("[0-9a-f]{64}", manifest["sha256"])
            or not isinstance(manifest["manifest"], str)
        ):
            raise EvidenceError("bundled_manifest_invalid")
        for line in manifest["manifest"].splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            pin = line.split(";", 1)[0].strip()
            match = re.fullmatch(r"([A-Za-z0-9._-]+)==([A-Za-z0-9.!+~:_-]+)", pin)
            if not match:
                raise EvidenceError("bundled_package_identity_unresolved")
            packages.append({"name": match[1], "version": match[2]})
    return public_packages(packages)


def git_identity(host, source, prefixes):
    """Verify committed public content without Git filters, status hooks or remote access."""
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise EvidenceError("source_directory_invalid")
    git = [
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(source),
    ]
    identity = {}
    for key, expression in [("commit", "HEAD"), ("tree", "HEAD^{tree}")]:
        result = host.run([*git, "rev-parse", expression])
        value = result.stdout.decode().strip()
        if result.returncode != 0 or not re.fullmatch("[0-9a-f]{40}", value):
            raise EvidenceError("source_identity_unavailable")
        identity[key] = value
    tree = host.run([*git, "ls-tree", "-rz", "--full-tree", "HEAD", "--", *prefixes])
    if tree.returncode != 0:
        raise EvidenceError("source_public_tree_unavailable")
    entries = {}
    for record in tree.stdout.split(b"\0"):
        if not record:
            continue
        meta, path_raw = record.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        relative = path_raw.decode()
        path = Path(relative)
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or path.is_absolute()
            or ".." in path.parts
        ):
            raise EvidenceError("source_public_tree_invalid")
        raw = host.read_public(source / relative)
        # Git SHA-1 is its content-addressed source identity; retained payload hashes use SHA-256.
        if (
            hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False
            ).hexdigest()
            != blob
        ):
            raise EvidenceError("source_public_content_drift")
        entries[relative] = hashlib.sha256(raw).hexdigest()
    if not entries:
        raise EvidenceError("source_public_tree_empty")
    return identity, entries


def package_source_manifest(host, source):
    identity, entries = git_identity(
        host,
        source,
        [
            "backend/exitlane",
            "backend/pyproject.toml",
            "backend/hatch_build.py",
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            "docs",
        ],
    )
    expected = {
        name.removeprefix("backend/exitlane/"): digest
        for name, digest in entries.items()
        if name.startswith("backend/exitlane/")
    }
    source = Path(source)
    # The existing build hook bundles these exact public guides and licenses.
    catalog = ast.parse(
        host.read_public(source / "backend/exitlane/documentation.py").decode()
    )
    definitions = next(
        node.value
        for node in catalog.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "DOCUMENTS"
            for target in node.targets
        )
    )
    for name in [
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        *("docs/" + ast.literal_eval(item.args[2]) for item in definitions.elts),
    ]:
        if name not in entries:
            raise EvidenceError("packaged_source_metadata_unavailable")
        expected[name] = entries[name]
    return identity, expected


def application_identity(host, source, observed, prefix):
    if (
        not isinstance(observed, dict)
        or set(observed) != {"version", "location", "metadata_path", "record_path"}
        or not PACKAGE_VERSION.fullmatch(observed["version"])
    ):
        raise EvidenceError("installed_application_identity_unavailable")
    location = Path(observed["location"])
    prefix = Path(prefix).resolve()
    if (
        not location.is_relative_to(prefix)
        or location.name != "exitlane"
        or location.parent.name != "site-packages"
    ):
        raise EvidenceError("installed_application_location_invalid")
    identity, expected = package_source_manifest(host, source)
    names = set()
    for directory, directories, files in os.walk(location, followlinks=False):
        directories[:] = [name for name in directories if name != "__pycache__"]
        for name in directories + files:
            path = Path(directory) / name
            if path.is_symlink():
                raise EvidenceError("installed_application_content_invalid")
        names.update(
            (Path(directory) / name).relative_to(location).as_posix()
            for name in files
            if not name.endswith(".pyc")
        )
    if names != set(expected):
        raise EvidenceError("installed_application_content_mismatch")
    actual = {
        name: hashlib.sha256(host.read_public(location / name)).hexdigest()
        for name in sorted(names)
    }
    if actual != expected:
        raise EvidenceError("installed_application_content_mismatch")
    metadata = Path(observed["metadata_path"])
    record = Path(observed["record_path"])
    if (
        metadata.parent != record.parent
        or not metadata.is_relative_to(prefix)
        or metadata.name != "METADATA"
        or record.name != "RECORD"
    ):
        raise EvidenceError("installed_package_metadata_invalid")
    import tomllib

    expected_version = tomllib.loads(
        host.read_public(Path(source) / "backend/pyproject.toml").decode()
    )["project"]["version"]
    if expected_version != observed["version"]:
        raise EvidenceError("installed_package_version_mismatch")
    return {
        "version": observed["version"],
        "package_metadata_sha256": hashlib.sha256(
            host.read_public(metadata)
        ).hexdigest(),
        "package_record_sha256": hashlib.sha256(host.read_public(record)).hexdigest(),
        "content_sha256": digest_value(actual),
        "source": identity,
        "source_equivalence": "matched",
        "historical_build_commit": None,
        "historical_build_provenance": "unavailable_not_inferred_from_content_equivalence",
    }


def collector_identity(host, source):
    identity, entries = git_identity(
        host, source, ["scripts/qualification/" + name for name in COLLECTOR_FILES]
    )
    if len(entries) != len(COLLECTOR_FILES):
        raise EvidenceError("collector_source_identity_unavailable")
    running = Path(__file__).resolve().parent
    for name in COLLECTOR_FILES:
        relative = "scripts/qualification/" + name
        if (
            hashlib.sha256(host.read_public(running / name)).hexdigest()
            != entries[relative]
        ):
            raise EvidenceError("collector_source_content_mismatch")
    return {"version": "1", **identity, "module_sha256": entries}


def plan(options):
    return {
        "kind": "native-security-qualification-plan",
        "schema_version": 1,
        "execution": False,
        "host_mutation": False,
        "observations": [
            "Debian OS identity",
            "native dpkg installed/residual states",
            "installed ExitLane public code/package identity",
            "application source content equivalence",
            "collector source identity",
            "OS Python/stdlib and distributions",
            "current bootstrap wheels",
            "declared bundled dependencies",
            "actual final venv distributions",
            "offline native package-metadata Trivy scan",
        ],
        "external_python_advisory_lookup": options.allow_network,
        "apt": "controlled current-cache projection; simulation only"
        if options.simulate_apt
        else "controlled current-cache candidate projection",
        "libraries": {"service": options.service, "library": options.library}
        if options.library
        else "not requested",
        "output": str(options.output),
        "limits": [
            "no package/service/routing/provider mutations",
            "no private configuration/database/environment/arguments/memory collection",
            "not a security waiver or automatic release decision",
        ],
    }


def collect(options, host):
    cells, artifacts = {}, {}
    receipt = {
        "kind": "native-security-qualification",
        "schema_version": 1,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "collection_status": "incomplete",
        "cells": cells,
        "findings": {"native": None, "python": {}},
        "applicability": [],
        "artifacts": artifacts,
        "release_decision": "maintainer_review_required",
        "host_mutation": False,
    }

    def retain(name, raw):
        path = options.output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        artifacts[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}

    def capture(name, function):
        try:
            value = function()
            cells[name] = (
                value
                if isinstance(value, dict) and "status" in value
                else {"status": "complete", "data": value}
            )
        except EvidenceError as error:
            cells[name] = cell_error(error.code, "error")
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            UnicodeError,
            StopIteration,
            SyntaxError,
            RecursionError,
        ):
            cells[name] = cell_error("observation_unavailable")
        return cells[name]

    def observe_os():
        if (host.root / ".dockerenv").exists():
            raise EvidenceError("native_target_is_docker")
        release = host.root / "etc/os-release"
        if release.is_symlink():
            if release.resolve() != (host.root / "usr/lib/os-release").resolve():
                raise EvidenceError("os_release_path_invalid")
            release = release.resolve()
        arch = host.run(["/usr/bin/dpkg", "--print-architecture"])
        if arch.returncode != 0:
            raise EvidenceError("native_architecture_query_failed")
        data = parse_os_release(
            host.read_public(release, 65536).decode(),
            host.read_public(host.root / "etc/debian_version", 128).decode(),
            arch.stdout.decode(),
        )
        manager = host.run(["/usr/bin/dpkg-query", "--version"])
        match = re.match(
            rb"Debian dpkg-query package management program query tool version ([0-9A-Za-z.+~:-]+)",
            manager.stdout,
        )
        if manager.returncode != 0 or not match:
            raise EvidenceError("native_package_manager_identity_unavailable")
        data["package_manager"] = {"name": "dpkg", "version": match[1].decode()}
        machine = host.read_public(host.root / "etc/machine-id", 128).strip()
        if not re.fullmatch(rb"[0-9a-f]{32}", machine):
            raise EvidenceError("native_machine_identity_unavailable")
        data["machine_id_sha256"] = hashlib.sha256(machine).hexdigest()
        return data

    capture("os", observe_os)
    inventory = None

    def observe_dpkg():
        nonlocal inventory
        result = host.run(
            ["/usr/bin/dpkg-query", "--show", "--showformat", DPKG_FORMAT]
        )
        if result.returncode != 0:
            raise EvidenceError("native_package_query_failed")
        inventory = parse_dpkg_inventory(result.stdout.decode())
        if inventory["installed_count"] == 0:
            raise EvidenceError("native_installed_inventory_empty")
        retain("dpkg-inventory.json", canonical_bytes(inventory))
        data = {**inventory, "sha256": digest_value(inventory)}
        return {
            "status": "incomplete" if inventory["unstable_count"] else "complete",
            "data": data,
        }

    capture("dpkg", observe_dpkg)
    initial_inventory_hash = digest_value(inventory) if inventory else None
    capture("collector", lambda: collector_identity(host, options.collector_source))
    probes = {}
    for name, executable, mode, prefix in [
        ("python_os", "/usr/bin/python3", "os", ""),
        ("python_venv", options.venv_python, "venv", str(options.venv_prefix)),
    ]:

        def observe_python(executable=executable, mode=mode, prefix=prefix, name=name):
            data = host.python(executable, mode, prefix)
            if set(data) != {
                "interpreter",
                "distributions",
                "application",
                "bootstrap",
                "bundled",
                "bundled_gaps",
            } or set(data["interpreter"]) != {
                "version",
                "implementation",
                "executable",
                "stdlib",
                "binary_sha256",
            }:
                raise EvidenceError("python_observation_schema_invalid")
            data["distributions"] = public_packages(data["distributions"])
            if (
                not PACKAGE_VERSION.fullmatch(data["interpreter"]["version"])
                or data["interpreter"]["implementation"] != "cpython"
                or not re.fullmatch(
                    "[0-9a-f]{64}", data["interpreter"]["binary_sha256"]
                )
                or any(
                    not isinstance(data["interpreter"][key], str)
                    or not Path(data["interpreter"][key]).is_absolute()
                    or re.search(r"[\x00-\x20\x7f]", data["interpreter"][key])
                    for key in ("executable", "stdlib")
                )
            ):
                raise EvidenceError("python_interpreter_identity_invalid")
            probes[name] = data
            value = {
                "interpreter": data["interpreter"],
                "distributions": data["distributions"],
            }
            retain(name + "-inventory.json", canonical_bytes(value))
            return value

        capture(name, observe_python)
    if "python_venv" in probes:
        capture(
            "application",
            lambda: application_identity(
                host,
                options.application_source,
                probes["python_venv"]["application"],
                options.venv_prefix,
            ),
        )
    else:
        cells["application"] = cell_error("installed_application_identity_unavailable")

    def bootstrap():
        if "python_os" not in probes:
            raise EvidenceError("bootstrap_inventory_unavailable")
        data = probes["python_os"]["bootstrap"]
        if set(data) != {"ensurepip_present", "wheels", "historical_execution"}:
            raise EvidenceError("bootstrap_observation_invalid")
        packages, hashes = [], {}
        for wheel in data["wheels"]:
            if (
                set(wheel) != {"filename", "name", "version", "sha256", "bundled"}
                or Path(wheel["filename"]).name != wheel["filename"]
                or not re.fullmatch("[0-9a-f]{64}", wheel["sha256"])
            ):
                raise EvidenceError("bootstrap_wheel_identity_invalid")
            packages.append({"name": wheel["name"], "version": wheel["version"]})
            hashes[wheel["filename"]] = wheel["sha256"]
        value = {
            "packages": public_packages(packages),
            "wheel_sha256": hashes,
            "ensurepip_present": data["ensurepip_present"],
            "historical_execution": "unresolved_no_contemporaneous_evidence",
        }
        status = (
            "incomplete" if data["ensurepip_present"] and not packages else "complete"
        )
        return {"status": status, "data": value}

    capture("python_bootstrap", bootstrap)

    def bundles():
        if not probes:
            raise EvidenceError("bundled_inventory_unavailable")
        manifests, gaps = [], []
        for layer, data in probes.items():
            manifests.extend((layer, manifest) for manifest in data["bundled"])
            gaps.extend(data["bundled_gaps"])
        for wheel in probes.get("python_os", {}).get("bootstrap", {}).get("wheels", []):
            manifests.extend(("bootstrap", manifest) for manifest in wheel["bundled"])
        if any(
            set(gap) != {"parent", "reason"}
            or not PACKAGE_NAME.fullmatch(gap["parent"])
            or gap["reason"] != "bundled_dependency_manifest_unavailable"
            for gap in gaps
        ):
            raise EvidenceError("bundled_observation_invalid")
        value = {
            "groups": [
                {
                    "layer": layer,
                    "parent": manifest["parent"],
                    "manifest_sha256": manifest["sha256"],
                    "packages": bundled_packages([manifest]),
                }
                for layer, manifest in manifests
            ],
            "gaps": gaps,
            "manifest_sha256": sorted({m["sha256"] for _, m in manifests}),
            "interpretation": "declared_current_embedded_versions_not_historical_execution",
            "scope": "current_os_distributions_bootstrap_wheels_and_final_venv_manifests",
        }
        return {"status": "incomplete" if gaps else "complete", "data": value}

    capture("python_bundled", bundles)
    for layer, source_name in [
        ("os", "python_os"),
        ("venv", "python_venv"),
        ("bootstrap", "python_bootstrap"),
        ("bundled", "python_bundled"),
    ]:

        def audit(layer=layer, source_name=source_name):
            source = cells[source_name]
            if source["status"] not in {"complete", "incomplete"} or not source["data"]:
                return cell_error("python_inventory_unavailable")
            if layer == "bundled":
                observations, findings = [], []
                for index, group in enumerate(source["data"]["groups"]):
                    value, raw = host.audit(
                        options.pip_audit,
                        group["packages"],
                        allow_network=options.allow_network,
                        layer=f"bundled-{index}",
                    )
                    if raw is not None:
                        retain(f"pip-audit-bundled-{index}.json", raw)
                    observations.append({**group, "audit": value})
                    if value["data"].get("findings") is not None:
                        findings.extend(
                            {
                                **finding,
                                "bundled_layer": group["layer"],
                                "bundled_parent": group["parent"],
                            }
                            for finding in value["data"]["findings"]
                        )
                states = {item["audit"]["status"] for item in observations}
                status = (
                    "error"
                    if "error" in states
                    else "incomplete"
                    if "incomplete" in states
                    else "complete"
                )
                result_findings = findings if status == "complete" else None
                receipt["findings"]["python"][layer] = result_findings
                return {
                    "status": status,
                    "data": {"groups": observations, "findings": result_findings},
                }
            packages = source["data"].get(
                "distributions", source["data"].get("packages", [])
            )
            value, raw = host.audit(
                options.pip_audit,
                packages,
                allowed_skips={
                    "exitlane": "local_application_source_qualified_separately"
                },
                allow_network=options.allow_network,
                layer=layer,
            )
            if raw is not None:
                retain("pip-audit-" + layer + ".json", raw)
            receipt["findings"]["python"][layer] = value["data"].get("findings")
            return value

        capture("audit_" + layer, audit)

    def scan():
        if cells["os"]["status"] != "complete" or not inventory:
            return cell_error("native_scan_prerequisites_incomplete")
        projection = host.work / "native-rootfs"
        (projection / "etc").mkdir(parents=True, mode=0o700)
        (projection / "var/lib/dpkg").mkdir(parents=True, mode=0o700)
        status = dpkg_projection(inventory)
        identity = cells["os"]["data"]
        os_release = b'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID=13\nVERSION_CODENAME=trixie\n'
        (projection / "etc/os-release").write_bytes(os_release)
        (projection / "etc/debian_version").write_text(
            identity["debian_version"] + "\n"
        )
        (projection / "var/lib/dpkg/status").write_bytes(status)
        retain("dpkg-public-status.txt", status)
        retain("native-os-identity.json", canonical_bytes(identity))
        value, raw = host.trivy(
            options.trivy, options.trivy_cache, projection, inventory, identity
        )
        if raw is not None:
            retain("trivy-native.json", raw)
        value["data"]["projection_sha256"] = hashlib.sha256(
            status + os_release + identity["debian_version"].encode()
        ).hexdigest()
        receipt["findings"]["native"] = value["data"].get("findings")
        return value

    capture("trivy", scan)
    if inventory:
        capture(
            "apt", lambda: collect_apt(host, inventory, simulate=options.simulate_apt)
        )
    else:
        cells["apt"] = cell_error("native_inventory_unavailable")
    tracker = None

    def primary():
        nonlocal tracker
        if options.debian_tracker is None:
            return {
                "status": "skipped",
                "reason": "primary_advisory_snapshot_not_supplied",
                "data": {},
            }
        raw = host.read_public(options.debian_tracker, 64 * 1024 * 1024)
        tracker = json.loads(raw)
        if not isinstance(tracker, dict):
            raise EvidenceError("primary_advisory_snapshot_invalid")
        # Do not export the full tracker or arbitrary descriptions/URLs.
        return {
            "source": "Debian security tracker operator-supplied snapshot",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "trust": "operator_supplied_not_fetched_or_authenticated",
            "captured_at": receipt["observed_at"],
        }

    capture("primary_advisories", primary)
    if receipt["findings"]["native"] is not None and inventory:
        candidates = cells["apt"].get("data", {}).get("candidates", {})

        def compare(left, operator, right):
            if not PACKAGE_VERSION.fullmatch(left) or not PACKAGE_VERSION.fullmatch(
                right
            ):
                raise ValueError("version_invalid")
            result = host.run(
                ["/usr/bin/dpkg", "--compare-versions", left, operator, right]
            )
            if result.returncode not in (0, 1):
                raise ValueError("comparison_failed")
            return result.returncode == 0

        receipt["applicability"] = classify_findings(
            receipt["findings"]["native"], inventory, candidates, tracker, compare
        )
    if options.library:
        capture("libraries", lambda: host.libraries(options.service, options.library))
        if options.maintenance_receipt:
            try:
                raw = host.read_public(options.maintenance_receipt)
                previous = json.loads(raw)
                current = cells["libraries"]
                prior = previous["cells"]["libraries"]
                previous_machine = previous["cells"]["os"]["data"]["machine_id_sha256"]
                current_machine = cells["os"]["data"]["machine_id_sha256"]
                if (
                    previous["kind"] != "native-security-qualification"
                    or previous["schema_version"] != 1
                    or previous_machine != current_machine
                    or prior["status"] != "complete"
                    or current["status"] != "complete"
                    or prior["data"]["service"] != current["data"]["service"]
                    or prior["data"]["library"] != current["data"]["library"]
                    or datetime.fromisoformat(previous["observed_until"])
                    >= datetime.fromisoformat(receipt["observed_at"])
                ):
                    raise EvidenceError("maintenance_target_binding_invalid")
                old, new = prior["data"], current["data"]
                for value in (
                    old["boot_id_sha256"],
                    previous_machine,
                    previous["cells"]["application"]["data"]["content_sha256"],
                    previous["cells"]["dpkg"]["data"]["sha256"],
                ):
                    if not isinstance(value, str) or not re.fullmatch(
                        "[0-9a-f]{64}", value
                    ):
                        raise EvidenceError("maintenance_public_identity_invalid")
                if (
                    type(old["start_ticks"]) is not int
                    or old["start_ticks"] <= 0
                    or type(old["pid"]) is not int
                    or old["pid"] <= 0
                    or type(old["restart_required"]) is not bool
                ):
                    raise EvidenceError("maintenance_process_identity_invalid")
                rebooted = old["boot_id_sha256"] != new["boot_id_sha256"]
                restarted = rebooted or (old["pid"], old["start_ticks"]) != (
                    new["pid"],
                    new["start_ticks"],
                )
                current["data"]["maintenance_evidence"] = {
                    "previous_receipt_sha256": hashlib.sha256(raw).hexdigest(),
                    "trust": "operator_supplied_previous_observation_not_authenticated",
                    "same_machine": True,
                    "process_restart_observed": restarted,
                    "boot_change_observed": rebooted,
                    "stale_mappings_cleared": restarted
                    and old["restart_required"] is True
                    and new["restart_required"] is False,
                    "previous_application_content_sha256": previous["cells"][
                        "application"
                    ]["data"]["content_sha256"],
                    "previous_dpkg_sha256": previous["cells"]["dpkg"]["data"]["sha256"],
                }
            except (
                OSError,
                EvidenceError,
                ValueError,
                KeyError,
                TypeError,
                RecursionError,
            ):
                cells["libraries"] = cell_error("maintenance_evidence_unavailable")
    else:
        cells["libraries"] = {
            "status": "skipped",
            "reason": "not_requested",
            "data": {},
        }

    def consistency():
        if initial_inventory_hash is None:
            return cell_error("initial_inventory_unavailable")
        result = host.run(
            ["/usr/bin/dpkg-query", "--show", "--showformat", DPKG_FORMAT]
        )
        if result.returncode != 0:
            raise EvidenceError("final_native_package_query_failed")
        final_hash = digest_value(parse_dpkg_inventory(result.stdout.decode()))
        stable = initial_inventory_hash == final_hash
        return {
            "status": "complete" if stable else "incomplete",
            "reason": None if stable else "native_inventory_changed_during_collection",
            "data": {
                "before_sha256": initial_inventory_hash,
                "after_sha256": final_hash,
                "interpretation": "inventory_consistency_not_proof_of_no_external_host_mutation",
            },
        }

    capture("target_consistency", consistency)
    receipt["observed_until"] = datetime.now(timezone.utc).isoformat()
    receipt["collection_status"] = aggregate(cells, bool(options.library))
    receipt["summary"] = {
        "native_findings": None
        if receipt["findings"]["native"] is None
        else len(receipt["findings"]["native"]),
        "applicability_categories": dict(
            Counter(item["category"] for item in receipt["applicability"])
        ),
    }
    return receipt


def aggregate(cells, libraries_requested=False):
    required = REQUIRED | ({"libraries"} if libraries_requested else set())
    if any(name not in cells for name in required):
        return "incomplete"
    if any(
        not isinstance(cell, dict)
        or cell.get("status") not in {"complete", "incomplete", "error", "skipped"}
        or not isinstance(cell.get("data"), dict)
        for cell in cells.values()
    ):
        return "error"
    if any(cell.get("status") == "error" for cell in cells.values()):
        return "error"
    if any(cells[name].get("status") != "complete" for name in required) or any(
        cell.get("status") == "incomplete" for cell in cells.values()
    ):
        return "incomplete"
    return "complete"


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute the printed read-only plan, writing only the new private output directory.",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--application-source", type=Path, required=True)
    parser.add_argument(
        "--collector-source", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--venv-prefix", type=Path, default=Path("/opt/exitlane/venv"))
    parser.add_argument("--venv-python", default="/opt/exitlane/venv/bin/python")
    parser.add_argument("--trivy", default="/usr/local/bin/trivy")
    parser.add_argument("--trivy-cache", type=Path, default=Path("/root/.cache/trivy"))
    parser.add_argument("--pip-audit", default="/usr/local/bin/pip-audit")
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Permit the planned PyPI advisory lookup; never permits package downloads or maintenance.",
    )
    parser.add_argument(
        "--debian-tracker",
        type=Path,
        help="Explicit primary advisory JSON snapshot; no automatic tracker download.",
    )
    parser.add_argument("--simulate-apt", action="store_true")
    parser.add_argument(
        "--service",
        default="exitlane.service",
        choices=["exitlane.service", "nordvpnd.service"],
    )
    parser.add_argument(
        "--library", help="One selected system library basename, such as libssl.so.3."
    )
    parser.add_argument(
        "--maintenance-receipt",
        type=Path,
        help="Bind a previous native collector receipt from the same machine/service/library to fresh process and mapping observations; operator-supplied, not authenticated.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    options = arguments(argv)
    inspection_plan = plan(options)
    print(canonical_bytes(inspection_plan).decode())
    if not options.execute:
        return 0
    os.umask(0o077)
    try:
        if (
            not options.output.is_absolute()
            or options.output.exists()
            or options.output.is_symlink()
        ):
            raise EvidenceError("output_must_be_new_absolute_directory")
        if (
            any(parent.is_symlink() for parent in options.output.parents)
            or ".." in options.output.parts
        ):
            raise EvidenceError("output_ancestor_invalid")
        for source in (
            options.application_source,
            options.collector_source,
            options.venv_prefix,
        ):
            if options.output.is_relative_to(source.resolve()):
                raise EvidenceError("output_must_not_modify_target")
        options.output.mkdir(mode=0o700)
        work = options.output / "work"
        work.mkdir(mode=0o700)
        receipt = collect(options, ReadOnlyHost(work))
        raw = canonical_bytes(receipt)
        (options.output / "receipt.json").write_bytes(raw)
        (options.output / "worksheet.txt").write_text(
            worksheet(receipt), encoding="utf-8"
        )
        print(
            canonical_bytes(
                {
                    "collection_status": receipt["collection_status"],
                    "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                    "output": str(options.output),
                }
            ).decode()
        )
        return 0 if receipt["collection_status"] == "complete" else 2
    except (OSError, EvidenceError) as error:
        print(
            canonical_bytes(
                {
                    "collection_status": "error",
                    "reason": error.code
                    if isinstance(error, EvidenceError)
                    else "artifact_write_failed",
                }
            ).decode()
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
