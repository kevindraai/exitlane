"""Offline evidence contracts, including privacy and honest missing coverage."""

import importlib.util
import json
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[2] / "scripts/qualification/native_security_evidence.py"
SPEC = importlib.util.spec_from_file_location("native_security_evidence", MODULE)
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


def inventory(extra=""):
    return evidence.parse_dpkg_inventory(
        "libc6\tamd64\t2.41-1+b1\tinstall ok installed\tii \tglibc\t2.41-1\n" + extra
    )


def os_identity():
    return evidence.parse_os_release(
        'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n',
        "13.1",
        "amd64",
    )


def trivy():
    return {
        "SchemaVersion": 2,
        "ArtifactType": "filesystem",
        "Metadata": {"OS": {"Family": "debian", "Name": "13"}},
        "Results": [
            {
                "Target": "Debian",
                "Class": "os-pkgs",
                "Type": "debian",
                "Packages": [
                    {
                        "Name": "libc6",
                        "Arch": "amd64",
                        "Version": "2.41",
                        "Release": "1+b1",
                        "SrcName": "glibc",
                        "SrcVersion": "2.41",
                        "SrcRelease": "1",
                    }
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "libc6",
                        "InstalledVersion": "2.41-1+b1",
                        "Severity": "HIGH",
                        "Description": "Public advisory",
                        "FixedVersion": "99",
                    }
                ],
            }
        ],
    }


def validate(report, inv=None):
    return evidence.validate_trivy(json.dumps(report).encode(), inv or inventory(), os_identity())


def test_canonical_hash_and_nan_refusal():
    assert evidence.canonical_bytes({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()
    assert evidence.digest_value({"a": 1, "b": 2}) == evidence.digest_value({"b": 2, "a": 1})
    with pytest.raises(evidence.EvidenceError):
        evidence.canonical_bytes(float("nan"))


@pytest.mark.parametrize(
    "text,version,arch",
    [
        ("ID=ubuntu\nNAME=Ubuntu\nVERSION_ID=13\nVERSION_CODENAME=trixie", "13", "amd64"),
        ("ID=debian\nNAME=Debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm", "12", "amd64"),
        ("ID=debian\nNAME=Debian\nVERSION_ID=13\nVERSION_CODENAME=trixie", "13", "arm64"),
        ("ID=debian\nNAME=Debian\nVERSION_ID=13\nVERSION_CODENAME=trixie", "12", "amd64"),
        ("ID=debian\nVERSION_ID=13", "13", "amd64"),
        ("ID=debian\nID=debian", "13", "amd64"),
    ],
)
def test_os_unsupported_missing_contradictory(text, version, arch):
    with pytest.raises(evidence.EvidenceError):
        evidence.parse_os_release(text, version, arch)


def test_dpkg_partitions_multiarch_and_projection():
    inv = inventory(
        "libc6\ti386\t2.41-1+b1\thold ok installed\thi \tglibc\t2.41-1\n"
        "oldlib\tamd64\t1\tdeinstall ok config-files\trc \toldlib\t1\n"
        "partial\tamd64\t1\tinstall ok unpacked\tiU \tpartial\t1\n"
    )
    assert (inv["installed_count"], inv["residual_count"], inv["other_count"]) == (2, 1, 1)
    projection = evidence.dpkg_projection(inv)
    assert b"Source: glibc (2.41-1)" in projection
    assert b"Status: deinstall ok config-files" in projection
    inv["installed_count"] = 9
    with pytest.raises(evidence.EvidenceError):
        evidence.dpkg_projection(inv)


def test_dpkg_other_missing_identity_fields_retained_and_not_installed():
    inv = inventory(
        "old-selection\t\t\tunknown ok not-installed\tun \t\t\n"
        "pending\tamd64\t\tinstall ok not-installed\tin \tpending\t\n"
    )
    assert inv["installed_count"] == 1 and inv["other_count"] == 2
    assert inv["packages"][1]["version"] == inv["packages"][1]["architecture"] == ""
    projection = evidence.dpkg_projection(inv)
    assert b"Package: old-selection\nStatus: unknown ok not-installed\n\n" in projection
    assert b"Source:  ()" not in projection
    assert validate(trivy(), inv)["status"] == "incomplete"


@pytest.mark.parametrize(
    "status,abbrev", [("install ok installed", "ii "), ("deinstall ok config-files", "rc ")]
)
def test_dpkg_active_and_residual_missing_versions_rejected(status, abbrev):
    with pytest.raises(evidence.EvidenceError):
        evidence.parse_dpkg_inventory(f"missing\tamd64\t\t{status}\t{abbrev}\tmissing\t")


@pytest.mark.parametrize(
    "desired,abbrev", [("unknown", "un "), ("deinstall", "rn "), ("purge", "pn "), ("hold", "hn ")]
)
def test_normal_inactive_dpkg_selection_is_not_unstable(desired, abbrev):
    inv = inventory(f"inactive\t\t\t{desired} ok not-installed\t{abbrev}\t\t\n")
    assert inv["other_count"] == 1 and inv["unstable_count"] == 0
    assert inv["installed_count"] == 1
    assert validate(trivy(), inv)["status"] == "complete"


@pytest.mark.parametrize(
    "status,abbrev",
    [
        ("install ok not-installed", "in "),
        ("install ok unpacked", "iU "),
        ("install reinstreq installed", "iiR"),
    ],
)
def test_pending_or_broken_dpkg_record_is_unstable(status, abbrev):
    inv = inventory(f"pending\tamd64\t1\t{status}\t{abbrev}\tpending\t1\n")
    assert inv["unstable_count"] == 1
    assert validate(trivy(), inv)["status"] == "incomplete"


@pytest.mark.parametrize(
    "text",
    [
        "",
        "secret-canary",
        "a\tamd64\t1\tinstall ok installed\tii \ta\t1\na\tamd64\t2\tinstall ok installed\tii \ta\t2",
    ],
)
def test_dpkg_invalid_duplicate_does_not_echo(text):
    with pytest.raises(evidence.EvidenceError) as exc:
        evidence.parse_dpkg_inventory(text)
    assert "secret-canary" not in str(exc.value)


def test_trivy_complete_preserves_every_severity_and_finding():
    report = trivy()
    for severity in ("LOW", "MEDIUM", "CRITICAL", "UNKNOWN"):
        report["Results"][0]["Vulnerabilities"].append(
            {**report["Results"][0]["Vulnerabilities"][0], "Severity": severity}
        )
    result = validate(report)
    assert result["status"] == "complete"
    assert result["report"] == report
    assert result["findings"] == report["Results"][0]["Vulnerabilities"]


def test_modern_trivy_public_schema_and_exact_debian_minor():
    report = trivy()
    report.update(
        Trivy={"Version": "0.69.3"}, ReportID="public-report-id", ArtifactID="public-artifact-id"
    )
    report["Metadata"]["OS"]["Name"] = "13.1"
    report["Results"][0]["Packages"][0].update(
        Repository={"Class": "os-pkgs"}, InstalledFiles=["/usr/lib/libc.so.6"], AnalyzedBy="debian"
    )
    report["Results"][0]["Vulnerabilities"][0]["Fingerprint"] = "public-fingerprint"
    assert validate(report)["status"] == "complete"
    report["Metadata"]["OS"]["Name"] = "13.2"
    assert validate(report)["status"] == "incomplete"
    report["Trivy"]["private_environment"] = "canary"
    with pytest.raises(evidence.EvidenceError):
        validate(report)


@pytest.mark.parametrize("change", ["os", "missing", "unknown", "duplicate", "source", "version"])
def test_trivy_incomplete_not_zero(change):
    report = trivy()
    pkg = report["Results"][0]["Packages"][0]
    if change == "os":
        report["Metadata"]["OS"]["Name"] = "12"
    elif change == "missing":
        report["Results"][0]["Packages"] = []
    elif change == "unknown":
        pkg["Name"] = "unknown"
    elif change == "duplicate":
        report["Results"][0]["Packages"].append(dict(pkg))
    elif change == "source":
        pkg["SrcRelease"] = "2"
    else:
        pkg["Release"] = "2"
    result = validate(report)
    assert result["status"] == "incomplete"
    assert len(result["findings"]) == 1


def test_trivy_residual_omission_ok_but_abnormal_not_complete():
    inv = inventory("oldlib\tamd64\t1\tdeinstall ok config-files\trc \toldlib\t1\n")
    assert validate(trivy(), inv)["status"] == "complete"
    report = trivy()
    report["Results"][0]["Packages"].append(
        {"Name": "oldlib", "Arch": "amd64", "Version": "1", "SrcName": "oldlib", "SrcVersion": "1"}
    )
    report["Results"][0]["Vulnerabilities"].append(
        {
            "VulnerabilityID": "CVE-2026-0002",
            "PkgName": "oldlib",
            "InstalledVersion": "1",
            "Severity": "LOW",
        }
    )
    result = validate(report, inv)
    assert result["status"] == "complete" and len(result["findings"]) == 2
    inv = inventory("partial\tamd64\t1\tinstall ok unpacked\tiU \tpartial\t1\n")
    assert validate(trivy(), inv)["status"] == "incomplete"


@pytest.mark.parametrize("where", ["root", "metadata", "package", "vuln", "url", "custom"])
def test_secret_metadata_refused_before_artifact(where):
    report = trivy()
    if where == "url":
        report["Results"][0]["Vulnerabilities"][0]["PrimaryURL"] = (
            "https://user:canary@example.invalid/x"
        )
    elif where == "custom":
        report["Results"][0]["Vulnerabilities"][0]["Custom"] = {"private": "canary"}
    else:
        obj = {
            "root": report,
            "metadata": report["Metadata"],
            "package": report["Results"][0]["Packages"][0],
            "vuln": report["Results"][0]["Vulnerabilities"][0],
        }[where]
        obj["private_environment"] = "canary"
    with pytest.raises(evidence.EvidenceError) as exc:
        validate(report)
    assert "canary" not in str(exc.value)


def test_trivy_missing_schema_and_bad_json():
    for raw in (b"", b"[]", b'{"SchemaVersion":2,"SchemaVersion":2}', b'{"x":NaN}'):
        with pytest.raises(evidence.EvidenceError):
            evidence.validate_trivy(raw, inventory(), os_identity())
    report = trivy()
    del report["Results"][0]["Packages"]
    with pytest.raises(evidence.EvidenceError):
        validate(report)


@pytest.mark.parametrize(
    "target,key,value",
    [
        ("package", "Licenses", {"environment": "canary"}),
        ("package", "Epoch", "canary"),
        ("vuln", "VendorSeverity", {"debian": "canary"}),
        ("vuln", "References", [{"private": "canary"}]),
        ("vuln", "DataSource", {"Name": {"private": "canary"}}),
        ("vuln", "CVSS", {"debian": {"V3Score": "canary"}}),
    ],
)
def test_nested_public_schema_rejects_private_objects(target, key, value):
    report = trivy()
    obj = report["Results"][0]["Packages" if target == "package" else "Vulnerabilities"][0]
    obj[key] = value
    with pytest.raises(evidence.EvidenceError) as exc:
        validate(report)
    assert "canary" not in str(exc.value)


def test_trivy_epoch_and_missing_vulnerability_type():
    inv = evidence.parse_dpkg_inventory(
        "libc6\tamd64\t1:2.41-1+b1\tinstall ok installed\tii \tglibc\t1:2.41-1"
    )
    report = trivy()
    pkg = report["Results"][0]["Packages"][0]
    pkg["Epoch"] = pkg["SrcEpoch"] = 1
    report["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "1:2.41-1+b1"
    assert validate(report, inv)["status"] == "complete"
    report["Results"][0]["Vulnerabilities"] = {}
    with pytest.raises(evidence.EvidenceError):
        validate(report, inv)


def pip_report():
    return {
        "dependencies": [
            {
                "name": "some_Package",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "PYSEC-2026-1",
                        "fix_versions": ["1.1"],
                        "aliases": ["CVE-2026-0003"],
                        "description": "Public advisory",
                    }
                ],
            },
            {"name": "exitlane", "skip_reason": "Not on PyPI"},
        ],
        "fixes": [],
    }


def audit(report):
    return evidence.validate_pip_audit(
        json.dumps(report).encode(),
        [{"name": "some-package", "version": "1.0"}, {"name": "exitlane", "version": "1.0.0"}],
        {"exitlane": "local application identity separately bound"},
    )


def test_pip_actual_coverage_and_local_skip():
    result = audit(pip_report())
    assert result["status"] == "complete"
    assert len(result["findings"]) == 1
    assert result["coverage"]["skips"][0]["intentional"]


@pytest.mark.parametrize("change", ["missing", "extra", "duplicate", "wrong_version", "skip"])
def test_pip_coverage_failures(change):
    report = pip_report()
    if change == "missing":
        report["dependencies"].pop(0)
    elif change == "extra":
        report["dependencies"].append({"name": "extra", "version": "1", "vulns": []})
    elif change == "duplicate":
        report["dependencies"].append(report["dependencies"][0])
    elif change == "wrong_version":
        report["dependencies"][0]["version"] = "2"
    else:
        report["dependencies"][0] = {
            "name": "some-package",
            "version": "1.0",
            "skip_reason": "private dependency",
        }
    assert audit(report)["status"] == "incomplete"


@pytest.mark.parametrize("field", ["direct_url", "environment", "private_config"])
def test_pip_private_fields_refused(field):
    report = pip_report()
    report["dependencies"][0][field] = "canary"
    with pytest.raises(evidence.EvidenceError):
        audit(report)


def test_apt_source_binary_binnmu_and_policy():
    result = evidence.parse_apt_show(
        "Package: libc6\nArchitecture: amd64\nVersion: 2.41-2+b1\nSource: glibc (2.41-2)\n"
    )
    assert result["source_name"] == "glibc" and result["source_version"] == "2.41-2"
    assert (
        evidence.parse_apt_show("Package: demo\nArchitecture: all\nVersion: 1\n")["source_version"]
        == "1"
    )
    policy = evidence.parse_apt_policy(
        "libc6:\n  Installed: 2.41-1+b1\n  Candidate: 2.41-2+b1\n  Version table:\n     2.41-2+b1 500\n        500 https://deb.debian.org/debian trixie/main amd64 Packages\n        release o=Debian,a=stable,n=trixie,l=Debian,c=main,b=amd64\n *** 2.41-1+b1 100\n        100 /var/lib/dpkg/status\n"
    )
    assert policy["candidate"] == "2.41-2+b1"
    assert policy["versions"][0]["sources"][0]["origin"] == "Debian"
    with pytest.raises(evidence.EvidenceError):
        evidence.parse_apt_policy(
            "Installed: 1\nCandidate: 2\n2 500\n500 https://user:canary@example.invalid trixie/main amd64 Packages"
        )


def test_apt_simulation_full_transaction_and_indirect_exclusion():
    inv = inventory()["packages"] + [
        {"name": "nordvpn", "architecture": "amd64", "version": "1", "state": "installed"}
    ]
    result = evidence.parse_apt_simulation(
        "Inst libc6 [2.41-1+b1] (2.41-2+b1 Debian:stable [amd64])\nInst helper (1 Debian:stable [amd64])\nRemv nordvpn [1]\n",
        inv,
        ["nordvpn"],
    )
    assert len(result["upgrades"]) == len(result["additions"]) == len(result["removals"]) == 1
    assert result["excluded_touched"] == ["nordvpn"] and not result["eligible"]
    result = evidence.parse_apt_simulation(
        "The following packages have been kept back:\n  libc6\n", inv, []
    )
    assert result["held"] == ["libc6"] and not result["eligible"]
    with pytest.raises(evidence.EvidenceError):
        evidence.parse_apt_simulation("Inst malformed", inv, [])


def test_library_current_deleted_and_private_path_refusal():
    maps = "7f00-7f01 r-xp 00000000 08:01 42 /usr/lib/x86_64-linux-gnu/libc.so.6\n7f01-7f02 rw-p 00000001 08:01 42 /usr/lib/x86_64-linux-gnu/libc.so.6\n7f02-7f03 r-xp 00000000 08:01 40 /lib/x86_64-linux-gnu/libc.so.6 (deleted)\n7f03-7f04 rw-p 00000000 00:00 0 [heap]\n"
    result = evidence.parse_library_maps(maps, "libc.so.6")
    assert len(result) == 2 and result[1]["deleted"]
    assert "7f00" not in json.dumps(result) and "heap" not in json.dumps(result)
    assert evidence.parse_library_maps("", "libc.so.6") == []
    for line in ("malformed libc.so.6", "7f00-7f01 r-xp 0 08:01 42 /root/private/libc.so.6"):
        with pytest.raises(evidence.EvidenceError):
            evidence.parse_library_maps(line, "libc.so.6")


def classify(release, candidate=None, inv=None):
    tracker = {"glibc": {"CVE-2026-0001": {"releases": {"trixie": release}}}}
    compare_calls = []

    def compare(lhs, op, rhs):
        compare_calls.append((lhs, op, rhs))
        return lhs == rhs

    result = evidence.classify_findings(
        trivy()["Results"][0]["Vulnerabilities"],
        inv or inventory(),
        {"libc6:amd64": candidate} if candidate else {},
        tracker,
        compare,
    )
    return result[0], compare_calls


def test_primary_source_fix_join_never_scanner_binary_fix():
    candidate = {
        "source_name": "glibc",
        "source_version": "2.41-2",
        "version": "2.41-2+b8",
        "sources_authenticated": True,
        "eligible": True,
    }
    result, calls = classify({"status": "resolved", "fixed_version": "2.41-2"}, candidate)
    assert result["category"] == "supported_fix_in_captured_cache"
    assert calls == [("2.41-2", "ge", "2.41-2"), ("2.41-1", "ge", "2.41-2")]
    candidate["sources_authenticated"] = False
    assert (
        classify({"status": "resolved", "fixed_version": "2.41-2"}, candidate)[0]["category"]
        == "unresolved"
    )
    candidate["sources_authenticated"] = True
    candidate["source_version"] = "2.41-1"
    assert (
        classify({"status": "resolved", "fixed_version": "2.41-2"}, candidate)[0]["category"]
        == "primary_fix_not_in_captured_cache"
    )


@pytest.mark.parametrize(
    "release,category",
    [
        ({"status": "open", "fixed_version": "unfixed"}, "distribution_unfixed"),
        ({"status": "resolved", "fixed_version": "0"}, "distribution_not_affected"),
        ({"status": "undetermined", "fixed_version": "undetermined"}, "unresolved"),
        ({"status": "resolved"}, "unresolved"),
        ({"status": "resolved", "fixed_version": "2.41-2"}, "primary_fix_not_in_captured_cache"),
    ],
)
def test_primary_categories(release, category):
    assert classify(release)[0]["category"] == category


@pytest.mark.parametrize(
    "fixed",
    [
        "SECRET-CANARY",
        "1.0+secret-canary",
        "2.41-2\nPASSWORD=x",
        "https://user:password@example.invalid",
        "-1",
        "2 3",
        "2_3",
        {},
        ["2"],
        2,
    ],
)
def test_invalid_primary_fixed_versions_are_not_exported_or_compared(fixed):
    result, calls = classify({"status": "resolved", "fixed_version": fixed})
    assert result["category"] == "unresolved"
    assert result["tracker_fixed_version"] is None
    assert result["reason"] == "primary_fixed_version_invalid"
    assert calls == []
    assert "CANARY" not in json.dumps(result) and "PASSWORD" not in json.dumps(result)


def test_invalid_primary_status_and_candidate_version_not_exported():
    result, calls = classify({"status": {"private": "CANARY"}, "fixed_version": "2.41-2"})
    assert result["category"] == "unresolved" and result["tracker_fixed_version"] is None
    assert calls == []
    candidate = {
        "source_name": "glibc",
        "source_version": "SECRET-CANARY",
        "sources_authenticated": True,
        "eligible": True,
    }
    result, calls = classify({"status": "resolved", "fixed_version": "2.41-2"}, candidate)
    assert result["category"] == "unresolved" and result["candidate"] is None
    assert "CANARY" not in json.dumps(result) and calls == []


@pytest.mark.parametrize(
    "fixed",
    ["2:2.41-2+deb13u1", "0~20260101+gitabcdef-1", "1.2.3+dfsg-2", "1.0~rc1-1", "1.0-beta-2"],
)
def test_primary_valid_debian_versions_retained(fixed):
    result, _ = classify({"status": "resolved", "fixed_version": fixed})
    assert result["tracker_fixed_version"] == fixed
    assert result["category"] == "primary_fix_not_in_captured_cache"


def test_installed_source_already_fixed_is_primary_scanner_discrepancy():
    candidate = {
        "source_name": "glibc",
        "source_version": "2.41-2",
        "sources_authenticated": True,
        "eligible": True,
    }
    result, calls = classify({"status": "resolved", "fixed_version": "2.41-1"}, candidate)
    assert result["category"] == "unresolved"
    assert result["reason"] == "installed_source_at_primary_fix_discrepancy"
    assert ("2.41-1", "ge", "2.41-1") in calls
    assert result["finding"] == trivy()["Results"][0]["Vulnerabilities"][0]


def test_classification_residual_and_missing_tracker():
    inv = evidence.parse_dpkg_inventory(
        "libc6\tamd64\t2.41-1+b1\tdeinstall ok config-files\trc \tglibc\t2.41-1"
    )
    findings = trivy()["Results"][0]["Vulnerabilities"]
    assert (
        evidence.classify_findings(findings, inv, {}, None, lambda *_: False)[0]["category"]
        == "residual_not_installed"
    )
    assert (
        evidence.classify_findings(findings, inventory(), {}, None, lambda *_: False)[0]["category"]
        == "unresolved"
    )


def test_worksheet_same_counts_hash_and_injection_escape():
    receipt = {
        "status": "incomplete",
        "cells": {
            "scan\n# forged|row": {"status": "incomplete", "finding_count": 2, "sha256": "abc"}
        },
    }
    text = evidence.worksheet(receipt)
    assert "finding_count: 2" in text and evidence.digest_value(receipt) in text
    assert "scan\\u000a\\# forged\\|row" in text
    assert "\n# forged" not in text
    assert "PASS" not in text


def test_worksheet_integrated_receipt_shape_missing_findings():
    receipt = {
        "collection_status": "error",
        "cells": {"native_scan": {"status": "error", "data": {"finding_count": "unavailable"}}},
        "findings": {"native": None, "python": {"venv": []}},
        "artifacts": {"scan.json": {"sha256": "f" * 64, "size": 2}},
    }
    text = evidence.worksheet(receipt)
    assert "Collection completeness: error" in text
    assert "Findings native: unavailable" in text
    assert "Findings python/venv: 0" in text
    assert "f" * 64 in text


def test_worksheet_public_identities_and_collection_decision_separation():
    receipt = {
        "collection_status": "incomplete",
        "cells": {
            "os": {"status": "complete", "data": os_identity()},
            "application": {
                "status": "complete",
                "data": {
                    "version": "1.0.0",
                    "source_sha": "a" * 40,
                    "historical_build_provenance": "unresolved",
                    "private_config": "CANARY",
                },
            },
            "python_venv": {
                "status": "complete",
                "data": {
                    "interpreter": {"version": "3.13.5"},
                    "distributions": [{"name": "public", "version": "1"}],
                },
            },
            "trivy": {
                "status": "complete",
                "data": {
                    "tool_version": "0.69.3",
                    "database": {"sha256": "b" * 64},
                    "coverage": {"expected_count": 1, "observed_count": 1, "missing": []},
                    "findings": [],
                },
            },
            "apt": {
                "status": "incomplete",
                "data": {
                    "sources_authenticated": False,
                    "candidates": {"libc6": {}},
                    "simulation": {"upgrades": [1], "removals": [], "eligible": False},
                },
            },
            "libraries": {"status": "complete", "data": {"restart_needed": True}},
        },
        "applicability": [{"category": "unresolved"}, {"category": "distribution_unfixed"}],
    }
    text = evidence.worksheet(receipt)
    for expected in (
        "version: 1\\.0\\.0",
        "source_sha: " + "a" * 40,
        "historical_build_provenance: unresolved",
        "distributions count: 1",
        "tool_version: 0\\.69\\.3",
        "b" * 64,
        "coverage expected_count: 1",
        "simulation upgrades count: 1",
        "restart_needed: True",
        "Applicability unresolved: 1",
    ):
        assert expected in text
    assert "CANARY" not in text
    assert "captured-cache projection" in text
