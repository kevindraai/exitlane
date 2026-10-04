"""Release policy must not turn a reviewed OS residual into a scanner exclusion."""

import copy
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "release_scan", Path(__file__).resolve().parents[2] / "scripts/check_release_scan.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def candidate():
    finding = {
        "VulnerabilityID": "CVE-2026-1",
        "PkgName": "libtest",
        "InstalledVersion": "1.0-1",
        "Severity": "HIGH",
    }
    os_info = {"Family": "debian", "Name": "13.7"}
    scan = {
        "SchemaVersion": 2,
        "Metadata": {"OS": os_info},
        "Results": [
            {"Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [finding]},
            {"Class": "lang-pkgs", "Type": "python-pkg", "Vulnerabilities": []},
        ],
    }
    review = {
        **finding,
        "disposition": "residual-platform-risk",
        "applicability": "Reviewed configuration has no vulnerable prerequisite",
        "mitigations": "Supported updates and minimum privileges",
        "evidence": "source-family receipt",
        "reviewed_at": "2026-10-04",
        "owner": "maintainers",
    }
    return scan, {"schema_version": 1, "os": os_info, "findings": [review]}


def test_exact_reviewed_unfixed_debian_risk_passes_without_modifying_evidence():
    scan, manifest = candidate()
    original = copy.deepcopy(scan)
    decision = policy.evaluate(scan, manifest)
    assert decision["passed"]
    assert len(decision["residual_platform_risks"]) == 1
    assert scan == original


@pytest.mark.parametrize("field", ["VulnerabilityID", "PkgName", "InstalledVersion", "Severity"])
def test_review_does_not_cover_changed_identity(field):
    scan, manifest = candidate()
    scan["Results"][0]["Vulnerabilities"][0][field] = (
        "CRITICAL" if field == "Severity" else "different"
    )
    assert not policy.evaluate(scan, manifest)["passed"]


def test_available_fix_always_blocks_even_with_review():
    scan, manifest = candidate()
    scan["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = "1.0-2"
    assert not policy.evaluate(scan, manifest)["passed"]


def test_application_advisory_cannot_use_os_review():
    scan, manifest = candidate()
    scan["Results"][1]["Vulnerabilities"] = scan["Results"][0]["Vulnerabilities"]
    assert not policy.evaluate(scan, manifest)["passed"]


def test_all_secrets_block_without_copying_matched_value():
    scan, manifest = candidate()
    scan["Results"][0]["Secrets"] = [{"Severity": "LOW", "Match": "sensitive"}]
    decision = policy.evaluate(scan, manifest)
    assert not decision["passed"]
    assert "sensitive" not in str(decision)


def test_other_distribution_cannot_use_debian_residuals():
    scan, manifest = candidate()
    scan["Metadata"]["OS"] = {"Family": "ubuntu", "Name": "26.04"}
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("field", ["applicability", "mitigations", "evidence", "owner"])
def test_incomplete_review_fails_closed(field):
    scan, manifest = candidate()
    del manifest["findings"][0][field]
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


def test_duplicate_review_fails_closed():
    scan, manifest = candidate()
    manifest["findings"].append(manifest["findings"][0])
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("index", [0, 1])
def test_missing_scan_surface_fails_closed(index):
    scan, manifest = candidate()
    del scan["Results"][index]
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("field", ["Severity", "VulnerabilityID", "PkgName", "InstalledVersion"])
def test_malformed_findings_fail_closed(field):
    scan, manifest = candidate()
    del scan["Results"][0]["Vulnerabilities"][0][field]
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


def test_unknown_severity_value_fails_closed():
    scan, manifest = candidate()
    scan["Results"][0]["Vulnerabilities"][0]["Severity"] = "high"
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("field", ["Vulnerabilities", "Secrets"])
@pytest.mark.parametrize("value", [{}, "", False, 0, "bad", 1, [None], ["bad"]])
def test_malformed_collections_fail_closed(field, value):
    scan, manifest = candidate()
    scan["Results"][0][field] = value
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("value", [None, [], False, 0, "", {}])
def test_malformed_os_metadata_fails_closed(value):
    scan, manifest = candidate()
    scan["Metadata"]["OS"] = value
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


def test_single_inconsistent_result_cannot_claim_both_scan_surfaces():
    scan, manifest = candidate()
    scan["Results"] = [{"Class": "os-pkgs", "Type": "python-pkg"}]
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("value", [None, [], False, 0, ""])
def test_malformed_result_objects_fail_closed(value):
    scan, manifest = candidate()
    scan["Results"].append(value)
    with pytest.raises(ValueError):
        policy.evaluate(scan, manifest)


@pytest.mark.parametrize("value", [None, [], False, 0, ""])
def test_malformed_top_level_objects_fail_closed(value):
    _, manifest = candidate()
    with pytest.raises(ValueError):
        policy.evaluate(value, manifest)


@pytest.mark.parametrize("value", [None, []])
def test_valid_empty_collections_are_accepted(value):
    scan, manifest = candidate()
    scan["Results"][1]["Vulnerabilities"] = value
    scan["Results"][1]["Secrets"] = value
    assert policy.evaluate(scan, manifest)["passed"]
