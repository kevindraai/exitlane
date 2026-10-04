"""Fail closed on actionable image findings; retain the original Trivy JSON unchanged."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


IDENTITY = ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")


def evaluate(scan: dict, manifest: dict) -> dict:
    """Only explicitly reviewed, unfixed Debian OS identities can receive residual status."""
    if (
        not isinstance(scan, dict)
        or scan.get("SchemaVersion") != 2
        or not isinstance(scan.get("Results"), list)
    ):
        raise ValueError("invalid_trivy_report")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != 1
        or not isinstance(manifest.get("findings"), list)
    ):
        raise ValueError("invalid_residual_manifest")
    reviews = {}
    for record in manifest["findings"]:
        if not isinstance(record, dict):
            raise ValueError("invalid_residual_record")
        identity = tuple(record[key] for key in IDENTITY)
        if identity in reviews or not all(isinstance(x, str) and x for x in identity):
            raise ValueError("invalid_residual_identity")
        for key in ("applicability", "mitigations", "evidence", "reviewed_at", "owner"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise ValueError("incomplete_residual_review")
        if record.get("disposition") != "residual-platform-risk":
            raise ValueError("invalid_residual_disposition")
        reviews[identity] = record
    metadata = scan.get("Metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("OS"), dict):
        raise ValueError("missing_os_metadata")
    os_info = metadata["OS"]
    if (
        os_info.get("Family") != "debian"
        or not isinstance(os_info.get("Name"), str)
        or not os_info["Name"]
    ):
        raise ValueError("invalid_debian_os_metadata")
    debian = os_info == manifest.get("os")
    blockers, residuals = [], []
    results = scan["Results"]
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("invalid_scan_result")
        result_class, result_type = result.get("Class"), result.get("Type")
        if result_class == "os-pkgs" and result_type != "debian":
            raise ValueError("inconsistent_os_scan")
        if result_type == "python-pkg" and result_class != "lang-pkgs":
            raise ValueError("inconsistent_python_scan")
        for field in ("Vulnerabilities", "Secrets"):
            collection = result.get(field)
            # Trivy may omit empty collections or encode them as null; other types are invalid.
            if collection is not None and not isinstance(collection, list):
                raise ValueError("invalid_finding_collection")
            if collection is not None and not all(
                isinstance(item, dict) for item in collection
            ):
                raise ValueError("invalid_finding_object")
    if not any(
        r.get("Class") == "os-pkgs" and r.get("Type") == "debian" for r in results
    ):
        raise ValueError("missing_os_scan")
    if not any(
        r.get("Class") == "lang-pkgs" and r.get("Type") == "python-pkg" for r in results
    ):
        raise ValueError("missing_python_scan")
    for result in results:
        if result.get("Secrets"):
            # Never copy a scanner secret's matched value into the decision report/log.
            blockers.append(
                {"reason": "secret_findings", "count": len(result["Secrets"])}
            )
        for finding in result.get("Vulnerabilities") or []:
            if finding.get("Severity") not in (
                "UNKNOWN",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            ):
                raise ValueError("invalid_finding_severity")
            if not all(
                isinstance(finding.get(key), str) and finding[key] for key in IDENTITY
            ):
                raise ValueError("invalid_finding_identity")
            if finding.get("FixedVersion") is not None and not isinstance(
                finding["FixedVersion"], str
            ):
                raise ValueError("invalid_fixed_version")
            if finding.get("Severity") not in ("HIGH", "CRITICAL"):
                continue
            identity = tuple(finding[key] for key in IDENTITY)
            item = dict(zip(IDENTITY, identity, strict=True))
            reviewed = (
                debian
                and result.get("Class") == "os-pkgs"
                and result.get("Type") == "debian"
                and not finding.get("FixedVersion")
                and identity in reviews
            )
            if reviewed:
                residuals.append({**item, "review": reviews[identity]})
            else:
                blockers.append(
                    {**item, "reason": "fix_available_or_unreviewed_or_application"}
                )
    return {
        "passed": not blockers,
        "blockers": blockers,
        "residual_platform_risks": residuals,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.scan.read_bytes()
    try:
        scan = json.loads(raw)
        if not isinstance(scan, dict):
            raise ValueError("invalid_trivy_report")
        if (
            scan.get("ArtifactName") != args.artifact
            or scan.get("ArtifactType") != "container_image"
        ):
            raise ValueError("scan_artifact_identity_mismatch")
        decision = evaluate(scan, json.loads(args.manifest.read_text()))
    except (ValueError, KeyError, TypeError) as exc:
        # Avoid echoing potentially sensitive malformed input.
        decision = {"passed": False, "error": type(exc).__name__}
    decision["scan_sha256"] = hashlib.sha256(raw).hexdigest()
    decision["manifest_sha256"] = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(decision, indent=2) + "\n")
    print("release_scan_passed" if decision["passed"] else "release_scan_blocked")
    return 0 if decision["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
