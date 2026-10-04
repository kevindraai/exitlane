"""Fail closed on actionable image findings; retain the original Trivy JSON unchanged."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


IDENTITY = ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity")


def evaluate(scan: dict, manifest: dict) -> dict:
    """Only explicitly reviewed, unfixed Debian OS identities can receive residual status."""
    if scan.get("SchemaVersion") != 2 or not isinstance(scan.get("Results"), list):
        raise ValueError("invalid_trivy_report")
    if manifest.get("schema_version") != 1:
        raise ValueError("invalid_residual_manifest")
    reviews = {}
    for record in manifest["findings"]:
        identity = tuple(record[key] for key in IDENTITY)
        if identity in reviews or not all(isinstance(x, str) and x for x in identity):
            raise ValueError("invalid_residual_identity")
        for key in ("applicability", "mitigations", "evidence", "reviewed_at", "owner"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise ValueError("incomplete_residual_review")
        if record.get("disposition") != "residual-platform-risk":
            raise ValueError("invalid_residual_disposition")
        reviews[identity] = record
    os_info = scan.get("Metadata", {}).get("OS", {})
    debian = os_info == manifest.get("os") and os_info.get("Family") == "debian"
    blockers, residuals = [], []
    results = scan["Results"]
    if not any(r.get("Class") == "os-pkgs" for r in results):
        raise ValueError("missing_os_scan")
    if not any(r.get("Type") == "python-pkg" for r in results):
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
