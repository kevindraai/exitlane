#!/usr/bin/env python3
"""Bind attestation recovery to one qualified, already published digest; never push."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from validate_docker_release import SHA, ReleaseValidationError, package_version_for_tag

REPO = "kevindraai/exitlane"
QUALIFIED_STEPS = (
    "Verify trusted workflow and application source identities",
    "Build exact versioned amd64 image",
    "Check installed files and dependencies",
    "Qualify release image provider TLS",
    "Qualify release image health and state contract",
    "Scan exact release image for OS, Python and secrets",
    "Create SPDX SBOM for exact release image",
    "Publish one version tag without replacing an existing release",
    "Pull the exact published digest",
    "Verify pulled digest metadata and contents",
)


def validate_origin(*, run, jobs, log, run_id, tag, source_sha, digest):
    package_version_for_tag(tag)
    if (
        SHA.fullmatch(source_sha) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ReleaseValidationError("docker_resume_identity_invalid")
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ReleaseValidationError("docker_resume_run_invalid")
    if (
        run.get("id") != int(run_id)
        or run.get("head_sha") != source_sha
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("path") != ".github/workflows/docker-release.yml"
        or run.get("status") != "completed"
        or run.get("conclusion") != "failure"
        or run.get("repository", {}).get("full_name") != REPO
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] < 1
    ):
        raise ReleaseValidationError("docker_resume_origin_run_mismatch")
    publishing = [job for job in jobs if job.get("name") == "publish"]
    if len(publishing) != 1:
        raise ReleaseValidationError("docker_resume_origin_job_missing")
    job = publishing[0]
    steps = job.get("steps", [])
    for required in QUALIFIED_STEPS:
        matching = [s for s in steps if s.get("name") == required]
        if len(matching) != 1 or matching[0].get("conclusion") != "success":
            raise ReleaseValidationError("docker_resume_origin_unqualified")
    failed = [step.get("name") for step in steps if step.get("conclusion") == "failure"]
    if failed != ["Attest image build provenance"]:
        raise ReleaseValidationError("docker_resume_origin_failure_mismatch")
    observed = re.findall(
        re.escape(f"Pushed ghcr.io/{REPO}:{tag} with digest ")
        + r"(sha256:[0-9a-f]{64})",
        log,
    )
    if observed != [digest]:
        raise ReleaseValidationError("docker_resume_published_digest_mismatch")
    return {
        "source_sha": source_sha,
        "tag": tag,
        "digest": digest,
        "original_workflow_sha": source_sha,
        "original_invocation": f"{run_id}/{run['run_attempt']}",
        "original_log_sha256": hashlib.sha256(log.encode()).hexdigest(),
        "qualification": "original exact-image and pulled-digest steps passed; fresh recovery checks remain mandatory",
    }


def api(path):
    raw = subprocess.check_output(["gh", "api", path], timeout=30)
    if len(raw) > 8 * 1024 * 1024:
        raise ReleaseValidationError("docker_resume_response_too_large")
    return json.loads(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]*", args.run_id):
        parser.error("invalid original run ID")
    run = api(f"repos/{REPO}/actions/runs/{args.run_id}")
    jobs = api(
        f"repos/{REPO}/actions/runs/{args.run_id}/attempts/{run['run_attempt']}/jobs?per_page=100"
    )["jobs"]
    publishing = [job for job in jobs if job.get("name") == "publish"]
    if len(publishing) != 1:
        raise ReleaseValidationError("docker_resume_origin_job_missing")
    log = subprocess.check_output(
        [
            "gh",
            "run",
            "view",
            args.run_id,
            "--repo",
            REPO,
            "--job",
            str(publishing[0]["id"]),
            "--log",
        ],
        text=True,
        timeout=60,
    )
    if len(log.encode()) > 16 * 1024 * 1024:
        raise ReleaseValidationError("docker_resume_log_too_large")
    result = validate_origin(
        run=run,
        jobs=jobs,
        log=log,
        run_id=args.run_id,
        tag=args.tag,
        source_sha=args.source_sha,
        digest=args.digest,
    )
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n")
    args.log_output.write_text(log)


if __name__ == "__main__":
    main()
