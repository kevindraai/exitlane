#!/usr/bin/env python3
"""Bind the selected application source and trusted workflow to a verified image."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from validate_docker_release import SHA, ReleaseValidationError, package_version_for_tag

PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
REPOSITORY = "https://github.com/kevindraai/exitlane"
WORKFLOW = REPOSITORY + "/.github/workflows/docker-release.yml@refs/heads/main"
IMAGE = "ghcr.io/kevindraai/exitlane"
MAX_VERIFICATION_BYTES = 8 * 1024 * 1024


def predicate(*, tag: str, source_sha: str, workflow_sha: str, invocation: str) -> dict:
    package_version_for_tag(tag)
    if SHA.fullmatch(source_sha) is None or SHA.fullmatch(workflow_sha) is None:
        raise ReleaseValidationError("docker_release_provenance_sha_invalid")
    if re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", invocation) is None:
        raise ReleaseValidationError("docker_release_provenance_invocation_invalid")
    return {
        "buildDefinition": {
            "buildType": REPOSITORY
            + "/blob/"
            + workflow_sha
            + "/docs/docker-appliance-candidate.md",
            "externalParameters": {
                "releaseTag": tag,
                "sourceSha": source_sha,
                "dockerfile": "docker/Dockerfile.appliance",
                "platform": "linux/amd64",
            },
            "resolvedDependencies": [
                {
                    "uri": "git+" + REPOSITORY + "@refs/tags/" + tag,
                    "digest": {"gitCommit": source_sha},
                },
                {
                    "uri": "git+" + REPOSITORY + "@refs/heads/main",
                    "digest": {"gitCommit": workflow_sha},
                },
            ],
        },
        "runDetails": {
            "builder": {"id": WORKFLOW},
            "metadata": {"invocationId": REPOSITORY + "/actions/runs/" + invocation},
        },
    }


def verify(results, *, digest: str, expected: dict) -> None:
    """Consume only JSON from a successful, policy-constrained gh attestation verify."""
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None or not isinstance(
        results, list
    ):
        raise ReleaseValidationError("docker_release_provenance_result_invalid")
    for result in results:
        verified = (
            result.get("verificationResult") if isinstance(result, dict) else None
        )
        statement = verified.get("statement") if isinstance(verified, dict) else None
        if not isinstance(statement, dict):
            continue
        if (
            statement.get("_type") == "https://in-toto.io/Statement/v1"
            and statement.get("predicateType") == PREDICATE_TYPE
            and statement.get("subject")
            == [{"name": IMAGE, "digest": {"sha256": digest.removeprefix("sha256:")}}]
            and statement.get("predicate") == expected
        ):
            return
    raise ReleaseValidationError("docker_release_provenance_source_mismatch")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("create", "verify"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--invocation", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--digest")
    args = parser.parse_args(argv)
    try:
        expected = predicate(
            tag=args.tag,
            source_sha=args.source_sha,
            workflow_sha=args.workflow_sha,
            invocation=args.invocation,
        )
        if args.operation == "create":
            if args.output is None:
                parser.error("create requires --output")
            args.output.write_text(
                json.dumps(expected, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            if args.input is None or args.digest is None:
                parser.error("verify requires --input and --digest")
            if args.input.stat().st_size > MAX_VERIFICATION_BYTES:
                raise ReleaseValidationError(
                    "docker_release_provenance_result_too_large"
                )
            verify(
                json.loads(args.input.read_text(encoding="utf-8")),
                digest=args.digest,
                expected=expected,
            )
    except (OSError, ValueError, ReleaseValidationError) as exc:
        print(
            str(exc)
            if isinstance(exc, ReleaseValidationError)
            else "docker_release_provenance_unavailable",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
