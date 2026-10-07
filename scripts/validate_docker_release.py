#!/usr/bin/env python3
"""Fail-closed validation for an explicitly dispatched GHCR image release."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TAG = re.compile(
    r"v(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)(?:-rc\.(?P<rc>[1-9][0-9]*))?\Z"
)
SHA = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
MINIMUM_DOCKER_RELEASE_SHA = "be97510c8ef5468b38e8ef6cbac7a738fa329620"
MAX_RELEASE_RESPONSE = 1024 * 1024
MAX_PROJECT_METADATA = 64 * 1024
PUBLICATION_ENVIRONMENT = "ghcr-production"
PRODUCT_OWNER = "kevindraai"


class ReleaseValidationError(RuntimeError):
    """A stable, non-secret validation error suitable for workflow logs."""


def package_version_for_tag(tag: str) -> str:
    match = TAG.fullmatch(tag) if isinstance(tag, str) else None
    if match is None:
        raise ReleaseValidationError("docker_release_tag_invalid")
    base = ".".join(match.group(name) for name in ("major", "minor", "patch"))
    return base + ("rc" + match.group("rc") if match.group("rc") is not None else "")


def validate_published_release(tag: str, release: Any) -> None:
    if (
        not isinstance(release, dict)
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or not isinstance(release.get("published_at"), str)
        or not release["published_at"].strip()
    ):
        raise ReleaseValidationError("docker_release_not_published")


def _is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
        timeout=15,
    )
    return result.returncode == 0


def _tag_commit(tag: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or SHA.fullmatch(value) is None:
        raise ReleaseValidationError("docker_release_tag_commit_invalid")
    return value


def _project_version(source_sha: str) -> str:
    if SHA.fullmatch(source_sha or "") is None:
        raise ReleaseValidationError("docker_release_source_sha_invalid")
    path = f"{source_sha}:backend/pyproject.toml"
    try:
        size = subprocess.check_output(
            ["git", "cat-file", "-s", path],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
        ).strip()
        if not size.isdecimal() or int(size) > MAX_PROJECT_METADATA:
            raise ReleaseValidationError("docker_release_project_metadata_invalid")
        source = subprocess.check_output(
            ["git", "show", path],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        project = tomllib.loads(source)
    except (OSError, subprocess.SubprocessError, tomllib.TOMLDecodeError):
        raise ReleaseValidationError("docker_release_project_metadata_invalid") from None
    metadata = project.get("project")
    version = metadata.get("version") if isinstance(metadata, dict) else None
    if not isinstance(version, str):
        raise ReleaseValidationError("docker_release_project_metadata_invalid")
    return version


def _fetch_release(tag: str, repository: str, token: str) -> dict[str, Any]:
    if TAG.fullmatch(tag) is None:
        raise ReleaseValidationError("docker_release_tag_invalid")
    if REPOSITORY.fullmatch(repository) is None:
        raise ReleaseValidationError("docker_release_repository_invalid")
    url = f"https://api.github.com/repos/{repository}/releases/tags/{tag}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ExitLane-Docker-release-validator",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(MAX_RELEASE_RESPONSE + 1)
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ReleaseValidationError("docker_release_api_unavailable") from None
    if len(raw) > MAX_RELEASE_RESPONSE:
        raise ReleaseValidationError("docker_release_api_response_too_large")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ReleaseValidationError("docker_release_api_response_invalid") from None
    validate_published_release(tag, result)
    return result


def validate_publication_environment(
    environment: Any,
    *,
    name: str = PUBLICATION_ENVIRONMENT,
    prevent_self_review: bool = False,
) -> None:
    """Fail before scheduling a job that could auto-create an unprotected environment."""
    if not isinstance(environment, dict) or environment.get("name") != name:
        raise ReleaseValidationError("docker_release_approval_environment_missing")
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        raise ReleaseValidationError("docker_release_product_owner_approval_required")
    approval = [r for r in rules if isinstance(r, dict) and r.get("type") == "required_reviewers"]
    reviewers = approval[0].get("reviewers") if len(approval) == 1 else None
    if (
        not isinstance(reviewers, list)
        or len(reviewers) != 1
        or not isinstance(reviewers[0], dict)
        or reviewers[0].get("type") != "User"
        or not isinstance(reviewers[0].get("reviewer"), dict)
        or reviewers[0]["reviewer"].get("login") != PRODUCT_OWNER
    ):
        raise ReleaseValidationError("docker_release_product_owner_approval_required")
    if prevent_self_review and approval[0].get("prevent_self_review") is not True:
        raise ReleaseValidationError("docker_release_self_review_forbidden")
    if environment.get("can_admins_bypass") is not False:
        raise ReleaseValidationError("docker_release_approval_bypass_forbidden")
    policy = environment.get("deployment_branch_policy")
    if not isinstance(policy, dict) or policy != {
        "protected_branches": True,
        "custom_branch_policies": False,
    }:
        raise ReleaseValidationError("docker_release_protected_branch_required")


def _fetch_publication_environment(
    repository: str,
    token: str,
    *,
    name: str = PUBLICATION_ENVIRONMENT,
    prevent_self_review: bool = False,
) -> dict[str, Any]:
    if REPOSITORY.fullmatch(repository) is None:
        raise ReleaseValidationError("docker_release_repository_invalid")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/environments/{name}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ExitLane-Docker-release-validator",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(MAX_RELEASE_RESPONSE + 1)
        if len(raw) > MAX_RELEASE_RESPONSE:
            raise ReleaseValidationError("docker_release_approval_response_too_large")
        environment = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise ReleaseValidationError("docker_release_approval_environment_unavailable") from None
    validate_publication_environment(
        environment, name=name, prevent_self_review=prevent_self_review
    )
    return environment


def validate(
    *,
    tag: str,
    source_sha: str,
    confirmation: str,
    current_sha: str,
    main_sha: str,
    project_version: str,
    release: Any,
    tag_commit: str,
    is_ancestor=_is_ancestor,
    minimum_sha: str = MINIMUM_DOCKER_RELEASE_SHA,
) -> dict[str, str]:
    app_version = package_version_for_tag(tag)
    if (
        SHA.fullmatch(source_sha or "") is None
        or SHA.fullmatch(current_sha or "") is None
        or SHA.fullmatch(main_sha or "") is None
        or SHA.fullmatch(tag_commit or "") is None
        or SHA.fullmatch(minimum_sha or "") is None
        or current_sha != main_sha
        or source_sha != tag_commit
        or project_version != app_version
        or confirmation != f"PUBLISH EXITLANE {tag} {source_sha}"
    ):
        raise ReleaseValidationError("docker_release_source_confirmation_mismatch")
    validate_published_release(tag, release)
    try:
        ancestry = is_ancestor(minimum_sha, source_sha) and is_ancestor(source_sha, main_sha)
    except (OSError, subprocess.SubprocessError):
        ancestry = False
    if not ancestry:
        raise ReleaseValidationError("docker_release_source_not_qualified_main")
    return {
        "tag": tag,
        "source_sha": source_sha,
        "app_version": "v" + app_version,
        "image": "ghcr.io/kevindraai/exitlane:" + tag,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if REPOSITORY.fullmatch(repository) is None or not token:
        print("docker_release_environment_invalid", file=sys.stderr)
        return 2
    try:
        app_version = package_version_for_tag(args.tag)
        _fetch_publication_environment(repository, token)
        release = _fetch_release(args.tag, repository, token)
        facts = validate(
            tag=args.tag,
            source_sha=args.source_sha,
            confirmation=args.confirmation,
            current_sha=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True, timeout=15
            ).strip(),
            main_sha=os.environ.get("GITHUB_SHA", ""),
            project_version=_project_version(args.source_sha),
            release=release,
            tag_commit=_tag_commit(args.tag),
        )
        if facts["app_version"] != "v" + app_version:
            raise ReleaseValidationError("docker_release_version_mismatch")
    except (
        ReleaseValidationError,
        OSError,
        subprocess.SubprocessError,
        tomllib.TOMLDecodeError,
    ) as exc:
        code = (
            str(exc)
            if isinstance(exc, ReleaseValidationError)
            else "docker_release_validation_failed"
        )
        print(code, file=sys.stderr)
        return 1
    if args.github_output is not None:
        try:
            with args.github_output.open("a", encoding="utf-8") as output:
                for name, value in facts.items():
                    output.write(f"{name}={value}\n")
        except OSError:
            print("docker_release_output_unavailable", file=sys.stderr)
            return 1
    else:
        print(json.dumps(facts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
