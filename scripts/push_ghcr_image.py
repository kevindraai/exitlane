#!/usr/bin/env python3
"""Push one previously checked ExitLane release image and report its registry digest."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-rc\.[1-9][0-9]*)?\Z"
)
IMAGE = re.compile(r"ghcr\.io/kevindraai/exitlane:(v[^\s@]+)\Z")
DIGEST_LINE = re.compile(r"(?m)^\S+: digest: (sha256:[a-f0-9]{64}) size: [0-9]+\s*$")
REGISTRY_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
MAX_PACKAGE_RESPONSE = 1024 * 1024
MAX_PACKAGE_PAGES = 10


class PushError(RuntimeError):
    pass


def _existing_release_digest(tag: str, repository: str, token: str, *, open_url=urllib.request.urlopen) -> str | None:
    if TAG.fullmatch(tag) is None or repository != "kevindraai/exitlane" or not token:
        raise PushError("docker_release_environment_invalid")
    for page in range(1, MAX_PACKAGE_PAGES + 1):
        request = urllib.request.Request(
            "https://api.github.com/user/packages/container/exitlane/versions"
            f"?per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ExitLane-Docker-release-publisher",
            },
        )
        try:
            with open_url(request, timeout=15) as response:
                raw = response.read(MAX_PACKAGE_RESPONSE + 1)
        except urllib.error.HTTPError as error:
            if error.code == 404 and page == 1:
                return None
            raise PushError("docker_release_tag_registry_state_unknown") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise PushError("docker_release_tag_registry_state_unknown") from None
        if len(raw) > MAX_PACKAGE_RESPONSE:
            raise PushError("docker_release_tag_registry_response_too_large")
        try:
            versions: Any = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PushError("docker_release_tag_registry_response_invalid") from None
        if not isinstance(versions, list) or any(not isinstance(item, dict) for item in versions):
            raise PushError("docker_release_tag_registry_response_invalid")
        matches = []
        for item in versions:
            metadata = item.get("metadata")
            container = metadata.get("container") if isinstance(metadata, dict) else None
            tags = container.get("tags") if isinstance(container, dict) else None
            name = item.get("name")
            if not isinstance(name, str) or REGISTRY_DIGEST.fullmatch(name) is None or not isinstance(tags, list):
                raise PushError("docker_release_tag_registry_response_invalid")
            if any(not isinstance(value, str) for value in tags):
                raise PushError("docker_release_tag_registry_response_invalid")
            if tag in tags:
                matches.append(item)
        if matches:
            digests = {item.get("name") for item in matches}
            if len(digests) != 1 or REGISTRY_DIGEST.fullmatch(next(iter(digests)) or "") is None:
                raise PushError("docker_release_tag_registry_response_invalid")
            # Version tags are never overwritten. A failed later workflow step
            # needs an explicitly reviewed recovery path, not an implicit repush.
            raise PushError("docker_release_tag_already_published")
        if len(versions) < 100:
            return None
    raise PushError("docker_release_tag_registry_scan_limit")


def push_digest(image: str, *, run=subprocess.run) -> str:
    match = IMAGE.fullmatch(image) if isinstance(image, str) else None
    if match is None or TAG.fullmatch(match.group(1)) is None:
        raise PushError("docker_push_image_invalid")
    try:
        result = run(
            ["docker", "push", image],
            capture_output=True,
            check=False,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PushError("docker_push_failed") from None
    if result.returncode != 0:
        raise PushError("docker_push_failed")
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    digests = set(DIGEST_LINE.findall(output))
    if len(digests) != 1:
        raise PushError("docker_push_digest_invalid")
    return digests.pop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        token = os.environ.get("GITHUB_TOKEN", "")
        if repository != "kevindraai/exitlane" or not token:
            raise PushError("docker_release_environment_invalid")
        match = IMAGE.fullmatch(args.image)
        if match is None or TAG.fullmatch(match.group(1)) is None:
            raise PushError("docker_push_image_invalid")
        tag = match.group(1)
        _existing_release_digest(tag, repository, token)
        digest = push_digest(args.image)
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"digest={digest}\n")
    except (PushError, OSError) as exc:
        code = str(exc) if isinstance(exc, PushError) else "docker_push_output_unavailable"
        print(code, file=sys.stderr)
        return 1
    print(f"Pushed {args.image} with digest {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
