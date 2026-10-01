#!/usr/bin/env python3
"""Push one previously checked ExitLane release image and report its registry digest."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-rc\.[1-9][0-9]*)?\Z"
)
IMAGE = re.compile(r"ghcr\.io/kevindraai/exitlane:(v[^\s@]+)\Z")
DIGEST_LINE = re.compile(r"(?m)^\S+: digest: (sha256:[a-f0-9]{64}) size: [0-9]+\s*$")


class PushError(RuntimeError):
    pass


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
