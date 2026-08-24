"""Fail when workflow action pins or required main triggers regress."""

from __future__ import annotations

import re
from itertools import chain
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIRED_MAIN_PUSH_WORKFLOWS = (
    WORKFLOWS / "ci.yml",
    WORKFLOWS / "security-codeql.yml",
    WORKFLOWS / "security-supply-chain.yml",
    WORKFLOWS / "security-zap-baseline.yml",
)
ACTION_REFERENCE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA_REFERENCE = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
DIGEST_PINNED_CONTAINER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-fA-F]{64}$")
MAIN_PUSH = re.compile(
    r"(?m)^on:\s*$\n(?:(?:^[ \t]+.*\n)|(?:^\s*$\n))*?"
    r"^[ \t]+push:\s*$\n^[ \t]+branches:"
    r"(?:\s*\[main\]\s*$|\s*$\n^[ \t]+-\s+main\s*$)"
)


def main() -> int:
    failures: list[str] = []
    references = 0

    workflows = sorted(chain(WORKFLOWS.glob("*.yml"), WORKFLOWS.glob("*.yaml")))
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        for match in ACTION_REFERENCE.finditer(text):
            references += 1
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            if not (
                FULL_SHA_REFERENCE.fullmatch(reference)
                or DIGEST_PINNED_CONTAINER.fullmatch(reference)
            ):
                failures.append(f"{workflow.relative_to(ROOT)}: unpinned action {reference}")

    for workflow in REQUIRED_MAIN_PUSH_WORKFLOWS:
        text = workflow.read_text(encoding="utf-8")
        if not MAIN_PUSH.search(text):
            failures.append(f"{workflow.relative_to(ROOT)}: missing push trigger for main")

    if failures:
        print("Workflow security policy validation failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(
        "Workflow security policy valid: "
        f"{references} pinned action references; required push: main triggers present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
