#!/usr/bin/env python3
"""Fail when workflow action pins or the CodeQL main trigger regress."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CODEQL = WORKFLOWS / "security-codeql.yml"
ACTION_REFERENCE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA_REFERENCE = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
CODEQL_MAIN_PUSH = re.compile(
    r"(?m)^on:\s*$\n(?:(?:^[ \t]+.*\n)|(?:^\s*$\n))*?"
    r"^[ \t]+push:\s*$\n^[ \t]+branches:\s*\[main\]\s*$"
)


def main() -> int:
    failures: list[str] = []
    references = 0

    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for match in ACTION_REFERENCE.finditer(text):
            references += 1
            reference = match.group(1)
            if not FULL_SHA_REFERENCE.fullmatch(reference):
                failures.append(f"{workflow.relative_to(ROOT)}: unpinned action {reference}")

    codeql_text = CODEQL.read_text(encoding="utf-8")
    if not CODEQL_MAIN_PUSH.search(codeql_text):
        failures.append(f"{CODEQL.relative_to(ROOT)}: missing push trigger for main")

    if failures:
        print("Workflow security policy validation failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Workflow security policy valid: {references} full-SHA action references; CodeQL push: main")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
