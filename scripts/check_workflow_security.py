"""Fail when workflow action pins or required main triggers regress."""

from __future__ import annotations

import re
from itertools import chain
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIRED_MAIN_PUSH_WORKFLOWS = (
    WORKFLOWS / "ci.yml",
    WORKFLOWS / "security-codeql.yml",
    WORKFLOWS / "security-supply-chain.yml",
    WORKFLOWS / "security-zap-baseline.yml",
)
FULL_SHA_REFERENCE = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")
DIGEST_PINNED_CONTAINER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-fA-F]{64}$")
ALLOWED_ACTION_OWNERS = {"actions", "github"}
MAIN_PUSH = re.compile(
    r"(?m)^on:\s*$\n(?:(?:^[ \t]+.*\n)|(?:^\s*$\n))*?"
    r"^[ \t]+push:\s*$\n^[ \t]+branches:"
    r"(?:\s*\[main\]\s*$|\s*$\n^[ \t]+-\s+main\s*$)"
)


class UniqueKeyLoader(yaml.BaseLoader):
    """Keep workflow keys such as 'on' as strings and reject ambiguous mappings."""


def _unique_mapping(loader, node):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def action_references(value):
    if isinstance(value, dict):
        if "uses" in value:
            yield value["uses"]
        for child in value.values():
            yield from action_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from action_references(child)


def workflow_references(text):
    return list(action_references(yaml.load(text, Loader=UniqueKeyLoader)))


def main() -> int:
    failures: list[str] = []
    references = 0

    workflows = sorted(chain(WORKFLOWS.glob("*.yml"), WORKFLOWS.glob("*.yaml")))
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        try:
            workflow_actions = workflow_references(text)
        except yaml.YAMLError as exc:
            failures.append(
                f"{workflow.relative_to(ROOT)}: invalid workflow YAML: {exc}"
            )
            continue
        for reference in workflow_actions:
            references += 1
            if not isinstance(reference, str):
                failures.append(
                    f"{workflow.relative_to(ROOT)}: invalid action reference"
                )
                continue
            if reference.startswith("./"):
                continue
            if not (
                FULL_SHA_REFERENCE.fullmatch(reference)
                or DIGEST_PINNED_CONTAINER.fullmatch(reference)
            ):
                failures.append(
                    f"{workflow.relative_to(ROOT)}: unpinned action {reference}"
                )
                continue

            action = reference.removeprefix("docker://")
            owner, separator, _name = action.partition("/")
            if not separator or owner.lower() not in ALLOWED_ACTION_OWNERS:
                failures.append(
                    f"{workflow.relative_to(ROOT)}: action owner not allowed by repository policy: {reference}"
                )

    for workflow in REQUIRED_MAIN_PUSH_WORKFLOWS:
        text = workflow.read_text(encoding="utf-8")
        if not MAIN_PUSH.search(text):
            failures.append(
                f"{workflow.relative_to(ROOT)}: missing push trigger for main"
            )

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
