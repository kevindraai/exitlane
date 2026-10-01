"""Bundle public licenses and allowlisted Help guides in wheel and sdist builds."""

from __future__ import annotations

import ast
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        root = Path(self.root)
        package = root / "exitlane"
        catalog = ast.parse((package / "documentation.py").read_text(encoding="utf-8"))
        definitions = next(
            node.value
            for node in catalog.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "DOCUMENTS" for target in node.targets
            )
        )
        documents = [ast.literal_eval(item.args[2]) for item in definitions.elts]
        sources = [
            (root.parent / name, package / name, f"exitlane/{name}")
            for name in ("LICENSE", "THIRD_PARTY_NOTICES.md")
        ]
        sources.extend(
            (root.parent / "docs" / name, package / "docs" / name, f"exitlane/docs/{name}")
            for name in documents
        )
        for repository_source, bundled_source, destination in sources:
            # A wheel rebuilt from its sdist must use the already bundled files.
            source = bundled_source if bundled_source.is_file() else repository_source
            if not source.is_file():
                raise FileNotFoundError(f"Required public package file missing: {destination}")
            build_data["force_include"][str(source)] = destination
