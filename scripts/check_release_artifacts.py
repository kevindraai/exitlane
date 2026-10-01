#!/usr/bin/env python3
"""Inspect release packages without executing their application or extracting private state."""

from __future__ import annotations

import argparse
import ast
import email
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = re.compile(r"(^|/)(\.env(?:\..*)?|\.git|\.venv|\.agents|\.codex|__pycache__|"
                     r"\.pytest_cache|\.ruff_cache|secret\.key|.*\.(?:db|sqlite|sqlite3|elb|log|pyc))(/|$)")


def inspect(path: Path) -> dict:
    version = tomllib.loads((ROOT / "backend/pyproject.toml").read_text())["project"]["version"]
    catalog = ast.parse((ROOT / "backend/exitlane/documentation.py").read_text())
    definitions = next(node.value for node in catalog.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "DOCUMENTS"
                               for target in node.targets))
    guides = [ast.literal_eval(item.args[2]) for item in definitions.elts]
    wheel = path.suffix == ".whl"
    if wheel:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            files = {name: archive.read(name) for name in names if not name.endswith("/")}
        prefix = ""
        metadata = next(value for name, value in files.items() if name.endswith(".dist-info/METADATA"))
    else:
        prefix = f"exitlane-{version}/"
        with tarfile.open(path, "r:gz") as archive:
            entries = archive.getmembers()
            if any(not entry.isfile() and not entry.isdir() for entry in entries):
                raise ValueError("Archive contains non-regular entries")
            names = [entry.name for entry in entries]
            files = {entry.name: archive.extractfile(entry).read() for entry in entries if entry.isfile()}
        metadata = files[prefix + "PKG-INFO"]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate archive paths")
    for name in names:
        if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or PRIVATE.search(name):
            raise ValueError(f"Unexpected/private package path: {name}")
        if wheel and any(part in {"tests", "scripts", "node_modules"} for part in PurePosixPath(name).parts):
            raise ValueError(f"Development files in wheel: {name}")
    parsed = email.message_from_bytes(metadata)
    if parsed["Name"] != "exitlane" or parsed["Version"] != version or parsed["License-Expression"] != "GPL-3.0-only":
        raise ValueError("Package identity/license mismatch")
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        if files.get(prefix + "exitlane/" + name) != (ROOT / name).read_bytes():
            raise ValueError(f"Missing or stale license/notice: {name}")
    for name in guides:
        if files.get(prefix + "exitlane/docs/" + name) != (ROOT / "docs" / name).read_bytes():
            raise ValueError(f"Missing or stale Help guide: {name}")
    for source in (ROOT / "backend/exitlane/static").rglob("*"):
        if source.is_file():
            name = prefix + source.relative_to(ROOT / "backend").as_posix()
            if files.get(name) != source.read_bytes():
                raise ValueError(f"Missing or stale local frontend asset: {name}")
    return {"file": path.name, "version": version, "entries": len(names), "help_guides": len(guides)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    directory = parser.parse_args().directory
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    artifacts = wheels + sdists
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")
    for path in sorted(artifacts):
        print(inspect(path))


if __name__ == "__main__":
    main()
