#!/usr/bin/env python3
"""Read-only image content checks; never inspect mounted appliance state or secrets.

Run in the candidate image (or against an unpacked image root via --root).
The caller separately verifies Docker capabilities, mounts and real readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

FORBIDDEN_DISTRIBUTIONS = frozenset(
    {
        "pytest",
        "ruff",
        "bandit",
        "pip-audit",
        "httpx",
        "requests",
        "urllib3",
        "pip",
        "setuptools",
        "wheel",
        "build",
        "hatchling",
    }
)
REQUIRED_TOOLS = (
    "usr/bin/ip",
    "usr/bin/wg",
    "usr/bin/wg-quick",
    "usr/sbin/nft",
    "usr/bin/getent",
    "usr/bin/ping",
)
REQUIRED_ASSETS = (
    "docs/docker-operations.md",
    "static/index.html",
    "static/js/app.js",
    "static/locales/en.json",
    "providers/pia_ca.pem",
)
FORBIDDEN_NAMES = frozenset(
    {
        ".git",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "tests",
        ".env",
        ".envrc",
    }
)


class ImageContractError(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ImageContractError(code)


def inspect_root(root: Path) -> dict:
    """Return public package/file facts; no application imports or /data reads."""
    root = root.resolve(strict=True)
    site = root / "usr/local/lib/python3.13/site-packages"
    require(site.is_dir(), "image_python_layout_missing")
    package = site / "exitlane"
    require(package.is_dir(), "image_shared_package_missing")
    distributions = {}
    for metadata in site.glob("*.dist-info/METADATA"):
        require(not metadata.is_symlink(), "image_package_metadata_invalid")
        name = version = None
        for line in metadata.read_text(encoding="utf-8").splitlines():
            if line.startswith("Name: "):
                name = line[6:].lower().replace("_", "-")
            elif line.startswith("Version: "):
                version = line[9:]
            if name and version:
                break
        require(bool(name and version), "image_package_metadata_invalid")
        distributions[name] = version
    require("exitlane" in distributions, "image_wheel_metadata_missing")
    require(
        not FORBIDDEN_DISTRIBUTIONS.intersection(distributions),
        "image_development_dependency",
    )
    require(
        all((root / path).is_file() for path in REQUIRED_TOOLS),
        "image_network_tool_missing",
    )
    public_files = {name: package / name for name in REQUIRED_ASSETS}
    public_files.update(
        {
            "license": root / "usr/share/doc/exitlane/LICENSE",
            "ca_bundle": root / "etc/ssl/certs/ca-certificates.crt",
            "timezone": root / "usr/share/zoneinfo/UTC",
        }
    )
    require(
        all(path.is_file() and path.stat().st_size for path in public_files.values())
        and all(
            not path.is_symlink()
            for path in public_files.values()
            if path.is_relative_to(package)
        ),
        "image_public_asset_missing",
    )
    require(
        not any(
            (root / p).exists() for p in ("src", "build", "wheel", "app", "root/.cache")
        ),
        "image_build_tree_present",
    )
    # Only package/build locations are inspected. Never traverse /data or recovery files.
    for path in site.rglob("*"):
        require(not path.is_symlink(), "image_package_symlink")
        require(
            path.name not in FORBIDDEN_NAMES and not path.name.startswith(".env."),
            "image_development_artifact",
        )
        require(
            path.suffix
            not in {
                ".pyc",
                ".db",
                ".key",
                ".sqlite",
                ".sqlite3",
                ".p12",
                ".pfx",
                ".conf",
            }
            and not path.name.endswith((".db-wal", ".db-shm", ".db-journal")),
            "image_state_artifact",
        )
        if path.suffix == ".pem":
            require(
                path
                in {
                    package / "providers/pia_ca.pem",
                    site / "pip/_vendor/certifi/cacert.pem",
                }
                and b"PRIVATE KEY" not in path.read_bytes(),
                "image_unexpected_pem",
            )
    package_hash = hashlib.sha256()
    package_files = sorted(path for path in package.rglob("*") if path.is_file())
    for path in package_files:
        package_hash.update(str(path.relative_to(package)).encode("utf-8") + b"\0")
        package_hash.update(hashlib.sha256(path.read_bytes()).digest())
    return {
        "python": "3.13",
        "package_files": len(package_files),
        "package_sha256": package_hash.hexdigest(),
        "packages": dict(sorted(distributions.items())),
        "public_sha256": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in sorted(public_files.items())
        },
    }


def validate_requirements(text: str) -> dict[str, tuple[str, set[str]]]:
    """Check exact hash-pinned export syntax without resolving or downloading."""
    logical = text.replace("\\\n", " ").splitlines()
    result = {}
    for line in logical:
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([a-z0-9][a-z0-9-]*)==([a-zA-Z0-9.+-]+)(?:\s*;[^\\]+?)?\s+((?:--hash=sha256:[0-9a-f]{64}\s*)+)",
            line.strip(),
        )
        require(match is not None, "image_requirement_not_pinned")
        name, version, hashes = match.groups()
        require(name not in result, "image_requirement_duplicate")
        require(name not in FORBIDDEN_DISTRIBUTIONS, "image_development_dependency")
        result[name] = version, set(re.findall(r"sha256:([0-9a-f]{64})", hashes))
    require(bool(result), "image_requirements_empty")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    arguments = parser.parse_args()
    try:
        print(json.dumps(inspect_root(arguments.root), sort_keys=True))
    except (ImageContractError, OSError) as error:
        print(
            str(error)
            if isinstance(error, ImageContractError)
            else "image_content_unreadable"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
