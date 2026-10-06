"""Offline APT evidence from a bounded current-cache projection.

Never loads the host's APT configuration or executes package maintenance. This is
intentionally not an attestation of the configured host transaction or archive trust.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from native_security_evidence import (
    EvidenceError,
    digest_value,
    parse_apt_policy,
    parse_apt_show,
    parse_apt_simulation,
)

_MAX_BYTES = 512 * 1024 * 1024
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*")
_ARCH = re.compile(r"[a-z0-9][a-z0-9-]*")
_VERSION = re.compile(r"[A-Za-z0-9.+:~_-]+")
_INDEX = re.compile(
    r"(?:deb\.debian\.org_debian|security\.debian\.org_debian-security|"
    r"deb\.debian\.org_debian-security)_dists_"
    r"trixie(?:-updates|-security)?_(?:InRelease|Release(?:\.gpg)?|"
    r"(?:main|contrib|non-free|non-free-firmware)_binary-(?:amd64|all)_Packages"
    r"(?:\.(?:lz4|gz|xz))?)"
)
_RELATIONS = {
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Conflicts",
    "Breaks",
    "Replaces",
    "Provides",
    "Multi-Arch",
    "Essential",
    "Priority",
    "Section",
    "Installed-Size",
}


def _fail(code):
    raise EvidenceError(code)


def _read(path):
    # Refuse symlinks rather than following public-path aliases into private data.
    if (
        path.is_symlink()
        or any(p.is_symlink() for p in path.parents)
        or not path.is_file()
        or path.stat().st_nlink != 1
    ):
        _fail("apt_snapshot_input_invalid")
    if path.stat().st_size > _MAX_BYTES:
        _fail("apt_snapshot_too_large")
    raw = path.read_bytes()
    if len(raw) > _MAX_BYTES:
        _fail("apt_snapshot_too_large")
    return raw


def _inputs(root):
    folder = root / "var/lib/apt/lists"
    if folder.is_symlink() or not folder.is_dir():
        _fail("apt_cache_missing")
    files = [root / "var/lib/dpkg/status"]
    files.extend(sorted(p for p in folder.iterdir() if _INDEX.fullmatch(p.name)))
    if len(files) > 128:
        _fail("apt_snapshot_too_many_files")
    if not any("_Packages" in p.name for p in files):
        _fail("apt_cache_missing")
    keyring = root / "usr/share/keyrings/debian-archive-keyring.gpg"
    if keyring.exists():
        files.append(keyring)
    return files


def _snapshot(root, reader=None):
    files = _inputs(root)
    captured = {}
    for path in files:
        actual = path
        if (
            path == root / "usr/share/keyrings/debian-archive-keyring.gpg"
            and path.is_symlink()
        ):
            actual = path.resolve(strict=True)
            if actual != root / "usr/share/keyrings/debian-archive-keyring.pgp":
                _fail("apt_snapshot_input_invalid")
        if actual.is_symlink() or any(p.is_symlink() for p in actual.parents):
            _fail("apt_snapshot_input_invalid")
        captured[path] = reader(actual, _MAX_BYTES) if reader else _read(actual)
    if sum(len(v) for v in captured.values()) > _MAX_BYTES:
        _fail("apt_snapshot_too_large")
    identities = {
        str(p.relative_to(root)): hashlib.sha256(raw).hexdigest()
        for p, raw in captured.items()
    }
    return captured, digest_value(identities)


def _status(raw, inventory):
    """Retain only resolver fields, bound to the already observed dpkg inventory."""
    wanted = {(p["name"], p["architecture"]): p for p in inventory["packages"]}
    seen, output = set(), []
    for paragraph in raw.decode("utf-8", errors="strict").split("\n\n"):
        if not paragraph.strip():
            continue
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")):
                # dpkg relationship fields are single lines; descriptive prose is omitted.
                continue
            if ":" not in line:
                _fail("apt_dpkg_status_invalid")
            key, value = line.split(":", 1)
            value = value.lstrip(" ")
            if key in fields:
                _fail("apt_dpkg_status_invalid")
            fields[key] = value
        try:
            identity = (fields["Package"], fields["Architecture"])
            observed = parse_apt_show("\n".join(f"{k}: {v}" for k, v in fields.items()))
            expected = wanted[identity]
        except KeyError:
            _fail("apt_inventory_changed")
        if (
            identity in seen
            or any(
                observed[k] != expected[v]
                for k, v in (
                    ("version", "version"),
                    ("source_name", "source_name"),
                    ("source_version", "source_version"),
                )
            )
            or fields.get("Status") != expected["status"]
        ):
            _fail("apt_inventory_changed")
        seen.add(identity)
        selected = {
            k: v
            for k, v in fields.items()
            if k in _RELATIONS
            or k in {"Package", "Architecture", "Version", "Source", "Status"}
        }
        for value in selected.values():
            if any(ord(c) < 32 or ord(c) > 126 for c in value) or len(value) > 65536:
                _fail("apt_dpkg_status_invalid")
        output.append("\n".join(f"{k}: {v}" for k, v in selected.items()))
    if seen != set(wanted):
        _fail("apt_inventory_changed")
    return ("\n\n".join(output) + "\n").encode()


def _private_config(work, captured, root, inventory):
    for name in (
        "lists/partial",
        "cache/archives/partial",
        "log",
        "parts",
        "preferences",
        "methods",
    ):
        (work / name).mkdir(parents=True, exist_ok=True, mode=0o700)
    # APT asks methods for capabilities even during simulation. This fixed local
    # stub advertises the protocol and refuses every acquisition without networking.
    method_program = (
        "#!/usr/bin/python3 -S\nimport sys\n"
        "print('100 Capabilities\\nVersion: 1.0\\nSingle-Instance: true\\nLocal-Only: true\\n', flush=True)\n"
        "for line in sys.stdin:\n"
        "    if line.startswith('600 '):\n"
        "        print('400 URI Failure\\nMessage: offline projection refuses acquisition\\n', flush=True)\n"
    )
    for method in ("http", "https", "file", "store", "copy"):
        method_path = work / "methods" / method
        method_path.write_text(method_program)
        method_path.chmod(0o700)
    status = work / "status"
    status.write_bytes(_status(captured[root / "var/lib/dpkg/status"], inventory))
    for path, raw in captured.items():
        if path.parent == root / "var/lib/apt/lists":
            (work / "lists" / path.name).write_bytes(raw)
    (work / "extended_states").write_text("")
    (work / "sources.list").write_text(
        "deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware\n"
        "deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware\n"
        "deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware\n"
        "deb http://deb.debian.org/debian-security trixie-security main contrib non-free non-free-firmware\n"
    )
    # APT_CONFIG is loaded before Dir::Etc main/parts. No host hooks ever load.
    settings = {
        "Dir": str(work),
        "Dir::Etc": str(work),
        "Dir::Etc::main": "-",
        "Dir::Etc::parts": str(work / "parts"),
        "Dir::Etc::sourcelist": str(work / "sources.list"),
        "Dir::Etc::sourceparts": str(work / "parts"),
        "Dir::Etc::preferences": str(work / "empty-preferences"),
        "Dir::Etc::preferencesparts": str(work / "preferences"),
        "Dir::State": str(work),
        "Dir::State::status": str(status),
        "Dir::State::lists": str(work / "lists"),
        "Dir::State::extended_states": str(work / "extended_states"),
        "Dir::Cache": str(work / "cache"),
        "Dir::Cache::pkgcache": "",
        "Dir::Cache::srcpkgcache": "",
        "Dir::Log": str(work / "log"),
        "Dir::Bin::Methods": str(work / "methods"),
        "Dir::Bin::dpkg": "/bin/false",
        "APT::Architecture": "amd64",
        "APT::Architectures::": "amd64",
        "Debug::NoLocking": "true",
        "APT::Get::Download": "false",
        "Acquire::Languages": "none",
    }
    cfg = work / "apt.conf"
    if any(
        '"' in value or "\\" in value or "\n" in value for value in settings.values()
    ):
        _fail("apt_private_path_invalid")
    cfg.write_text(
        "\n".join(f'{key} "{value}";' for key, value in settings.items()) + "\n"
        "#clear DPkg::Pre-Invoke;\n#clear DPkg::Post-Invoke;\n"
        "#clear DPkg::Pre-Install-Pkgs;\n#clear APT::Update::Pre-Invoke;\n"
        "#clear APT::Update::Post-Invoke;\n#clear APT::Update::Post-Invoke-Success;\n"
    )
    return {"APT_CONFIG": str(cfg)}


def _authenticate(host, work, captured, env):
    """Verify the Debian keyring signature and signed uncompressed index hashes."""
    keyring_path = host.root / "usr/share/keyrings/debian-archive-keyring.gpg"
    if keyring_path not in captured:
        return {}, {"status": "incomplete", "reason": "debian_archive_keyring_missing"}
    keyring = work / "debian-archive-keyring.gpg"
    keyring.write_bytes(captured[keyring_path])
    indexes, releases = {}, []
    for path, raw in captured.items():
        if not path.name.endswith("_InRelease"):
            continue
        local = work / "lists" / path.name
        result = host.run(
            ["gpgv", "--keyring", str(keyring), str(local)], env=env, timeout=60
        )
        entry = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "signature_verified": result.returncode == 0,
        }
        releases.append(entry)
        if result.returncode != 0:
            continue
        try:
            text = raw.decode("utf-8")
            if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\n"):
                continue
            content = text.split("\n\n", 1)[1].split(
                "-----BEGIN PGP SIGNATURE-----", 1
            )[0]
            fields = {}
            hashes = {}
            in_hashes = False
            for line in content.splitlines():
                if line == "SHA256:":
                    in_hashes = True
                elif in_hashes and line.startswith(" "):
                    match = re.fullmatch(
                        r" ([a-f0-9]{64})\s+(\d+)\s+((?:main|contrib|non-free|non-free-firmware)/binary-(?:amd64|all)/Packages)",
                        line,
                    )
                    if match:
                        if match[3] in hashes:
                            _fail("apt_release_hash_duplicate")
                        hashes[match[3]] = (match[1], int(match[2]))
                else:
                    in_hashes = False
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        if key in {
                            "Origin",
                            "Label",
                            "Codename",
                            "Suite",
                            "Date",
                            "Valid-Until",
                        }:
                            if key in fields:
                                _fail("apt_release_metadata_duplicate")
                            fields[key] = value
            codename = fields.get("Codename")
            suite_match = re.search(
                r"_dists_(trixie(?:-updates|-security)?)_InRelease$", path.name
            )
            if (
                fields.get("Origin") != "Debian"
                or not suite_match
                or codename != suite_match[1]
            ):
                continue
            date = parsedate_to_datetime(fields["Date"])
            if date.tzinfo is None or date > datetime.now(timezone.utc):
                continue
            expires = fields.get("Valid-Until")
            if expires:
                expiry = parsedate_to_datetime(expires)
                if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                    continue
            entry.update(
                codename=codename,
                date=date.isoformat(),
                valid_until=expiry.isoformat() if expires else None,
                keyring_sha256=hashlib.sha256(captured[keyring_path]).hexdigest(),
            )
            prefix = path.name.removesuffix("InRelease")
            for index_path in captured:
                if (
                    not index_path.name.startswith(prefix)
                    or "_Packages" not in index_path.name
                ):
                    continue
                suffix = index_path.name[len(prefix) :].split("_Packages", 1)[0]
                match = re.fullmatch(
                    r"(main|contrib|non-free|non-free-firmware)_binary-(amd64|all)",
                    suffix,
                )
                if not match:
                    continue
                expected = hashes.get(f"{match[1]}/binary-{match[2]}/Packages")
                if expected is None:
                    continue
                decoded = host.run(
                    [
                        "/usr/lib/apt/apt-helper",
                        "cat-file",
                        str(work / "lists" / index_path.name),
                    ],
                    env=env,
                    timeout=60,
                    limit=128 * 1024 * 1024,
                )
                payload = decoded.stdout
                if decoded.returncode != 0 or len(payload) > 128 * 1024 * 1024:
                    continue
                if (hashlib.sha256(payload).hexdigest(), len(payload)) != expected:
                    continue
                for paragraph in payload.decode("utf-8").split("\n\n"):
                    if paragraph.strip():
                        package = parse_apt_show(paragraph)
                        identity = (
                            package["name"],
                            package["architecture"],
                            package["version"],
                            package["source_name"],
                            package["source_version"],
                        )
                        indexes.setdefault(identity, set()).add(codename)
        except (UnicodeError, ValueError, KeyError, IndexError, OverflowError):
            continue
    return indexes, {
        "status": "complete" if indexes else "incomplete",
        "releases": releases,
        "reason": "cached_release_index_chain_verified"
        if indexes
        else "cached_release_index_chain_unverified",
    }


def _run(host, argv, env):
    result = host.run(argv, env=env, timeout=60)
    if result.returncode != 0:
        _fail("apt_command_failed")
    if len(result.stdout) > 32 * 1024 * 1024:
        _fail("apt_output_too_large")
    return result.stdout.decode("utf-8", errors="strict")


def _eligible(sources, architecture):
    return bool(sources) and all(
        source["uri"]
        in {
            "http://deb.debian.org/debian",
            "http://security.debian.org/debian-security",
            "http://deb.debian.org/debian-security",
        }
        and source["suite"] in {"trixie", "trixie-updates", "trixie-security"}
        and source["component"] in {"main", "contrib", "non-free", "non-free-firmware"}
        and source["architecture"] in {architecture, "all"}
        for source in sources
    )


def _bind_simulation(host, result, candidates, authenticated, env):
    """Bind every chosen Inst identity, including new dependencies, to signed indexes."""
    bound = True
    for change in result["upgrades"] + result["additions"]:
        name, architecture, version = (
            change["name"],
            change["architecture"],
            change["version"],
        )
        change.update(
            source_name=None,
            source_version=None,
            sources_authenticated=False,
            authenticated_suites=[],
        )
        try:
            if (
                not _PACKAGE.fullmatch(name)
                or not _ARCH.fullmatch(architecture)
                or not _VERSION.fullmatch(version)
            ):
                _fail("apt_simulation_identity_invalid")
            candidate = candidates.get(f"{name}:{architecture}")
            if candidate and candidate["candidate_version"] == version:
                source_name, source_version = (
                    candidate["source_name"],
                    candidate["source_version"],
                )
                identity = (
                    name,
                    candidate["candidate_architecture"],
                    version,
                    source_name,
                    source_version,
                )
                suites = (
                    authenticated.get(identity, set())
                    if candidate["sources_authenticated"]
                    else set()
                )
            else:
                shown = parse_apt_show(
                    _run(
                        host,
                        [
                            "apt-cache",
                            "show",
                            "--no-all-versions",
                            f"{name}:{architecture}={version}",
                        ],
                        env,
                    )
                )
                if (
                    shown["name"] != name
                    or shown["architecture"] not in {architecture, "all"}
                    or shown["version"] != version
                ):
                    _fail("apt_simulation_metadata_mismatch")
                source_name, source_version = (
                    shown["source_name"],
                    shown["source_version"],
                )
                identity = (
                    name,
                    shown["architecture"],
                    version,
                    source_name,
                    source_version,
                )
                suites = authenticated.get(identity, set())
                policy = parse_apt_policy(
                    _run(host, ["apt-cache", "policy", f"{name}:{architecture}"], env)
                )
                selected_sources = [
                    source
                    for row in policy["versions"]
                    if row["version"] == version
                    for source in row["sources"]
                ]
                if not _eligible(selected_sources, architecture) or not all(
                    source["suite"] in suites for source in selected_sources
                ):
                    suites = set()
            change.update(
                source_name=source_name,
                source_version=source_version,
                sources_authenticated=bool(suites),
                authenticated_suites=sorted(suites),
            )
            if not suites:
                bound = False
        except (EvidenceError, OSError, UnicodeError, KeyError, TypeError, ValueError):
            bound = False
    result["sources_authenticated"] = bound
    result["eligible"] = result["eligible"] and bound
    if not bound:
        result.update(status="incomplete", reason="apt_simulation_source_unverified")


def collect_apt(
    host,
    inventory: dict,
    *,
    simulate: bool = False,
    exclusions: tuple = ("nordvpn", "nordvpn-keyring"),
) -> dict:
    """Collect public candidates and, optionally, an offline simulated transaction."""
    data = {
        "mode": "controlled_cache_projection",
        "candidates": {},
        "sources_authenticated": False,
        "trust": "unverified_cached_archive_metadata",
        "policy": "debian_trixie_projection_without_host_sources_preferences_or_hooks",
        "limitations": [
            "configured_host_sources_and_pinning_not_observed",
            "controlled_projection_is_not_configured_host_transaction",
            "provider_packages_excluded_from_requested_transactions_and_authentication_scope",
            "collection_is_not_maintenance_or_release_approval",
        ],
        "authentication_scope": "installed_packages_except_explicit_exclusions",
        "exclusions": list(exclusions),
        "simulation": {"status": "skipped", "reason": "not_requested"},
    }
    try:
        for p in inventory["packages"]:
            if (
                not _PACKAGE.fullmatch(p["name"])
                or not _ARCH.fullmatch(p["architecture"])
                or not _VERSION.fullmatch(p["version"])
            ):
                _fail("apt_inventory_invalid")
        if any(not _PACKAGE.fullmatch(p) for p in exclusions):
            _fail("apt_exclusions_invalid")
        captured, before = _snapshot(host.root, getattr(host, "read_public", None))
        data["snapshot"] = {"before_sha256": before, "file_count": len(captured)}
        requests, held, excluded = [], [], []
        with tempfile.TemporaryDirectory(prefix="apt-", dir=host.work) as temporary:
            env = _private_config(Path(temporary), captured, host.root, inventory)
            authenticated, trust = _authenticate(host, Path(temporary), captured, env)
            data["archive_authentication"] = trust
            for package in inventory["packages"]:
                if package["state"] != "installed":
                    continue
                name, architecture = package["name"], package["architecture"]
                key = f"{name}:{architecture}"
                policy = parse_apt_policy(_run(host, ["apt-cache", "policy", key], env))
                version = policy["candidate"]
                if policy["installed"] != package["version"]:
                    _fail("apt_inventory_changed")
                sources = [
                    s
                    for v in policy["versions"]
                    if v["version"] == version
                    for s in v["sources"]
                ]
                candidate = {
                    "candidate_version": version,
                    "candidate_architecture": None,
                    "source_name": None,
                    "source_version": None,
                    "eligible": False,
                    "sources_authenticated": False,
                    "sources": sources,
                }
                if version is not None:
                    if not _VERSION.fullmatch(version):
                        _fail("apt_candidate_invalid")
                    shown = parse_apt_show(
                        _run(
                            host,
                            [
                                "apt-cache",
                                "show",
                                "--no-all-versions",
                                f"{key}={version}",
                            ],
                            env,
                        )
                    )
                    if (
                        shown["name"] != name
                        or shown["architecture"] not in {architecture, "all"}
                        or shown["version"] != version
                    ):
                        _fail("apt_candidate_metadata_mismatch")
                    candidate.update(
                        candidate_architecture=shown["architecture"],
                        source_name=shown["source_name"],
                        source_version=shown["source_version"],
                        eligible=_eligible(sources, architecture)
                        and name not in exclusions
                        and not package["status"].startswith("hold "),
                    )
                    identity = (
                        shown["name"],
                        shown["architecture"],
                        shown["version"],
                        shown["source_name"],
                        shown["source_version"],
                    )
                    verified_suites = authenticated.get(identity, set())
                    candidate["sources_authenticated"] = bool(sources) and all(
                        source["suite"] in verified_suites for source in sources
                    )
                data["candidates"][key] = candidate
                if name in exclusions:
                    excluded.append(key)
                elif package["status"].startswith("hold "):
                    held.append(key)
                elif candidate["eligible"] and version != package["version"]:
                    requests.append(f"{key}={version}")
            if simulate:
                result = (
                    parse_apt_simulation(
                        _run(
                            host,
                            [
                                "apt-get",
                                "--simulate",
                                "--no-download",
                                "install",
                                *requests,
                            ],
                            env,
                        ),
                        inventory["packages"],
                        list(exclusions),
                    )
                    if requests
                    else {
                        "upgrades": [],
                        "additions": [],
                        "removals": [],
                        "held": [],
                        "excluded_touched": [],
                        "eligible": True,
                    }
                )
                touched = {
                    p["name"]
                    for p in result["upgrades"]
                    + result["additions"]
                    + result["removals"]
                }
                held_touched = sorted(touched & {p.split(":", 1)[0] for p in held})
                result["held_touched"] = held_touched
                result["eligible"] = result["eligible"] and not held_touched
                result.update(
                    requests=requests,
                    held_inventory=held,
                    excluded_requests=excluded,
                    status="complete",
                    mode="controlled_cache_projection",
                    sources_authenticated=False,
                )
                _bind_simulation(host, result, data["candidates"], authenticated, env)
                # This outcome is a projected resolver result, never an approved maintenance action.
                data["simulation"] = result
        _, after = _snapshot(host.root, getattr(host, "read_public", None))
        data["snapshot"].update(after_sha256=after, consistent=before == after)
        if before != after:
            _fail("apt_snapshot_changed")
        required_candidates = [
            candidate
            for identity, candidate in data["candidates"].items()
            if identity.split(":", 1)[0] not in exclusions
        ]
        data["sources_authenticated"] = bool(required_candidates) and all(
            candidate["sources_authenticated"] for candidate in required_candidates
        )
        if authenticated:
            data["trust"] = "candidate_specific_cached_release_index_chain"
        return {
            "status": "complete"
            if data["sources_authenticated"]
            and data["simulation"]["status"] in {"complete", "skipped"}
            else "incomplete",
            "reason": data["simulation"].get("reason")
            if data["simulation"]["status"] == "incomplete"
            else None
            if data["sources_authenticated"]
            else "apt_policy_and_archive_trust_unverified",
            "data": data,
        }
    except (
        EvidenceError,
        OSError,
        UnicodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        reason = exc.code if isinstance(exc, EvidenceError) else "apt_collection_failed"
        for candidate in data["candidates"].values():
            candidate["sources_authenticated"] = False
        if simulate:
            data["simulation"].update(status="incomplete", reason=reason)
        return {"status": "incomplete", "reason": reason, "data": data}
