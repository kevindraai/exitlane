"""Pure public-metadata evidence parsers; collection is not a security disposition."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import PurePosixPath
from urllib.parse import urlsplit


class EvidenceError(ValueError):
    """A stable code, never input data, crosses the artifact boundary."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise EvidenceError(code)


def canonical_bytes(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError):
        _fail("canonical_value_invalid")


def digest_value(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _token(value, pattern=r"[A-Za-z0-9][A-Za-z0-9.+:~_-]*"):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        _fail("public_metadata_invalid")
    return value


def _debian_version(value):
    """Restrict public version evidence before comparison or artifact emission."""
    return (
        isinstance(value, str)
        and len(value) <= 256
        and re.fullmatch(
            r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~\-]*(?:-[A-Za-z0-9+.~]+)?", value
        )
        is not None
        and not re.search(
            r"secret|password|credential|token|bearer|private[_-]?key|canary",
            value,
            re.IGNORECASE,
        )
    )


def parse_os_release(text, debian_version, architecture):
    values = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if "=" not in line:
            _fail("os_release_invalid")
        key, value = line.split("=", 1)
        if key in values:
            _fail("os_release_invalid")
        try:
            words = shlex.split(value)
        except ValueError:
            _fail("os_release_invalid")
        if len(words) != 1:
            _fail("os_release_invalid")
        values[key] = words[0]
    if not all(values.get(k) for k in ("ID", "NAME", "VERSION_ID", "VERSION_CODENAME")):
        _fail("os_identity_missing")
    debian_version, architecture = debian_version.strip(), architecture.strip()
    if (
        values["ID"] != "debian"
        or values["NAME"] != "Debian GNU/Linux"
        or values["VERSION_ID"] != "13"
        or values["VERSION_CODENAME"] != "trixie"
        or architecture != "amd64"
        or not re.fullmatch(r"13(?:\.\d+)*", debian_version)
    ):
        _fail("os_identity_unsupported")
    return {
        "id": values["ID"],
        "name": values["NAME"],
        "version_id": "13",
        "version_codename": "trixie",
        "debian_version": debian_version,
        "architecture": architecture,
    }


def parse_dpkg_inventory(text):
    packages, seen = [], set()
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 7:
            _fail("dpkg_inventory_invalid")
        name, arch, version, status, abbrev, source, source_version = parts
        _token(name)
        if (
            ":" in name
            or ":" in source
            or not re.fullmatch(r"[uihrp][ncHUFWti][ R]", abbrev)
        ):
            _fail("dpkg_inventory_invalid")
        if not re.fullmatch(
            r"(?:unknown|install|hold|deinstall|purge) (?:ok|reinstreq) "
            r"(?:not-installed|config-files|half-installed|unpacked|half-configured|triggers-awaited|triggers-pending|installed)",
            status,
        ):
            _fail("dpkg_inventory_invalid")
        identity = (name, arch)
        if identity in seen:
            _fail("dpkg_inventory_duplicate")
        seen.add(identity)
        state = "other"
        if status in {"install ok installed", "hold ok installed"} and abbrev in {
            "ii ",
            "hi ",
        }:
            state = "installed"
        elif status.endswith(" ok config-files") and abbrev == {
            "unknown": "uc ",
            "install": "ic ",
            "hold": "hc ",
            "deinstall": "rc ",
            "purge": "pc ",
        }.get(status.split()[0]):
            state = "residual"
        for value in (arch, version, source, source_version):
            if value or state != "other":
                _token(value)
        for value in (version, source_version):
            if value and not _debian_version(value):
                _fail("dpkg_version_invalid")
        packages.append(
            {
                "name": name,
                "architecture": arch,
                "version": version,
                "status": status,
                "status_abbrev": abbrev,
                "source_name": source,
                "source_version": source_version,
                "state": state,
            }
        )
    if not packages:
        _fail("dpkg_inventory_empty")
    return {
        "packages": packages,
        "unstable_count": sum(
            p["state"] == "other"
            and p["status"]
            not in {
                "unknown ok not-installed",
                "deinstall ok not-installed",
                "purge ok not-installed",
                "hold ok not-installed",
            }
            for p in packages
        ),
        **{
            f"{state}_count": sum(p["state"] == state for p in packages)
            for state in ("installed", "residual", "other")
        },
    }


def dpkg_projection(inventory):
    try:
        text = "\n".join(
            "\t".join(
                p[k]
                for k in (
                    "name",
                    "architecture",
                    "version",
                    "status",
                    "status_abbrev",
                    "source_name",
                    "source_version",
                )
            )
            for p in inventory["packages"]
        )
        if parse_dpkg_inventory(text) != inventory:
            _fail("dpkg_projection_invalid")
        blocks = []
        for p in inventory["packages"]:
            fields = [f"Package: {p['name']}", f"Status: {p['status']}"]
            for field, key in (
                ("Architecture", "architecture"),
                ("Version", "version"),
            ):
                if p[key]:
                    fields.append(f"{field}: {p[key]}")
            if p["source_name"]:
                source = p["source_name"]
                if p["source_version"]:
                    source += f" ({p['source_version']})"
                fields.append("Source: " + source)
            blocks.append("\n".join(fields) + "\n")
        return ("\n".join(blocks) + "\n").encode()
    except (KeyError, TypeError):
        _fail("dpkg_projection_invalid")


def _keys(value, allowed, required=()):
    if (
        not isinstance(value, dict)
        or set(value) - set(allowed)
        or set(required) - set(value)
    ):
        _fail("report_schema_invalid")


def _strings(value, names):
    for name in names:
        if name in value and not isinstance(value[name], str):
            _fail("report_schema_invalid")


def _string_lists(value, names):
    for name in names:
        if name in value and (
            not isinstance(value[name], list)
            or any(not isinstance(item, str) for item in value[name])
        ):
            _fail("report_schema_invalid")


def _public(value):
    if isinstance(value, str):
        if any(ord(c) < 32 and c not in "\n\r\t" for c in value):
            _fail("report_content_invalid")
        for url in re.findall(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"']+", value):
            try:
                parsed = urlsplit(url)
                if parsed.username is not None or parsed.password is not None:
                    _fail("credential_url_rejected")
            except ValueError:
                _fail("report_content_invalid")
    elif isinstance(value, dict):
        for child in value.values():
            _public(child)
    elif isinstance(value, list):
        for child in value:
            _public(child)
    elif value is not None and not isinstance(value, (int, float, bool)):
        _fail("report_content_invalid")


def _json(raw):
    def pairs(items):
        value = {}
        for key, child in items:
            if key in value:
                _fail("report_duplicate_key")
            value[key] = child
        return value

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: _fail("report_content_invalid"),
        )
    except (ValueError, UnicodeError, TypeError, RecursionError):
        _fail("report_json_invalid")
    try:
        _public(value)
    except RecursionError:
        _fail("report_nesting_invalid")
    return value


PACKAGE_KEYS = {
    "ID",
    "Name",
    "Version",
    "Release",
    "Epoch",
    "Arch",
    "SrcName",
    "SrcVersion",
    "SrcRelease",
    "SrcEpoch",
    "Licenses",
    "Maintainer",
    "Layer",
    "Indirect",
    "DependsOn",
    "Identifier",
    "BuildInfo",
    "Repository",
    "InstalledFiles",
    "AnalyzedBy",
}
VULN_KEYS = {
    "VulnerabilityID",
    "PkgID",
    "PkgName",
    "PkgIdentifier",
    "InstalledVersion",
    "FixedVersion",
    "Status",
    "Layer",
    "SeveritySource",
    "PrimaryURL",
    "DataSource",
    "Title",
    "Description",
    "Severity",
    "CweIDs",
    "CVSS",
    "References",
    "PublishedDate",
    "LastModifiedDate",
    "VendorSeverity",
    "Custom",
    "PkgPath",
    "Fingerprint",
}


def _trivy_package(p):
    _keys(p, PACKAGE_KEYS, ("Name", "Version", "Arch", "SrcName", "SrcVersion"))
    for key in ("Name", "Version", "Arch", "SrcName", "SrcVersion"):
        _token(p[key])
    _strings(
        p,
        {
            "ID",
            "Name",
            "Version",
            "Release",
            "Arch",
            "SrcName",
            "SrcVersion",
            "SrcRelease",
            "Maintainer",
            "AnalyzedBy",
        },
    )
    _string_lists(p, {"Licenses", "DependsOn", "InstalledFiles"})
    for key in ("Epoch", "SrcEpoch"):
        if key in p and (type(p[key]) is not int or p[key] < 0):
            _fail("report_schema_invalid")
    if "Indirect" in p and type(p["Indirect"]) is not bool:
        _fail("report_schema_invalid")
    # These objects are public identifiers, not arbitrary scanner metadata.
    for key, allowed in (
        ("Layer", {"DiffID", "Digest"}),
        ("Identifier", {"PURL", "UID", "BOMRef"}),
        ("BuildInfo", {"ContentSets", "Nvr", "Arch"}),
        ("Repository", {"Class"}),
    ):
        if key in p:
            _keys(p[key], allowed)
            _strings(p[key], allowed - {"ContentSets"})
            _string_lists(p[key], {"ContentSets"})
    version = p["Version"] + ("-" + p["Release"] if p.get("Release") else "")
    if p.get("Epoch"):
        version = str(p["Epoch"]) + ":" + version
    source_version = p["SrcVersion"] + (
        "-" + p["SrcRelease"] if p.get("SrcRelease") else ""
    )
    if p.get("SrcEpoch"):
        source_version = str(p["SrcEpoch"]) + ":" + source_version
    return (p["Name"], p["Arch"], version, p["SrcName"], source_version)


def validate_trivy(raw, inventory, os_identity):
    report = _json(raw)
    _keys(
        report,
        {
            "SchemaVersion",
            "CreatedAt",
            "ArtifactName",
            "ArtifactType",
            "Metadata",
            "Results",
            "Trivy",
            "ReportID",
            "ArtifactID",
        },
        ("SchemaVersion", "ArtifactType", "Metadata", "Results"),
    )
    if report["SchemaVersion"] != 2 or report["ArtifactType"] != "filesystem":
        _fail("trivy_report_type_invalid")
    _strings(
        report, {"CreatedAt", "ArtifactName", "ArtifactType", "ReportID", "ArtifactID"}
    )
    if "Trivy" in report:
        _keys(report["Trivy"], {"Version"}, ("Version",))
        _strings(report["Trivy"], {"Version"})
    _keys(report["Metadata"], {"OS"}, ("OS",))
    _keys(
        report["Metadata"]["OS"],
        {"Family", "Name", "EOSL", "Extended"},
        ("Family", "Name"),
    )
    os_data = report["Metadata"]["OS"]
    _strings(os_data, {"Family", "Name"})
    for key in ("EOSL", "Extended"):
        if key in os_data and type(os_data[key]) is not bool:
            _fail("report_schema_invalid")
    matched_os = (
        os_data["Family"] == os_identity.get("id") == "debian"
        and os_identity.get("version_id") == "13"
        and os_data["Name"]
        in {os_identity.get("version_id"), os_identity.get("debian_version")}
    )
    if not isinstance(report["Results"], list):
        _fail("trivy_results_invalid")
    expected = {
        (
            p["name"],
            p["architecture"],
            p["version"],
            p["source_name"],
            p["source_version"],
        )
        for p in inventory["packages"]
        if p["state"] == "installed"
    }
    residual = {
        (
            p["name"],
            p["architecture"],
            p["version"],
            p["source_name"],
            p["source_version"],
        )
        for p in inventory["packages"]
        if p["state"] == "residual"
    }
    observed, findings, duplicates = set(), [], []
    os_results = 0
    for result in report["Results"]:
        _keys(
            result,
            {"Target", "Class", "Type", "Packages", "Vulnerabilities"},
            ("Target", "Class", "Type", "Packages"),
        )
        if result["Class"] != "os-pkgs" or result["Type"] != "debian":
            _fail("trivy_scope_invalid")
        _strings(result, {"Target", "Class", "Type"})
        os_results += 1
        if not isinstance(result["Packages"], list):
            _fail("trivy_packages_invalid")
        for p in result["Packages"]:
            identity = _trivy_package(p)
            if identity in observed:
                duplicates.append(identity)
            observed.add(identity)
        vuls = result.get("Vulnerabilities")
        if vuls is None:
            vuls = []
        if not isinstance(vuls, list):
            _fail("trivy_vulnerabilities_invalid")
        for v in vuls:
            _keys(
                v,
                VULN_KEYS,
                ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity"),
            )
            for key in ("VulnerabilityID", "PkgName", "InstalledVersion", "Severity"):
                _token(v[key])
            _strings(
                v,
                VULN_KEYS
                - {
                    "Layer",
                    "PkgIdentifier",
                    "DataSource",
                    "CweIDs",
                    "CVSS",
                    "References",
                    "VendorSeverity",
                    "Custom",
                },
            )
            _string_lists(v, {"CweIDs", "References"})
            for key, allowed in (
                ("Layer", {"DiffID", "Digest"}),
                ("PkgIdentifier", {"PURL", "UID", "BOMRef"}),
                ("DataSource", {"ID", "Name", "URL"}),
            ):
                if key in v:
                    _keys(v[key], allowed)
                    _strings(v[key], allowed)
            if "Custom" in v:
                _fail("report_schema_invalid")
            for key in ("CVSS", "VendorSeverity"):
                if key in v and not isinstance(v[key], dict):
                    _fail("report_schema_invalid")
            if "CVSS" in v:
                for vendor, cvss in v["CVSS"].items():
                    _token(vendor)
                    _keys(
                        cvss,
                        {
                            "V2Vector",
                            "V3Vector",
                            "V40Vector",
                            "V2Score",
                            "V3Score",
                            "V40Score",
                        },
                    )
                    _strings(cvss, {"V2Vector", "V3Vector", "V40Vector"})
                    for key in ("V2Score", "V3Score", "V40Score"):
                        if key in cvss and (
                            type(cvss[key]) not in {int, float}
                            or not 0 <= cvss[key] <= 10
                        ):
                            _fail("report_schema_invalid")
            if "VendorSeverity" in v:
                for vendor, severity in v["VendorSeverity"].items():
                    _token(vendor)
                    if type(severity) is not int or not 0 <= severity <= 4:
                        _fail("report_schema_invalid")
            findings.append(v)
    missing = sorted(expected - observed)
    unknown = sorted(observed - expected - residual)
    unbound = [
        i
        for i, v in enumerate(findings)
        if not any(
            p[0] == v["PkgName"] and p[2] == v["InstalledVersion"] for p in observed
        )
    ]
    coverage = {
        "expected_count": len(expected),
        "observed_count": len(observed),
        "missing": missing,
        "unknown": unknown,
        "duplicates": duplicates,
        "unbound_findings": unbound,
        "os_match": matched_os,
        "os_results": os_results,
        "other_count": inventory["other_count"],
        "unstable_count": inventory["unstable_count"],
    }
    complete = (
        matched_os
        and os_results == 1
        and expected
        and not missing
        and not unknown
        and not duplicates
        and not unbound
        and not inventory["unstable_count"]
    )
    return {
        "report": report,
        "findings": findings,
        "coverage": coverage,
        "status": "complete" if complete else "incomplete",
    }


def _normalized(name):
    return re.sub(r"[-_.]+", "-", _token(name)).lower()


def validate_pip_audit(raw, expected, allowed_skips):
    report = _json(raw)
    _keys(report, {"dependencies", "fixes"}, ("dependencies", "fixes"))
    if not isinstance(report["dependencies"], list) or not isinstance(
        report["fixes"], list
    ):
        _fail("pip_audit_report_invalid")
    wanted = {(_normalized(p["name"]), _token(p["version"])) for p in expected}
    if len(wanted) != len(expected):
        _fail("python_inventory_duplicate")
    skips_allowed = {
        _normalized(name): reason for name, reason in allowed_skips.items()
    }
    observed, duplicates, skips, findings = set(), [], [], []
    for dep in report["dependencies"]:
        _keys(dep, {"name", "version", "vulns", "skip_reason"}, ("name",))
        name = _normalized(dep["name"])
        version = dep.get("version")
        if version is None and "skip_reason" in dep:
            versions = [v for n, v in wanted if n == name]
            version = versions[0] if len(versions) == 1 else "unknown"
        _token(version)
        identity = (name, version)
        if identity in observed:
            duplicates.append(identity)
        observed.add(identity)
        if "skip_reason" in dep:
            if not isinstance(dep["skip_reason"], str) or not dep["skip_reason"]:
                _fail("pip_audit_skip_invalid")
            skips.append(
                {
                    "name": name,
                    "version": version,
                    "reason": dep["skip_reason"],
                    "intentional": name == "exitlane" and bool(skips_allowed.get(name)),
                }
            )
        else:
            if not isinstance(dep.get("vulns"), list):
                _fail("pip_audit_vulnerabilities_missing")
            for v in dep["vulns"]:
                _keys(
                    v,
                    {"id", "fix_versions", "aliases", "description"},
                    ("id", "fix_versions"),
                )
                _token(v["id"])
                if not isinstance(v["fix_versions"], list):
                    _fail("pip_audit_vulnerability_invalid")
                _strings(v, {"id", "description"})
                _string_lists(v, {"fix_versions", "aliases"})
                findings.append(
                    {"name": dep["name"], "version": version, "vulnerability": v}
                )
    for fix in report["fixes"]:
        _keys(fix, {"name", "old_version", "new_version", "success"}, ("name",))
        _strings(fix, {"name", "old_version", "new_version"})
        if "success" in fix and type(fix["success"]) is not bool:
            _fail("report_schema_invalid")
    coverage = {
        "expected_count": len(wanted),
        "observed_count": len(observed),
        "missing": sorted(wanted - observed),
        "unknown": sorted(observed - wanted),
        "duplicates": duplicates,
        "skips": skips,
    }
    complete = (
        bool(wanted)
        and not coverage["missing"]
        and not coverage["unknown"]
        and not duplicates
        and all(s["intentional"] for s in skips)
    )
    return {
        "report": report,
        "findings": findings,
        "coverage": coverage,
        "status": "complete" if complete else "incomplete",
    }


def parse_apt_show(text):
    fields = {}
    for line in text.splitlines():
        if line and not line[0].isspace() and ": " in line:
            key, value = line.split(": ", 1)
            if key in fields:
                _fail("apt_show_ambiguous")
            fields[key] = value
    try:
        name, arch, version = (
            _token(fields[k]) for k in ("Package", "Architecture", "Version")
        )
    except KeyError:
        _fail("apt_show_missing")
    source = fields.get("Source", name)
    match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^()\s]+)\))?", source)
    if not match:
        _fail("apt_source_invalid")
    return {
        "name": name,
        "architecture": arch,
        "version": version,
        "source_name": match[1],
        "source_version": _token(match[2] or version),
    }


def parse_apt_policy(text):
    _public(text)
    installed = candidate = None
    versions, current, source = [], None, None
    identity_fields = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("Installed:", "Candidate:")):
            key, value = stripped.split(":", 1)
            if key in identity_fields:
                _fail("apt_policy_ambiguous")
            identity_fields.add(key)
            value = value.strip()
            value = None if value == "(none)" else _token(value)
            if key == "Installed":
                installed = value
            else:
                candidate = value
        elif match := re.fullmatch(r"(?:\*\*\* )?(\S+)\s+(-?\d+)", stripped):
            current = {
                "version": _token(match[1]),
                "priority": int(match[2]),
                "sources": [],
            }
            versions.append(current)
            source = None
        elif match := re.fullmatch(
            r"(-?\d+)\s+(\S+)\s+(\S+)\s+(\S+) Packages", stripped
        ):
            if current is None:
                _fail("apt_policy_invalid")
            uri = match[2]
            if urlsplit(uri).scheme not in {"https", "http", "file"}:
                _fail("apt_policy_uri_invalid")
            suite, _, component = match[3].partition("/")
            source = {
                "uri": uri,
                "suite": suite,
                "component": component,
                "architecture": match[4],
                "origin": None,
                "label": None,
                "codename": None,
            }
            current["sources"].append(source)
        elif stripped.startswith("release ") and source is not None:
            release = dict(
                item.split("=", 1) for item in stripped[8:].split(",") if "=" in item
            )
            source.update(
                origin=release.get("o"),
                label=release.get("l"),
                codename=release.get("n"),
            )
    if not any(
        line.strip().startswith("Installed:") for line in text.splitlines()
    ) or not any(line.strip().startswith("Candidate:") for line in text.splitlines()):
        _fail("apt_policy_missing")
    if candidate is not None and candidate not in {v["version"] for v in versions}:
        _fail("apt_policy_candidate_missing")
    return {"installed": installed, "candidate": candidate, "versions": versions}


def parse_apt_simulation(text, installed, excluded):
    upgrades, additions, removals, held = [], [], [], []
    known = {
        (p["name"], p["architecture"]): p
        for p in installed
        if p.get("state", "installed") == "installed"
    }
    holding = False
    for line in text.splitlines():
        if line.startswith("Inst "):
            m = re.fullmatch(
                r"Inst ([a-z0-9+.-]+)(?::([a-z0-9-]+))?(?: \[([^\]]+)\])? \((\S+) .*?\[([a-z0-9-]+)\]\)",
                line,
            )
            if not m:
                _fail("apt_simulation_invalid")
            name, explicit_arch, old, version, arch = m.groups()
            if explicit_arch and explicit_arch != arch:
                _fail("apt_simulation_invalid")
            prior = known.get((name, arch))
            item = {
                "name": name,
                "architecture": arch,
                "old_version": prior["version"] if prior else None,
                "version": _token(version),
            }
            if old and (prior is None or old != prior["version"]):
                _fail("apt_simulation_inventory_mismatch")
            (upgrades if prior else additions).append(item)
        elif line.startswith("Remv "):
            m = re.fullmatch(
                r"Remv ([a-z0-9+.-]+)(?::([a-z0-9-]+))?(?: \[([^\]]+)\])?(?: .*)?", line
            )
            if not m:
                _fail("apt_simulation_invalid")
            name, arch, version = m.groups()
            matches = [
                p
                for (n, a), p in known.items()
                if n == name and (arch is None or arch == a)
            ]
            if len(matches) != 1 or (version and version != matches[0]["version"]):
                _fail("apt_simulation_inventory_mismatch")
            removals.append(
                {
                    "name": name,
                    "architecture": matches[0]["architecture"],
                    "version": matches[0]["version"],
                }
            )
        elif "kept back:" in line:
            holding = True
        elif holding and line.startswith("  "):
            held.extend(_token(name) for name in line.split())
        else:
            holding = False
    touched = sorted(
        {p["name"] for p in upgrades + additions + removals} & set(excluded)
    )
    return {
        "upgrades": upgrades,
        "additions": additions,
        "removals": removals,
        "held": held,
        "excluded_touched": touched,
        "eligible": not touched and not removals and not held,
    }


def parse_library_maps(text, library):
    _token(library, r"lib[A-Za-z0-9_.+-]+\.so(?:\.[A-Za-z0-9_.+-]+)*")
    selected = []
    for line in text.splitlines():
        if library not in line:
            continue
        m = re.fullmatch(
            r"[0-9a-f]+-[0-9a-f]+\s+[rwxps-]{4}\s+[0-9a-f]+\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)\s+(.+)",
            line,
        )
        if not m:
            _fail("library_maps_invalid")
        device, inode, path = m.groups()
        deleted = path.endswith(" (deleted)")
        path = path.removesuffix(" (deleted)")
        public_path = PurePosixPath(path)
        if public_path.name != library:
            continue
        if (
            not path.startswith(("/usr/lib/", "/lib/"))
            or ".." in public_path.parts
            or any(c.isspace() for c in path)
        ):
            _fail("library_path_invalid")
        item = {"path": path, "deleted": deleted, "device": device, "inode": int(inode)}
        if item not in selected:
            selected.append(item)
    return selected


def classify_findings(findings, inventory, candidates, tracker, compare):
    classified = []
    for finding in findings:
        name, version = finding.get("PkgName"), finding.get("InstalledVersion")
        matches = [
            p
            for p in inventory["packages"]
            if p["name"] == name and p["version"] == version
        ]
        category, fixed, candidate, reason = "unresolved", None, None, None
        if matches and all(p["state"] == "residual" for p in matches):
            category = "residual_not_installed"
        elif (
            len(matches) == 1
            and matches[0]["state"] == "installed"
            and tracker is not None
        ):
            package = matches[0]
            try:
                release = tracker[package["source_name"]][finding["VulnerabilityID"]][
                    "releases"
                ]["trixie"]
            except (KeyError, TypeError):
                release = None
            if isinstance(release, dict):
                fixed = release.get("fixed_version")
                status = release.get("status")
                candidate = candidates.get(f"{name}:{package['architecture']}")
                if candidate is not None and (
                    not isinstance(candidate, dict)
                    or not _debian_version(candidate.get("source_version"))
                    or (
                        "version" in candidate
                        and not _debian_version(candidate["version"])
                    )
                ):
                    candidate = None
                    reason = "candidate_source_version_invalid"
                if not isinstance(status, str) or status not in {
                    "open",
                    "resolved",
                    "undetermined",
                }:
                    fixed = None
                    reason = "primary_status_invalid"
                elif fixed is not None and (
                    fixed not in ("undetermined", "unfixed")
                    and not _debian_version(fixed)
                ):
                    fixed = None
                    reason = "primary_fixed_version_invalid"
                elif fixed == "0":
                    category = "distribution_not_affected"
                elif status in {"open", "undetermined"} or fixed in {
                    "undetermined",
                    "unfixed",
                }:
                    category = (
                        "distribution_unfixed"
                        if status == "open" or fixed == "unfixed"
                        else "unresolved"
                    )
                elif status == "resolved" and isinstance(fixed, str) and fixed:
                    category = (
                        "unresolved" if reason else "primary_fix_not_in_captured_cache"
                    )
                    if candidate:
                        category = "unresolved"
                    if (
                        candidate
                        and candidate.get("source_name") == package["source_name"]
                        and _debian_version(candidate.get("source_version"))
                        and candidate.get("sources_authenticated") is True
                        and candidate.get("eligible") is True
                    ):
                        try:
                            if (
                                compare(candidate["source_version"], "ge", fixed)
                                is True
                            ):
                                category = "supported_fix_in_captured_cache"
                            else:
                                category = "primary_fix_not_in_captured_cache"
                        except (ValueError, RuntimeError, OSError):
                            category = "unresolved"
                    if reason is None:
                        try:
                            if compare(package["source_version"], "ge", fixed) is True:
                                category = "unresolved"
                                reason = "installed_source_at_primary_fix_discrepancy"
                        except (ValueError, RuntimeError, OSError):
                            category = "unresolved"
                            reason = "installed_source_comparison_unavailable"
                # A missing fix is not evidence of a distribution fix or absence.
        classified.append(
            {
                "finding": finding,
                "category": category,
                "tracker_fixed_version": fixed,
                "candidate": candidate,
                "reason": reason,
            }
        )
    return classified


def worksheet(receipt):
    """Render only structural evidence; caller-controlled prose cannot inject rows."""

    def escape(value):
        value = str(value)
        return "".join(
            f"\\u{ord(c):04x}"
            if ord(c) < 32 or ord(c) == 127
            else "\\" + c
            if c in "\\`*_{}[]()<>#+.!|"
            else c
            for c in value
        )

    lines = [
        "Native security collection evidence",
        "",
        "Collection completeness: "
        + escape(receipt.get("collection_status", receipt.get("status", "incomplete"))),
        "Receipt SHA-256: " + digest_value(receipt),
    ]
    for name, cell in sorted(receipt.get("cells", {}).items()):
        if isinstance(cell, dict):
            lines.append(escape(name) + ": " + escape(cell.get("status", "incomplete")))
            if cell.get("reason"):
                lines.append("  reason: " + escape(cell["reason"]))
            data = cell.get("data", {})
            if not isinstance(data, dict):
                data = {}
            for key in ("sha256", "finding_count", "expected_count", "observed_count"):
                if key in cell:
                    lines.append("  " + key + ": " + escape(cell[key]))
                elif isinstance(cell.get("data"), dict) and key in cell["data"]:
                    lines.append("  " + key + ": " + escape(cell["data"][key]))
            # These are known public identity/count fields, never arbitrary cell
            # contents such as raw scanner text, vendor manifests or config.
            fields = {
                "os": (
                    "id",
                    "name",
                    "version_id",
                    "version_codename",
                    "debian_version",
                    "architecture",
                ),
                "dpkg": (
                    "installed_count",
                    "residual_count",
                    "other_count",
                    "unstable_count",
                    "tool_version",
                    "inventory_sha256",
                ),
                "application": (
                    "version",
                    "source_sha",
                    "source_tree",
                    "source_equivalent",
                    "content_equivalent",
                    "build_revision",
                    "historical_build_provenance",
                    "metadata_sha256",
                    "record_sha256",
                    "content_sha256",
                    "package_metadata_sha256",
                    "package_record_sha256",
                    "source_equivalence",
                    "historical_build_commit",
                ),
                "collector": (
                    "version",
                    "commit",
                    "tree",
                    "source_sha",
                    "source_tree",
                    "sha256",
                    "module_sha256",
                    "script_sha256",
                ),
                "python_bootstrap": (
                    "ensurepip_present",
                    "historical_execution",
                    "distribution_count",
                ),
                "python_bundled": ("distribution_count", "parent_count"),
                "apt": (
                    "mode",
                    "projection",
                    "semantics",
                    "cache_sha256",
                    "sources_authenticated",
                    "eligible_count",
                    "excluded_count",
                    "simulation_requested",
                    "applied",
                ),
                "libraries": (
                    "service",
                    "boot_id_sha256",
                    "pid",
                    "start_ticks",
                    "observed_at",
                    "restart_required",
                    "restart_needed",
                    "changed_process_identity",
                    "reboot_observed",
                    "previous_receipt_sha256",
                ),
                "primary_advisories": ("sha256", "observed_at", "source", "available"),
            }.get(name, ())
            for key in fields:
                if key in data and not isinstance(data[key], (dict, list)):
                    lines.append("  " + key + ": " + escape(data[key]))
            if name == "application" and isinstance(data.get("source"), dict):
                for key in ("commit", "tree"):
                    if key in data["source"]:
                        lines.append(
                            "  application source "
                            + key
                            + ": "
                            + escape(data["source"][key])
                        )
            if name in {"collector", "python_bootstrap"}:
                for key in ("module_sha256", "wheel_sha256"):
                    if isinstance(data.get(key), dict):
                        for artifact, sha256 in sorted(data[key].items()):
                            lines.append(
                                "  "
                                + key
                                + " "
                                + escape(artifact)
                                + ": "
                                + escape(sha256)
                            )
            if name.startswith("python_"):
                interpreter = data.get("interpreter")
                if isinstance(interpreter, dict):
                    for key in (
                        "version",
                        "implementation",
                        "executable",
                        "stdlib",
                        "sha256",
                        "owner_package",
                    ):
                        if key in interpreter and not isinstance(
                            interpreter[key], (dict, list)
                        ):
                            lines.append(
                                "  interpreter " + key + ": " + escape(interpreter[key])
                            )
                for key in (
                    "distributions",
                    "packages",
                    "wheels",
                    "gaps",
                    "bundled_gaps",
                ):
                    if isinstance(data.get(key), list):
                        lines.append("  " + key + " count: " + str(len(data[key])))
                bootstrap = data.get("bootstrap")
                if isinstance(bootstrap, dict):
                    for key in ("ensurepip_present", "historical_execution"):
                        if key in bootstrap:
                            lines.append(
                                "  bootstrap " + key + ": " + escape(bootstrap[key])
                            )
                    if isinstance(bootstrap.get("wheels"), list):
                        lines.append(
                            "  bootstrap wheel count: " + str(len(bootstrap["wheels"]))
                        )
            if name == "trivy" or name.startswith("audit_"):
                for key in (
                    "tool_version",
                    "tool_sha256",
                    "raw_sha256",
                    "returncode",
                    "requirements_sha256",
                    "scan_scope",
                ):
                    if key in data:
                        lines.append("  " + key + ": " + escape(data[key]))
                database = data.get("database")
                if isinstance(database, dict):
                    for key in (
                        "Version",
                        "UpdatedAt",
                        "NextUpdate",
                        "DownloadedAt",
                        "sha256",
                        "metadata_sha256",
                    ):
                        if key in database:
                            lines.append(
                                "  database " + key + ": " + escape(database[key])
                            )
                coverage = data.get("coverage")
                if isinstance(coverage, dict):
                    for key in (
                        "expected_count",
                        "observed_count",
                        "os_match",
                        "other_count",
                        "unstable_count",
                    ):
                        if key in coverage:
                            lines.append(
                                "  coverage " + key + ": " + escape(coverage[key])
                            )
                    for key in (
                        "missing",
                        "unknown",
                        "duplicates",
                        "unbound_findings",
                        "skips",
                    ):
                        if isinstance(coverage.get(key), list):
                            lines.append(
                                "  coverage "
                                + key
                                + " count: "
                                + str(len(coverage[key]))
                            )
                if "findings" in data:
                    lines.append(
                        "  finding count: "
                        + (
                            str(len(data["findings"]))
                            if isinstance(data["findings"], list)
                            else "unavailable"
                        )
                    )
            if name == "apt":
                lines.append(
                    "  APT result is a captured-cache projection; no maintenance was applied or post-update state proved."
                )
                for key in ("candidates", "excluded"):
                    if isinstance(data.get(key), (dict, list)):
                        lines.append("  " + key + " count: " + str(len(data[key])))
                simulation = data.get("simulation")
                if isinstance(simulation, dict):
                    for key in (
                        "upgrades",
                        "additions",
                        "removals",
                        "held",
                        "excluded_touched",
                    ):
                        if isinstance(simulation.get(key), list):
                            lines.append(
                                "  simulation "
                                + key
                                + " count: "
                                + str(len(simulation[key]))
                            )
                    if "eligible" in simulation:
                        lines.append(
                            "  simulation eligible: " + escape(simulation["eligible"])
                        )
            if name == "libraries":
                for key in ("observations", "services", "mappings"):
                    if isinstance(data.get(key), list):
                        lines.append("  " + key + " count: " + str(len(data[key])))
                for mapping in data.get("mappings", []):
                    if isinstance(mapping, dict):
                        for key in (
                            "path",
                            "deleted",
                            "device",
                            "inode",
                            "current_device",
                            "current_inode",
                            "current_exists",
                        ):
                            if key in mapping:
                                lines.append(
                                    "  mapping " + key + ": " + escape(mapping[key])
                                )
                if not data.get("mappings"):
                    lines.append(
                        "  Missing selected mappings do not prove cleared libraries."
                    )
                if data.get("restart_required"):
                    lines.append(
                        "  Stale library mappings require separately observed restart qualification."
                    )
                maintenance = data.get("maintenance_evidence")
                if isinstance(maintenance, dict):
                    for key in ("sha256", "trust"):
                        if key in maintenance:
                            lines.append(
                                "  maintenance evidence "
                                + key
                                + ": "
                                + escape(maintenance[key])
                            )
    categories = {}
    for item in receipt.get("applicability", []):
        if isinstance(item, dict):
            category = item.get("category", "unresolved")
            categories[category] = categories.get(category, 0) + 1
    for category, count in sorted(categories.items()):
        lines.append("Applicability " + escape(category) + ": " + str(count))
    for filename, artifact in sorted(receipt.get("artifacts", {}).items()):
        lines.append(
            "Artifact "
            + escape(filename)
            + ": "
            + escape(artifact.get("sha256", "unavailable"))
        )
    for layer, findings in sorted(receipt.get("findings", {}).items()):
        if isinstance(findings, list):
            lines.append("Findings " + escape(layer) + ": " + str(len(findings)))
        elif isinstance(findings, dict):
            for sublayer, values in sorted(findings.items()):
                lines.append(
                    "Findings "
                    + escape(layer)
                    + "/"
                    + escape(sublayer)
                    + ": "
                    + (str(len(values)) if isinstance(values, list) else "unavailable")
                )
        else:
            lines.append("Findings " + escape(layer) + ": unavailable")
    lines.extend(
        [
            "",
            "Collection evidence requires separate applicability, maintenance and release review.",
        ]
    )
    return "\n".join(lines) + "\n"
