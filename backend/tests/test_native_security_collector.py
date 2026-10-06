"""Read-only collector composition and negative controls, using public synthetic inputs."""

import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/qualification"))
import native_security as collector
from native_security_host import CommandResult

DPKG = b"libc6\tamd64\t2.41-1\tinstall ok installed\tii \tglibc\t2.41-1\n"
OS = b'ID=debian\nNAME="Debian GNU/Linux"\nVERSION_ID=13\nVERSION_CODENAME=trixie\n'
CANARY = "PRIVATE_PROVIDER_PASSWORD_CANARY"


class Host:
    def __init__(self, tmp_path):
        self.root = tmp_path / "root"
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.files = {
            "etc/os-release": OS,
            "etc/debian_version": b"13.1",
            "etc/machine-id": b"a" * 32,
        }
        self.dpkg = DPKG
        self.final_dpkg = None
        self.queries = 0
        self.scans = 0
        self.audits = []
        self.fail_query = False
        self.scan_status = "complete"
        self.scan_findings = []
        self.probe_extra = False
        self.bundles = False
        self.lib = {
            "status": "complete",
            "data": {
                "service": "exitlane.service",
                "library": "libssl.so.3",
                "boot_id_sha256": "b" * 64,
                "start_ticks": 200,
                "pid": 12,
                "restart_required": False,
                "mappings": [],
            },
        }

    def read_public(self, path, limit=64 * 1024 * 1024):
        if path.is_relative_to(self.root):
            return self.files[path.relative_to(self.root).as_posix()]
        return path.read_bytes()

    def run(self, argv, **kwargs):
        if "--print-architecture" in argv:
            raw = b"amd64"
        elif "--version" in argv:
            raw = (
                b"Debian dpkg-query package management program query tool version 1.22.21 (amd64)."
            )
        elif "--show" in argv:
            self.queries += 1
            if self.fail_query:
                return CommandResult(1, CANARY.encode(), "0" * 64)
            raw = self.final_dpkg if self.queries > 1 and self.final_dpkg is not None else self.dpkg
        else:
            raise AssertionError(argv)
        return CommandResult(0, raw, "0" * 64)

    def python(self, executable, mode, prefix):
        data = {
            "interpreter": {
                "version": "3.13.5",
                "implementation": "cpython",
                "executable": "/usr/bin/python3",
                "stdlib": "/usr/lib/python3.13",
                "binary_sha256": "1" * 64,
            },
            "distributions": [{"name": "sample", "version": "1.0"}],
            "application": {"version": "1.0.0"},
            "bootstrap": {
                "ensurepip_present": False,
                "wheels": [],
                "historical_execution": "unresolved_no_contemporaneous_evidence",
            },
            "bundled": [],
            "bundled_gaps": [],
        }
        if self.probe_extra:
            data["environment"] = CANARY
        if self.bundles:
            manifest = "urllib3==" + ("1.0" if mode == "os" else "2.0")
            data["bundled"] = [
                {
                    "parent": "pip",
                    "sha256": hashlib.sha256(manifest.encode()).hexdigest(),
                    "manifest": manifest,
                }
            ]
        return data

    def audit(self, executable, packages, **kwargs):
        self.audits.append((copy.deepcopy(packages), kwargs["layer"]))
        return {
            "status": "complete",
            "data": {"findings": [], "coverage": {}},
        }, b'{"dependencies":[],"fixes":[]}'

    def trivy(self, *args):
        self.scans += 1
        return {
            "status": self.scan_status,
            "data": {"findings": self.scan_findings},
        }, b'{"SchemaVersion":2}'

    def libraries(self, service, library):
        return copy.deepcopy(self.lib)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as safe_root:
        output = Path(safe_root) / "output"
        output.mkdir(mode=0o700)
        host = Host(tmp_path)
        options = collector.arguments(
            ["--output", str(output), "--application-source", str(tmp_path / "source")]
        )
        identity = {"version": "1.0.0", "content_sha256": "2" * 64, "source": {"commit": "3" * 40}}
        monkeypatch.setattr(
            collector, "application_identity", lambda *args: copy.deepcopy(identity)
        )
        monkeypatch.setattr(
            collector, "collector_identity", lambda *args: {"version": "1", "commit": "4" * 40}
        )
        monkeypatch.setattr(
            collector,
            "collect_apt",
            lambda *args, **kwargs: {
                "status": "complete",
                "data": {"candidates": {}, "policy_scope": "controlled_cache_projection"},
            },
        )
        yield options, host


def test_complete_means_collection_not_secure_and_hashes_retained_inputs(setup):
    options, host = setup
    receipt = collector.collect(options, host)
    assert receipt["collection_status"] == "complete"
    assert receipt["release_decision"] == "maintainer_review_required"
    assert (
        receipt["cells"]["os"]["data"]["machine_id_sha256"] == hashlib.sha256(b"a" * 32).hexdigest()
    )
    assert receipt["cells"]["target_consistency"]["status"] == "complete"
    for name, identity in receipt["artifacts"].items():
        assert (
            hashlib.sha256((options.output / name).read_bytes()).hexdigest() == identity["sha256"]
        )
        assert (options.output / name).stat().st_mode & 0o777 == 0o600
    assert host.scans == 1
    assert {layer for _, layer in host.audits} == {"os", "venv", "bootstrap"}


@pytest.mark.parametrize("kind", ["missing", "unsupported", "incomplete"])
def test_os_failure_cannot_be_clean_even_when_scanner_would_exit_zero(setup, kind):
    options, host = setup
    if kind == "missing":
        del host.files["etc/os-release"]
    else:
        host.files["etc/os-release"] = (
            b"ID=ubuntu" if kind == "unsupported" else b"ID=debian\nVERSION_ID=13"
        )
    receipt = collector.collect(options, host)
    assert receipt["collection_status"] != "complete"
    assert host.scans == 0
    assert receipt["findings"]["native"] is None


@pytest.mark.parametrize("kind", ["empty", "command_failure", "changed"])
def test_native_inventory_failure_is_explicit_and_never_zero_findings(setup, kind):
    options, host = setup
    if kind == "empty":
        host.dpkg = b""
    elif kind == "command_failure":
        host.fail_query = True
    else:
        host.final_dpkg = DPKG.replace(b"2.41-1", b"2.41-2")
    receipt = collector.collect(options, host)
    assert receipt["collection_status"] != "complete"
    assert CANARY not in json.dumps(receipt)
    if kind == "changed":
        assert (
            receipt["cells"]["target_consistency"]["reason"]
            == "native_inventory_changed_during_collection"
        )
    else:
        assert receipt["findings"]["native"] is None


def test_nonallowlisted_python_environment_never_retained(setup, monkeypatch):
    options, host = setup
    monkeypatch.setenv("PROVIDER_PASSWORD", CANARY)
    host.probe_extra = True
    receipt = collector.collect(options, host)
    assert receipt["collection_status"] != "complete"
    assert CANARY not in json.dumps(receipt)
    assert all(
        CANARY.encode() not in path.read_bytes()
        for path in options.output.iterdir()
        if path.is_file()
    )


def test_different_bundled_versions_preserve_parent_and_layer_and_are_audited_separately(setup):
    options, host = setup
    host.bundles = True
    receipt = collector.collect(options, host)
    assert receipt["collection_status"] == "complete"
    groups = receipt["cells"]["python_bundled"]["data"]["groups"]
    assert [(g["layer"], g["parent"], g["packages"][0]["version"]) for g in groups] == [
        ("python_os", "pip", "1.0"),
        ("python_venv", "pip", "2.0"),
    ]
    assert [
        (p[0]["version"], layer) for p, layer in host.audits if layer.startswith("bundled-")
    ] == [("1.0", "bundled-0"), ("2.0", "bundled-1")]


def test_scanner_failed_findings_preserved_and_whole_receipt_error(setup):
    options, host = setup
    host.scan_status = "error"
    host.scan_findings = [
        {
            "VulnerabilityID": "CVE-2026-0001",
            "PkgName": "libc6",
            "InstalledVersion": "2.41-1",
            "Severity": "LOW",
        }
    ]
    receipt = collector.collect(options, host)
    assert receipt["collection_status"] == "error"
    assert receipt["findings"]["native"] == host.scan_findings
    assert (options.output / "trivy-native.json").is_file()


@pytest.mark.parametrize("status", ["skipped", "incomplete", "error", "typo"])
def test_required_incomplete_or_unknown_status_cannot_succeed(status):
    cells = {name: {"status": "complete", "data": {}} for name in collector.REQUIRED}
    cells["trivy"]["status"] = status
    assert collector.aggregate(cells) != "complete"


def test_plan_does_not_inspect_host_create_output_or_execute(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(collector, "ReadOnlyHost", lambda *args: pytest.fail("host instantiated"))
    output = tmp_path / "never-created"
    assert collector.main(["--output", str(output), "--application-source", "/missing"]) == 0
    assert not output.exists()
    result = json.loads(capsys.readouterr().out)
    assert result["execution"] is False and result["host_mutation"] is False


@pytest.mark.parametrize(
    "different_machine,restarted", [(False, True), (False, False), (True, True)]
)
def test_post_maintenance_binds_same_target_and_fresh_process_observation(
    setup, different_machine, restarted
):
    options, host = setup
    previous = collector.collect(options, host)
    # Use a separate output for the fresh observation.
    options.output = options.output.parent / "after"
    options.output.mkdir(mode=0o700)
    previous["observed_until"] = "2020-01-01T00:00:00+00:00"
    previous["cells"]["libraries"] = copy.deepcopy(host.lib)
    previous["cells"]["libraries"]["data"]["start_ticks"] = 100 if restarted else 200
    previous["cells"]["libraries"]["data"]["restart_required"] = True
    if different_machine:
        previous["cells"]["os"]["data"]["machine_id_sha256"] = "0" * 64
    prior = options.output.parent / "previous.json"
    prior.write_text(json.dumps(previous))
    options.library = "libssl.so.3"
    options.maintenance_receipt = prior
    result = collector.collect(options, host)
    if different_machine:
        assert result["cells"]["libraries"]["status"] == "incomplete"
    else:
        binding = result["cells"]["libraries"]["data"]["maintenance_evidence"]
        assert binding["process_restart_observed"] == restarted
        assert binding["stale_mappings_cleared"] == restarted
        assert binding["same_machine"] is True


def committed_source(tmp_path):
    import subprocess

    source = tmp_path / "source"
    source.mkdir()
    files = {
        "backend/exitlane/__init__.py": '"public application"\n',
        "backend/exitlane/documentation.py": 'DOCUMENTS = [Document("guide", "Guide", "guide.md")]\n',
        "backend/pyproject.toml": '[project]\nversion = "1.0.0"\n',
        "backend/hatch_build.py": "# public build hook\n",
        "LICENSE": "Synthetic license\n",
        "THIRD_PARTY_NOTICES.md": "Synthetic notices\n",
        "docs/guide.md": "Synthetic public guide\n",
    }
    for name, content in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    for argv in [
        ["init"],
        ["add", "."],
        [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "Synthetic source",
        ],
    ]:
        subprocess.run(["/usr/bin/git", "-C", str(source), *argv], check=True, capture_output=True)
    return source


def test_installed_application_matches_committed_payload_without_inferred_build_sha(tmp_path):
    from native_security_host import ReadOnlyHost

    source = committed_source(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    host = ReadOnlyHost(work)
    prefix = tmp_path / "venv"
    location = prefix / "lib/python3.13/site-packages/exitlane"
    identity, expected = collector.package_source_manifest(host, source)
    for name in expected:
        actual = location / name
        actual.parent.mkdir(parents=True, exist_ok=True)
        original = source / (
            "backend/exitlane/" + name
            if (source / ("backend/exitlane/" + name)).is_file()
            else name
        )
        actual.write_bytes(original.read_bytes())
    meta = location.parent / "exitlane-1.0.0.dist-info"
    meta.mkdir()
    (meta / "METADATA").write_text("Name: ExitLane\nVersion: 1.0.0\n")
    (meta / "RECORD").write_text("public synthetic record\n")
    observed = {
        "version": "1.0.0",
        "location": str(location),
        "metadata_path": str(meta / "METADATA"),
        "record_path": str(meta / "RECORD"),
    }
    result = collector.application_identity(host, source, observed, prefix)
    assert result["source"] == identity
    assert result["source_equivalence"] == "matched"
    assert result["historical_build_commit"] is None
    (location / "__init__.py").write_text("# drift\n")
    with pytest.raises(collector.EvidenceError, match="installed_application_content_mismatch"):
        collector.application_identity(host, source, observed, prefix)
    (source / "LICENSE").write_text("source drift\n")
    with pytest.raises(collector.EvidenceError, match="source_public_content_drift"):
        collector.package_source_manifest(host, source)


@pytest.mark.parametrize("field", ["content_sha256", "boot_id_sha256"])
def test_previous_receipt_cannot_inject_private_metadata(setup, field):
    options, host = setup
    previous = collector.collect(options, host)
    previous["observed_until"] = "2020-01-01T00:00:00+00:00"
    previous["cells"]["libraries"] = copy.deepcopy(host.lib)
    if field == "content_sha256":
        previous["cells"]["application"]["data"][field] = CANARY
    else:
        previous["cells"]["libraries"]["data"][field] = CANARY
    options.output = options.output.parent / "after-private"
    options.output.mkdir(mode=0o700)
    prior = options.output.parent / "untrusted-prior.json"
    prior.write_text(json.dumps(previous))
    options.library = "libssl.so.3"
    options.maintenance_receipt = prior
    receipt = collector.collect(options, host)
    assert receipt["cells"]["libraries"]["status"] == "incomplete"
    assert CANARY not in json.dumps(receipt)


def test_output_symlink_ancestor_cannot_modify_target(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    assert (
        collector.main(
            ["--execute", "--output", str(link / "receipt"), "--application-source", "/source"]
        )
        == 2
    )
    assert not list(target.iterdir())
    assert "output_ancestor_invalid" in capsys.readouterr().out


@pytest.fixture
def safe_output_parent():
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as root:
        yield Path(root)


def synthetic_cli(output):
    return [
        "--execute",
        "--output",
        str(output),
        "--application-source",
        "/source",
        "--collector-source",
        "/source",
    ]


def test_cli_writes_private_pinned_artifacts_and_work(safe_output_parent, monkeypatch, capsys):
    output = safe_output_parent / "evidence"

    def synthetic_collect(options, host):
        assert host.work.is_dir()
        assert str(host.work).startswith("/proc/")
        assert host.run(["/usr/bin/true"]).returncode == 0
        options._output_dir.write("raw.json", b"synthetic-public-data")
        (host.work / "scratch").write_bytes(b"private-work")
        return {
            "collection_status": "complete",
            "artifacts": {
                "raw.json": {
                    "sha256": hashlib.sha256(b"synthetic-public-data").hexdigest(),
                    "size": 21,
                }
            },
        }

    monkeypatch.setattr(collector, "collect", synthetic_collect)
    monkeypatch.setattr(collector, "worksheet", lambda _: "synthetic worksheet\n")
    assert collector.main(synthetic_cli(output)) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["collection_status"] == "complete"
    assert output.stat().st_mode & 0o777 == 0o700
    for name in ("raw.json", "receipt.json", "worksheet.txt"):
        assert (output / name).stat().st_mode & 0o777 == 0o600
    assert (output / "work/scratch").read_bytes() == b"private-work"
    assert not list(output.glob(".*.tmp"))


def test_cli_swap_refuses_publication_without_touching_target(
    safe_output_parent, monkeypatch, capsys
):
    output = safe_output_parent / "evidence"
    target = safe_output_parent / "target"
    target.mkdir(mode=0o700)
    for name in ("receipt.json", "worksheet.txt", "raw.json"):
        (target / name).write_bytes(b"sentinel")

    def swap(options, host):
        options._output_dir.write("raw.json", b"safe-original")
        output.rename(safe_output_parent / "captured")
        output.symlink_to(target, target_is_directory=True)
        (host.work / "scratch").write_bytes(b"pinned-work")
        return {"collection_status": "complete"}

    monkeypatch.setattr(collector, "collect", swap)
    assert collector.main(synthetic_cli(output)) == 2
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["collection_status"] == "error"
    assert all(
        (target / name).read_bytes() == b"sentinel"
        for name in ("receipt.json", "worksheet.txt", "raw.json")
    )
    assert (safe_output_parent / "captured/work/scratch").read_bytes() == b"pinned-work"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory"])
def test_cli_refuses_existing_artifact_object(safe_output_parent, monkeypatch, capsys, kind):
    output = safe_output_parent / "evidence"
    target = safe_output_parent / "sentinel"
    target.write_bytes(b"unchanged")

    def plant(_options, _host):
        artifact = output / "receipt.json"
        if kind == "symlink":
            artifact.symlink_to(target)
        elif kind == "hardlink":
            artifact.hardlink_to(target)
        else:
            artifact.mkdir()
        return {"collection_status": "complete"}

    monkeypatch.setattr(collector, "collect", plant)
    assert collector.main(synthetic_cli(output)) == 2
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["collection_status"] == "error"
    assert target.read_bytes() == b"unchanged"
    assert not list(output.glob(".*.tmp"))


def test_artifact_publish_failure_cleans_temp_and_fresh_retry_succeeds(
    safe_output_parent, monkeypatch
):
    output = safe_output_parent / "evidence"
    original_link = collector.os.link

    def deny_link(*args, **kwargs):
        raise OSError("synthetic publish failure")

    monkeypatch.setattr(collector.os, "link", deny_link)
    with collector.OutputDirectory(output, create=True) as directory:
        with pytest.raises(OSError):
            directory.write("receipt.json", b"public")
    assert not list(output.iterdir())
    monkeypatch.setattr(collector.os, "link", original_link)
    with collector.OutputDirectory(safe_output_parent / "retry", create=True) as directory:
        directory.write("receipt.json", b"public")
    assert (safe_output_parent / "retry/receipt.json").read_bytes() == b"public"


def test_cli_rejects_replaceable_output_ancestor(tmp_path, capsys):
    output = tmp_path / "operator-controlled/evidence"
    output.parent.mkdir()
    assert (
        collector.main(["--execute", "--output", str(output), "--application-source", "/source"])
        == 2
    )
    assert not output.exists()
    assert "output_ancestor_invalid" in capsys.readouterr().out


@pytest.mark.parametrize("swap", ["output", "ancestor"])
def test_child_writes_through_pinned_work_after_path_swap(safe_output_parent, swap):
    ancestor = safe_output_parent / "ancestor"
    ancestor.mkdir(mode=0o700)
    output = ancestor / "evidence"
    target = safe_output_parent / "target"
    (target / "evidence/work").mkdir(parents=True, mode=0o700)
    (target / "evidence/work/child").write_bytes(b"sentinel")
    with collector.OutputDirectory(output, create=True) as directory:
        work = directory.create_work()
        if swap == "output":
            output.rename(ancestor / "captured")
            output.symlink_to(target / "evidence", target_is_directory=True)
            captured = ancestor / "captured"
        else:
            ancestor.rename(safe_output_parent / "captured-ancestor")
            ancestor.symlink_to(target, target_is_directory=True)
            captured = safe_output_parent / "captured-ancestor/evidence"
        host = collector.ReadOnlyHost(work)
        code = "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_bytes(b'pinned-child'); print(p.read_bytes().decode())"
        result = host.run([sys.executable, "-I", "-S", "-B", "-c", code, str(work / "child")])
        assert result.returncode == 0 and result.stdout.strip() == b"pinned-child"
        with pytest.raises((collector.EvidenceError, OSError)):
            directory.assert_current()
    assert (captured / "work/child").read_bytes() == b"pinned-child"
    assert (target / "evidence/work/child").read_bytes() == b"sentinel"


@pytest.mark.parametrize("raise_inside", [False, True])
def test_apt_private_temp_and_child_cleanup_stay_pinned_after_swap(
    safe_output_parent, raise_inside
):
    output = safe_output_parent / "evidence"
    target = safe_output_parent / "target"
    target.mkdir(mode=0o700)
    (target / "work").mkdir(mode=0o700)
    (target / "work/sentinel").write_bytes(b"unchanged")
    with collector.OutputDirectory(output, create=True) as directory:
        host = collector.ReadOnlyHost(directory.create_work())

        def exercise():
            with tempfile.TemporaryDirectory(prefix="apt-", dir=host.work) as temporary:
                config = Path(temporary) / "apt.conf"
                config.write_text('Dir "/private";\n')
                output.rename(safe_output_parent / "captured")
                output.symlink_to(target, target_is_directory=True)
                code = "from pathlib import Path; import os; p=Path(os.environ['APT_CONFIG']); print(p.read_text().strip()); (p.parent/'child').write_bytes(b'private')"
                result = host.run(
                    [sys.executable, "-I", "-S", "-B", "-c", code],
                    env={"APT_CONFIG": str(config)},
                )
                assert result.returncode == 0 and result.stdout.strip() == b'Dir "/private";'
                if raise_inside:
                    raise RuntimeError("synthetic APT failure")

        if raise_inside:
            with pytest.raises(RuntimeError, match="synthetic APT failure"):
                exercise()
        else:
            exercise()
    assert not list((safe_output_parent / "captured/work").glob("apt-*"))
    assert (target / "work/sentinel").read_bytes() == b"unchanged"
    assert list((target / "work").iterdir()) == [target / "work/sentinel"]


def test_trivy_stage_and_python_requirements_remain_in_pinned_work(safe_output_parent):
    output = safe_output_parent / "evidence"
    source = safe_output_parent / "public-db"
    source.write_bytes(b"synthetic-db")
    with collector.OutputDirectory(output, create=True) as directory:
        work = directory.create_work()
        host = collector.ReadOnlyHost(work)
        output.rename(safe_output_parent / "captured")
        output.symlink_to(safe_output_parent, target_is_directory=True)
        private_cache = work / "trivy-cache/db"
        private_cache.mkdir(parents=True, mode=0o700)
        digest = host.stage_database(source, private_cache / "trivy.db")
        requirements = work / "venv-requirements.txt"
        requirements.write_text("sample==1.0\n")
        code = "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_bytes().hex()); print(Path(sys.argv[2]).read_text().strip())"
        result = host.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                code,
                str(private_cache / "trivy.db"),
                str(requirements),
            ]
        )
        assert result.returncode == 0
        assert result.stdout.splitlines() == [b"synthetic-db".hex().encode(), b"sample==1.0"]
        assert digest == hashlib.sha256(b"synthetic-db").hexdigest()
    assert (
        safe_output_parent / "captured/work/trivy-cache/db/trivy.db"
    ).read_bytes() == b"synthetic-db"
    assert not (safe_output_parent / "trivy-cache").exists()
    assert not (safe_output_parent / "venv-requirements.txt").exists()


@pytest.mark.parametrize("mode", [0o777, 0o770])
def test_writable_ancestor_is_refused(safe_output_parent, mode):
    ancestor = safe_output_parent / "writable"
    ancestor.mkdir(mode=0o700)
    ancestor.chmod(mode)
    with pytest.raises(collector.EvidenceError, match="output_ancestor_invalid"):
        collector.OutputDirectory(ancestor / "evidence", create=True)
    assert not (ancestor / "evidence").exists()


def test_foreign_owned_ancestor_is_refused(safe_output_parent, monkeypatch):
    ancestor = safe_output_parent / "foreign"
    ancestor.mkdir(mode=0o700)
    real_fstat = os.fstat

    def foreign_owner(fd):
        info = real_fstat(fd)
        if os.readlink(f"/proc/self/fd/{fd}") == str(ancestor):
            fields = list(info)
            fields[4] = 65534 if os.geteuid() != 65534 else 65533
            return os.stat_result(fields)
        return info

    with monkeypatch.context() as patch:
        patch.setattr(collector.os, "fstat", foreign_owner)
        with pytest.raises(collector.EvidenceError, match="output_ancestor_invalid"):
            collector.OutputDirectory(ancestor / "evidence", create=True)


def test_fsync_failure_cleans_private_temp_without_publication(safe_output_parent, monkeypatch):
    output = safe_output_parent / "evidence"
    with collector.OutputDirectory(output, create=True) as directory:
        with monkeypatch.context() as patch:
            patch.setattr(
                collector.os,
                "fsync",
                lambda _fd: (_ for _ in ()).throw(OSError("synthetic fsync failure")),
            )
            with pytest.raises(OSError, match="synthetic fsync failure"):
                directory.write("receipt.json", b"public")
        assert not list(output.iterdir())
        directory.write("raw.json", b"already-published")
        with pytest.raises(FileExistsError):
            directory.write("raw.json", b"replacement")
        assert (output / "raw.json").read_bytes() == b"already-published"
        assert not list(output.glob(".*.tmp"))
