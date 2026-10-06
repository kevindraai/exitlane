"""Native read-only boundaries, synthetic scanners and process observations."""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/qualification"))
import native_security_host as host_module
from native_security_evidence import EvidenceError
from native_security_host import CommandResult, ReadOnlyHost
from test_native_security_evidence import inventory, os_identity, trivy


@pytest.fixture
def host(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    return ReadOnlyHost(work, root=root)


def test_command_environment_does_not_inherit_private_canaries(host, monkeypatch):
    monkeypatch.setenv("EXITLANE_PRIVATE_CANARY", "synthetic-private-marker")
    monkeypatch.setenv("HTTP_PROXY", "http://secret:password@qa.invalid")
    monkeypatch.setenv("PYTHONPATH", "synthetic-private-path")
    result = host.run(
        [sys.executable, "-I", "-S", "-c", "import json,os;print(json.dumps(dict(os.environ)))"]
    )
    environment = json.loads(result.stdout)
    assert result.returncode == 0
    assert "EXITLANE_PRIVATE_CANARY" not in environment
    assert "HTTP_PROXY" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["LC_ALL"] == "C"
    assert environment["PIP_CONFIG_FILE"] == "/dev/null"
    with pytest.raises(EvidenceError, match="command_environment_not_allowlisted"):
        host.run([sys.executable, "-c", "pass"], env={"SECRET": "canary"})


def test_command_nonzero_unavailable_timeout_and_output_bound(host):
    result = host.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import sys;sys.stderr.write('synthetic-error');sys.exit(7)",
        ]
    )
    assert result.returncode == 7
    assert result.stdout == b""
    assert result.stderr_sha256 == hashlib.sha256(b"synthetic-error").hexdigest()
    assert not hasattr(result, "stderr")
    assert host.run([str(host.work / "missing-tool")]).reason == "command_unavailable"
    result = host.run(
        [sys.executable, "-I", "-S", "-c", "import time;time.sleep(10)"], timeout=0.05
    )
    assert result.reason == "command_timeout"
    assert result.returncode is None
    result = host.run([sys.executable, "-I", "-S", "-c", "print('x'*10000)"], limit=32)
    assert result.reason == "command_output_limit"
    assert len(result.stdout) <= 32
    with pytest.raises(EvidenceError, match="command_input_limit"):
        host.run([sys.executable, "-c", "pass"], input=b"x" * 4097)


def test_child_is_reaped_before_observation_exception_unwinds(host, monkeypatch):
    spawned = []
    original_popen = host_module.subprocess.Popen

    def record_child(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def fail_select(_selector, _timeout=None):
        raise OSError("synthetic selector failure")

    monkeypatch.setattr(host_module.subprocess, "Popen", record_child)
    monkeypatch.setattr(host_module.selectors.DefaultSelector, "select", fail_select)
    with pytest.raises(OSError, match="synthetic selector failure"):
        host.run([sys.executable, "-I", "-S", "-c", "import time;time.sleep(30)"])
    assert len(spawned) == 1
    assert spawned[0].poll() is not None
    assert spawned[0].stdout.closed and spawned[0].stderr.closed


def test_public_reader_refuses_symlinks_hardlinks_nonregular_and_oversize(host):
    public = host.work / "metadata"
    public.write_bytes(b"public metadata")
    assert host.read_public(public) == b"public metadata"
    link = host.work / "symlink"
    link.symlink_to(public)
    with pytest.raises(EvidenceError, match="public_metadata_file_invalid"):
        host.read_public(link)
    hardlink = host.work / "hardlink"
    os.link(public, hardlink)
    with pytest.raises(EvidenceError, match="public_metadata_file_invalid"):
        host.read_public(public)
    hardlink.unlink()
    with pytest.raises(EvidenceError, match="public_metadata_file_invalid"):
        host.read_public(public, limit=2)
    with pytest.raises(EvidenceError, match="public_metadata_file_invalid"):
        host.read_public(host.work)


def test_public_reader_detects_replacement_between_lstat_and_open(host, monkeypatch):
    public = host.work / "metadata"
    public.write_bytes(b"original")
    replacement = host.work / "replacement"
    replacement.write_bytes(b"replacement")
    real_open = os.open

    def replace(path, flags, *args, **kwargs):
        if Path(path) == public:
            replacement.replace(public)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace)
    with pytest.raises(EvidenceError, match="public_metadata_file_changed"):
        host.read_public(public)


def test_python_probe_isolated_without_site_hooks(host, monkeypatch):
    marker = host.work / "hook-was-executed"
    (host.work / "sitecustomize.py").write_text(f"open({str(marker)!r},'w').write('unsafe')")
    monkeypatch.setenv("PYTHONPATH", str(host.work))
    prefix = host.work / "synthetic-venv"
    import sysconfig

    site = (
        prefix
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site.mkdir(parents=True)
    (site / "inject.pth").write_text(
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('unsafe')\n"
    )
    package = site / "sample-1.0.dist-info"
    package.mkdir()
    (package / "METADATA").write_text("Metadata-Version: 2.1\nName: sample\nVersion: 1.0\n")
    result = host.python(sys.executable, "venv", str(prefix))
    assert result["distributions"] == [{"name": "sample", "version": "1.0"}]
    assert result["interpreter"]["stdlib"] == sysconfig.get_path("stdlib")
    assert not marker.exists()
    assert not list(host.work.glob("__pycache__/*"))


def _scanner(host, monkeypatch, *, raw, returncode=0, identity=b"Version: 0.69.3\n", reason=None):
    tool = host.work / "scanner"
    tool.write_bytes(b"synthetic-scanner-identity")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return (
            CommandResult(0, identity, "e" * 64)
            if argv[-1] == "--version"
            else CommandResult(returncode, raw, "e" * 64, reason)
        )

    monkeypatch.setattr(host, "run", run)
    return str(tool), calls


def _cache(host):
    cache = host.work / "cache"
    (cache / "db").mkdir(parents=True)
    metadata = {
        "Version": 2,
        "UpdatedAt": "2026-01-01T00:00:00Z",
        "NextUpdate": "2026-01-02T00:00:00Z",
        "DownloadedAt": "2026-01-01T01:00:00Z",
    }
    (cache / "db/metadata.json").write_text(json.dumps(metadata))
    (cache / "db/trivy.db").write_bytes(b"synthetic-public-database")
    return cache


@pytest.mark.parametrize("returncode", [0, 9, None])
def test_trivy_retains_valid_scanner_findings_even_on_command_failure(
    host, monkeypatch, returncode
):
    raw = json.dumps(trivy()).encode()
    tool, calls = _scanner(host, monkeypatch, raw=raw, returncode=returncode)
    cell, retained = host.trivy(
        tool, _cache(host), host.work / "projection", inventory(), os_identity()
    )
    assert cell["status"] == ("complete" if returncode == 0 else "error")
    assert retained == raw
    assert cell["data"]["findings"] == trivy()["Results"][0]["Vulnerabilities"]
    assert cell["data"]["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    argv = calls[-1][0]
    assert "--offline-scan" in argv and "--skip-db-update" in argv
    assert argv[argv.index("--scanners") + 1] == "vuln"
    assert argv[argv.index("--pkg-types") + 1] == "os"
    assert Path(argv[argv.index("--ignorefile") + 1]).read_text() == ""


@pytest.mark.parametrize(
    "raw", [b"", b"not-json", b'{"private_environment":"canary"}', b"[" * 1200 + b"0" + b"]" * 1200]
)
def test_trivy_malformed_raw_is_hashed_but_never_retained(host, monkeypatch, raw):
    tool, _ = _scanner(host, monkeypatch, raw=raw, returncode=2)
    cell, retained = host.trivy(
        tool, _cache(host), host.work / "projection", inventory(), os_identity()
    )
    assert cell["status"] == "error"
    assert retained is None
    assert cell["data"]["findings"] is None
    assert cell["data"]["raw_size"] == len(raw)
    assert "canary" not in str(cell)


def test_trivy_missing_database_and_tool_identity_refused(host, monkeypatch):
    tool, calls = _scanner(host, monkeypatch, raw=b"")
    with pytest.raises(EvidenceError, match="trivy_database_unavailable"):
        host.trivy(
            tool, host.work / "missing", host.work / "projection", inventory(), os_identity()
        )
    assert len(calls) == 1
    _scanner(host, monkeypatch, raw=b"", identity=b"unexpected")
    with pytest.raises(EvidenceError, match="trivy_identity_unavailable"):
        host.trivy(tool, _cache(host), host.work / "projection", inventory(), os_identity())


@pytest.mark.parametrize("returncode", [0, 1, 2])
def test_pip_audit_exit_one_preserves_valid_findings(host, monkeypatch, returncode):
    report = {
        "dependencies": [
            {
                "name": "sample",
                "version": "1.0",
                "vulns": [{"id": "PYSEC-2026-1", "fix_versions": ["1.1"]}],
            }
        ],
        "fixes": [],
    }
    raw = json.dumps(report).encode()
    tool, calls = _scanner(
        host, monkeypatch, raw=raw, returncode=returncode, identity=b"pip-audit 2.10.0\n"
    )
    cell, retained = host.audit(tool, [{"name": "sample", "version": "1.0"}], allow_network=True)
    assert cell["status"] == ("complete" if returncode in (0, 1) else "error")
    assert retained == raw
    assert len(cell["data"]["findings"]) == 1
    assert "--disable-pip" in calls[-1][0] and "--no-deps" in calls[-1][0]
    assert (host.work / "venv-requirements.txt").read_text() == "sample==1.0\n"


def test_pip_audit_failure_and_no_network_preserve_unknown_findings(host, monkeypatch):
    tool, calls = _scanner(
        host, monkeypatch, raw=b"secret-canary", returncode=1, identity=b"pip-audit 2.10.0\n"
    )
    packages = [{"name": "sample", "version": "1.0"}]
    cell, retained = host.audit(tool, packages)
    assert cell["status"] == "incomplete"
    assert cell["data"]["findings"] is None
    assert retained is None and not calls
    cell, retained = host.audit(tool, packages, allow_network=True)
    assert cell["status"] == "error" and retained is None
    assert "secret-canary" not in str(cell)
    calls.clear()
    cell, retained = host.audit(
        tool,
        [{"name": "exitlane", "version": "1.0"}],
        allowed_skips={"exitlane": "local application"},
    )
    assert cell["status"] == "complete"
    assert cell["data"]["skipped"] == {"exitlane": "local application"}
    assert retained is None and not calls


def _process_fixture(
    host, monkeypatch, *, deleted=False, missing=False, race=False, inaccessible=False
):
    boot = host.root / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True)
    boot.write_text("01234567-89ab-cdef-0123-456789abcdef\n")
    proc = host.root / "proc/123"
    proc.mkdir(parents=True)
    # After the comm field, starttime is index 19 (Linux stat field 22).
    (proc / "stat").write_text(
        "123 (synthetic process) S " + " ".join(["0"] * 18 + ["42"] + ["0"] * 3)
    )
    library = host.root / "usr/lib/x86_64-linux-gnu/libc.so.6"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"synthetic-library")
    info = library.stat()
    device = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}"
    (proc / "maps").write_text(
        f"1000-2000 r-xp 00000000 {device} {info.st_ino} /usr/lib/x86_64-linux-gnu/libc.so.6"
        + (" (deleted)" if deleted else "")
        + "\n"
    )
    if missing:
        library.unlink()
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return CommandResult(0, b"124\n" if race and len(calls) > 1 else b"123\n", "e" * 64)

    monkeypatch.setattr(host, "run", run)
    if race:
        other = host.root / "proc/124"
        other.mkdir()
        (other / "stat").write_text((proc / "stat").read_text().replace("123 (", "124 ("))
    if inaccessible:
        original = host.read_public

        def read(path, limit=64 * 1024 * 1024):
            if Path(path).name == "maps":
                raise PermissionError("synthetic-inaccessible")
            return original(path, limit)

        monkeypatch.setattr(host, "read_public", read)
    return proc, library, calls


@pytest.mark.parametrize(
    "deleted,missing,restart", [(False, False, False), (True, False, True), (False, True, True)]
)
def test_loaded_library_identity_current_deleted_and_removed(
    host, monkeypatch, deleted, missing, restart
):
    _process_fixture(host, monkeypatch, deleted=deleted, missing=missing)
    cell = host.libraries("exitlane.service", "libc.so.6")
    assert cell["status"] == "complete"
    assert cell["data"]["restart_required"] is restart
    assert cell["data"]["mappings"][0]["deleted"] is deleted
    assert cell["data"]["scope"] == "selected_service_main_process_only"


@pytest.mark.parametrize("case", ["race", "inaccessible", "absent", "malformed"])
def test_loaded_library_unobservable_or_racing_process_is_unknown(host, monkeypatch, case):
    proc, _, _ = _process_fixture(
        host, monkeypatch, race=case == "race", inaccessible=case == "inaccessible"
    )
    if case == "absent":
        (proc / "maps").write_text("")
    if case == "malformed":
        (proc / "stat").write_text("malformed")
    cell = host.libraries("nordvpnd.service", "libc.so.6")
    assert cell["status"] == "incomplete"
    assert cell["data"]["restart_required"] is None
    assert cell["data"]["mappings"] == []


def test_loaded_library_refuses_unapproved_service_and_paths(host, monkeypatch):
    with pytest.raises(EvidenceError, match="library_service_not_allowlisted"):
        host.libraries("unapproved.service", "libc.so.6")
    with pytest.raises(EvidenceError, match="library_name_invalid"):
        host.libraries("exitlane.service", "../../private")
    _, library, _ = _process_fixture(host, monkeypatch)
    library.unlink()
    target = host.work / "private-data"
    target.write_bytes(b"synthetic-private-canary")
    library.symlink_to(target)
    cell = host.libraries("exitlane.service", "libc.so.6")
    assert cell["status"] == "incomplete"
    assert "synthetic-private-canary" not in str(cell)


def test_command_timeout_remains_enforced_after_child_closes_output(host):
    result = host.run(
        [sys.executable, "-I", "-S", "-c", "import os,time;os.close(1);os.close(2);time.sleep(10)"],
        timeout=0.05,
    )
    assert result.reason == "command_timeout"
    assert result.returncode is None


@pytest.mark.parametrize(
    "metadata",
    [
        "not-json",
        '{"Version":2,"private_environment":"canary"}',
        '{"Version":2,"UpdatedAt":"bad","NextUpdate":"bad","DownloadedAt":"bad"}',
    ],
)
def test_trivy_malformed_database_identity_refuses_scan(host, monkeypatch, metadata):
    tool, calls = _scanner(host, monkeypatch, raw=json.dumps(trivy()).encode())
    cache = _cache(host)
    (cache / "db/metadata.json").write_text(metadata)
    with pytest.raises(EvidenceError, match="trivy_database_unavailable") as error:
        host.trivy(tool, cache, host.work / "projection", inventory(), os_identity())
    assert len(calls) == 1
    assert "canary" not in str(error.value)


def test_pip_audit_valid_but_missing_package_coverage_is_incomplete(host, monkeypatch):
    raw = b'{"dependencies":[],"fixes":[]}'
    tool, _ = _scanner(host, monkeypatch, raw=raw, returncode=1, identity=b"pip-audit 2.10.0\n")
    cell, retained = host.audit(tool, [{"name": "sample", "version": "1.0"}], allow_network=True)
    assert cell["status"] == "incomplete"
    assert retained == raw
    assert cell["data"]["coverage"]["missing"] == [("sample", "1.0")]


def test_python_probe_failure_and_invalid_json_never_export_raw(host, monkeypatch):
    monkeypatch.setattr(host, "run", lambda argv: CommandResult(2, b"private-canary", "e" * 64))
    with pytest.raises(EvidenceError, match="python_inventory_failed"):
        host.python(sys.executable, "os")
    monkeypatch.setattr(host, "run", lambda argv: CommandResult(0, b"private-canary", "e" * 64))
    with pytest.raises(EvidenceError, match="python_inventory_invalid") as error:
        host.python(sys.executable, "os")
    assert "private-canary" not in str(error.value)


def test_public_reader_rejects_ancestor_symlink_before_canary_read(host, monkeypatch):
    private = host.work / "synthetic-private"
    private.mkdir()
    (private / "metadata").write_bytes(b"synthetic-private-canary")
    alias = host.work / "public-alias"
    alias.symlink_to(private, target_is_directory=True)
    called = []
    real_open = os.open

    def record_open(*args, **kwargs):
        called.append(args[0])
        return real_open(*args, **kwargs)

    monkeypatch.setattr(os, "open", record_open)
    with pytest.raises(EvidenceError, match="public_metadata_ancestor_invalid") as error:
        host.read_public(alias / "metadata")
    assert not called
    assert "synthetic-private-canary" not in str(error.value)


@pytest.mark.parametrize("symlink_kind", ["metadata", "manifest", "distinfo_parent"])
def test_isolated_python_probe_rejects_metadata_and_vendor_symlink_canaries(
    host, monkeypatch, symlink_kind
):
    prefix = host.work / "synthetic-venv"
    site = (
        prefix
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site.mkdir(parents=True)
    metadata = "Metadata-Version: 2.1\nName: pip\nVersion: 1.0\n"
    distinfo = site / "pip-1.0.dist-info"
    distinfo.mkdir()
    (distinfo / "METADATA").write_text(metadata)
    vendor = site / "pip/_vendor"
    vendor.mkdir(parents=True)
    private = host.work / "synthetic-private"
    private.mkdir()
    if symlink_kind == "metadata":
        canary = private / "METADATA"
        canary.write_text(metadata.replace("Name: pip", "Name: private-canary"))
        (distinfo / "METADATA").unlink()
        (distinfo / "METADATA").symlink_to(canary)
    elif symlink_kind == "manifest":
        canary = private / "vendor.txt"
        canary.write_text("private-canary==1.0\n")
        (vendor / "vendor.txt").symlink_to(canary)
    else:
        (distinfo / "METADATA").unlink()
        distinfo.rmdir()
        target = private / "pip-1.0.dist-info"
        target.mkdir()
        (target / "METADATA").write_text(metadata.replace("Name: pip", "Name: private-canary"))
        distinfo.symlink_to(target, target_is_directory=True)
    original = host.run
    results = []

    def run(argv, **kwargs):
        assert argv[1:4] == ["-I", "-S", "-B"]
        result = original(argv, **kwargs)
        results.append(result)
        return result

    monkeypatch.setattr(host, "run", run)
    with pytest.raises(EvidenceError, match="python_inventory_failed"):
        host.python(sys.executable, "venv", str(prefix))
    assert results[0].returncode != 0
    assert b"private-canary" not in results[0].stdout


@pytest.mark.parametrize("hardlinked", [False, True])
def test_bootstrap_wheel_with_bundled_payload_without_manifest_records_gap(
    host, monkeypatch, hardlinked
):
    import zipfile

    from native_security_host import PYTHON_PROBE

    stdlib = host.work / "synthetic-stdlib"
    bundled = stdlib / "ensurepip/_bundled"
    bundled.mkdir(parents=True)
    wheel = bundled / "pip-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "pip-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: pip\nVersion: 1.0\n"
        )
        archive.writestr("pip/_vendor/dependency/__init__.py", "# Synthetic bundled dependency\n")
        archive.writestr(
            "pip/_vendor/dependency-1.0.dist-info/METADATA", "Name: dependency\nVersion: 1.0\n"
        )
    if hardlinked:
        os.link(wheel, host.work / "private-wheel-link")
    empty = host.work / "empty-system-packages"
    empty.mkdir()
    prelude = (
        "import pathlib,sysconfig,importlib.metadata,email.parser,zipfile\n"
        "original_path=type(pathlib.Path('/'))\n"
        f"stdlib={str(stdlib)!r};empty={str(empty)!r}\n"
        "original_get_path=sysconfig.get_path\n"
        "sysconfig.get_path=lambda name,*a,**k: stdlib if name=='stdlib' else empty if name=='purelib' else original_get_path(name,*a,**k)\n"
        "pathlib.Path=lambda value,*a: original_path(empty if str(value) in ('/usr/share/python-wheels','/usr/lib/python3/dist-packages') else value,*a)\n"
    )
    original = host.run

    def run(argv, **kwargs):
        assert argv[1:4] == ["-I", "-S", "-B"]
        assert argv[5] == PYTHON_PROBE
        argv = list(argv)
        argv[5] = prelude + PYTHON_PROBE
        return original(argv, **kwargs)

    monkeypatch.setattr(host, "run", run)
    if hardlinked:
        with pytest.raises(EvidenceError, match="python_inventory_failed"):
            host.python(sys.executable, "os")
        return
    result = host.python(sys.executable, "os")
    assert result["bootstrap"]["wheels"][0]["name"] == "pip"
    assert result["bootstrap"]["wheels"][0]["bundled"] == []
    assert result["bundled_gaps"] == [
        {"parent": "pip", "reason": "bundled_dependency_manifest_unavailable"}
    ]


def test_database_streaming_copy_hash_mode_and_bounded_chunks(host, monkeypatch):
    source = host.work / "synthetic-database"
    data = b"0123456789abcdef" * (200_000)
    source.write_bytes(data)
    destination = host.work / "staged-database"
    original = os.fdopen
    reads = []

    class RecordingReader:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            reads.append(size)
            return self.stream.read(size)

    def fdopen(fd, *args, **kwargs):
        return RecordingReader(original(fd, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", fdopen)
    digest = host.stage_database(source, destination)
    assert digest == hashlib.sha256(data).hexdigest()
    assert destination.read_bytes() == data
    assert destination.stat().st_mode & 0o777 == 0o600
    assert reads and all(size == 1024 * 1024 for size in reads)


@pytest.mark.parametrize("invalid", ["empty", "oversize", "symlink", "ancestor", "hardlink"])
def test_database_streaming_refuses_invalid_sources_without_copy(host, invalid):
    source = host.work / "synthetic-database"
    source.write_bytes(b"public database")
    if invalid == "empty":
        source.write_bytes(b"")
    elif invalid == "oversize":
        with source.open("r+b") as stream:
            stream.truncate(4 * 1024**3 + 1)  # Sparse; no large allocation or memory read.
    elif invalid == "symlink":
        alias = host.work / "alias"
        alias.symlink_to(source)
        source = alias
    elif invalid == "ancestor":
        alias = host.work / "alias"
        alias.symlink_to(host.work, target_is_directory=True)
        source = alias / source.name
    elif invalid == "hardlink":
        os.link(source, host.work / "hardlink")
    destination = host.work / "staged-database"
    with pytest.raises(EvidenceError, match="trivy_database_(path|size)_invalid"):
        host.stage_database(source, destination)
    assert not destination.exists()


@pytest.mark.parametrize("change", ["replacement", "growth", "same_size"])
def test_database_streaming_detects_source_change(host, monkeypatch, change):
    source = host.work / "synthetic-database"
    source.write_bytes(b"public database")
    destination = host.work / "staged-database"
    if change == "replacement":
        replacement = host.work / "replacement"
        replacement.write_bytes(b"changed database")
        original = os.open

        def replace(path, flags, *args, **kwargs):
            if Path(path) == source:
                replacement.replace(source)
            return original(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", replace)
    else:
        original = os.fstat
        calls = []

        def fstat(fd):
            calls.append(fd)
            if len(calls) == 1:
                if change == "growth":
                    with source.open("ab") as stream:
                        stream.write(b"modified")
                else:
                    with source.open("r+b") as stream:
                        stream.write(b"X")
                    original_time = source.stat().st_mtime_ns
                    os.utime(source, ns=(original_time, original_time + 1_000_000))
            return original(fd)

        monkeypatch.setattr(os, "fstat", fstat)
    with pytest.raises(EvidenceError, match="trivy_database_changed"):
        host.stage_database(source, destination)


def test_isolated_python_probe_covers_distinfo_directory_and_single_file_egginfo(host, monkeypatch):
    prefix = host.work / "synthetic-venv"
    site = (
        prefix
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site.mkdir(parents=True)
    distinfo = site / "modern-1.0.dist-info"
    distinfo.mkdir()
    (distinfo / "METADATA").write_text("Metadata-Version: 2.1\nName: modern\nVersion: 1.0\n")
    egginfo = site / "debian_directory-2.0.egg-info"
    egginfo.mkdir()
    (egginfo / "PKG-INFO").write_text(
        "Metadata-Version: 1.2\nName: debian-directory\nVersion: 2.0\n"
    )
    (site / "debian_single-3.0.egg-info").write_text(
        "Metadata-Version: 1.1\nName: debian-single\nVersion: 3.0\n"
    )
    original = host.run
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return original(argv, **kwargs)

    monkeypatch.setattr(host, "run", run)
    result = host.python(sys.executable, "venv", str(prefix))
    assert calls[0][1:4] == ["-I", "-S", "-B"]
    assert sorted(result["distributions"], key=lambda package: package["name"]) == [
        {"name": "debian-directory", "version": "2.0"},
        {"name": "debian-single", "version": "3.0"},
        {"name": "modern", "version": "1.0"},
    ]


@pytest.mark.parametrize("kind", ["directory_pkg_info", "single_file"])
def test_isolated_python_probe_refuses_egginfo_symlink_canary(host, kind):
    prefix = host.work / "synthetic-venv"
    site = (
        prefix
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    site.mkdir(parents=True)
    private = host.work / "synthetic-private-PKG-INFO"
    private.write_text("Metadata-Version: 1.2\nName: private-canary\nVersion: 1.0\n")
    if kind == "directory_pkg_info":
        egginfo = site / "synthetic-1.0.egg-info"
        egginfo.mkdir()
        (egginfo / "PKG-INFO").symlink_to(private)
    else:
        (site / "synthetic-1.0.egg-info").symlink_to(private)
    with pytest.raises(EvidenceError, match="python_inventory_failed") as error:
        host.python(sys.executable, "venv", str(prefix))
    assert "private-canary" not in str(error.value)
