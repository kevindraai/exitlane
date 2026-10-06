"""Read-only native observations; no application import, configuration or environment export."""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from native_security_evidence import EvidenceError, validate_pip_audit, validate_trivy

PYTHON_PROBE = r"""
import email.parser,hashlib,importlib.metadata,io,json,os,pathlib,stat,sys,sysconfig,zipfile
def public_read(path,limit=1048576):
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('public_metadata_symlink')
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:raise ValueError('public_metadata_invalid')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        actual=os.fstat(fd)
        if (actual.st_dev,actual.st_ino)!=(info.st_dev,info.st_ino):raise ValueError('public_metadata_changed')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(limit+1)
        if len(raw)>limit:raise ValueError('public_metadata_oversized')
        return raw
    finally:os.close(fd)
mode=sys.argv[1]
stdlib=pathlib.Path(sysconfig.get_path('stdlib'))
if mode=='venv':
    prefix=pathlib.Path(sys.argv[2])
    paths=[prefix/'lib'/('python%d.%d'%sys.version_info[:2])/'site-packages']
else:
    paths=[pathlib.Path(sysconfig.get_path('purelib')),pathlib.Path('/usr/lib/python3/dist-packages')]
dists=list(importlib.metadata.distributions(path=[str(p) for p in paths if p.is_dir()]))
packages=[];application=None;bundled=[];gaps=[]
for d in dists:
    metadata_path=d._path
    if metadata_path.is_dir():
        metadata_path=metadata_path/('PKG-INFO' if metadata_path.name.endswith('.egg-info') else 'METADATA')
    meta=email.parser.Parser().parsestr(public_read(metadata_path).decode('utf-8'))
    name=meta.get('Name');version=meta.get('Version')
    packages.append({'name':name,'version':version})
    if name and name.lower()=='exitlane':
        application={'version':version,'location':str(d.locate_file('exitlane')),
            'metadata_path':str(d._path/'METADATA'),'record_path':str(d._path/'RECORD')}
    if name and name.lower() in ('pip','setuptools'):
        manifest=d.locate_file(name.lower()+'/_vendor/vendor.txt')
        if manifest.is_file():
            raw=public_read(manifest)
            if len(raw)>1048576:raise ValueError('vendor_manifest_oversized')
            bundled.append({'parent':name,'sha256':hashlib.sha256(raw).hexdigest(),'manifest':raw.decode('utf-8')})
        elif d.locate_file(name.lower()+'/_vendor').is_dir():
            gaps.append({'parent':name,'reason':'bundled_dependency_manifest_unavailable'})
wheels=[]
if mode=='os':
    for folder in (stdlib/'ensurepip/_bundled',pathlib.Path('/usr/share/python-wheels')):
        if folder.is_dir():
            if any(p.is_symlink() for p in (folder,*folder.parents)):raise ValueError('bootstrap_path_invalid')
            for path in sorted(folder.glob('*.whl')):
                if path.is_symlink() or path.stat().st_size>67108864:raise ValueError('bootstrap_wheel_invalid')
                wheel_raw=public_read(path,67108864)
                with zipfile.ZipFile(io.BytesIO(wheel_raw)) as z:
                    entries=[x for x in z.infolist() if x.filename.endswith('.dist-info/METADATA') and x.filename.count('/')==1]
                    if len(entries)!=1 or entries[0].file_size>1048576:raise ValueError('bootstrap_metadata_invalid')
                    meta=email.parser.Parser().parsestr(z.read(entries[0]).decode('utf-8'))
                    vendors=[]
                    for item in ('pip/_vendor/vendor.txt','setuptools/_vendor/vendor.txt'):
                        if item in z.namelist():
                            if z.getinfo(item).file_size>1048576:raise ValueError('vendor_manifest_oversized')
                            raw=z.read(item)
                            vendors.append({'parent':meta['Name'],'sha256':hashlib.sha256(raw).hexdigest(),'manifest':raw.decode('utf-8')})
                        elif any(n.startswith(item.rsplit('/',1)[0]+'/') for n in z.namelist()):
                            gaps.append({'parent':meta['Name'],'reason':'bundled_dependency_manifest_unavailable'})
                    wheels.append({'filename':path.name,'name':meta['Name'],'version':meta['Version'],
                        'sha256':hashlib.sha256(wheel_raw).hexdigest(),'bundled':vendors})
print(json.dumps({'interpreter':{'version':sys.version.split()[0],'implementation':sys.implementation.name,
    'executable':sys.executable,'stdlib':str(stdlib)},'distributions':packages,'application':application,
    'bootstrap':{'ensurepip_present':(stdlib/'ensurepip/__init__.py').is_file(),'wheels':wheels,
        'historical_execution':'unresolved_no_contemporaneous_evidence'},'bundled':bundled,'bundled_gaps':gaps}))
"""


@dataclass
class CommandResult:
    returncode: int | None
    stdout: bytes
    stderr_sha256: str
    reason: str | None = None


class ReadOnlyHost:
    def __init__(self, work: Path, *, root: Path = Path("/")):
        self.work = work
        self.root = root

    def run(self, argv, *, input=None, env=None, timeout=60, limit=64 * 1024 * 1024):
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NETRC": "/dev/null",
            "PIP_CONFIG_FILE": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_LAZY_FETCH": "1",
        }
        if env:
            if set(env) != {"APT_CONFIG"}:
                raise EvidenceError("command_environment_not_allowlisted")
            environment.update(env)
        if input is not None and len(input) > 4096:
            raise EvidenceError("command_input_limit")
        stderr_hash = hashlib.sha256()
        output = bytearray()
        try:
            process = subprocess.Popen(
                list(argv),
                cwd=self.work,
                env=environment,
                stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
        except OSError:
            return CommandResult(
                None, b"", stderr_hash.hexdigest(), "command_unavailable"
            )
        if input is not None:
            try:
                process.stdin.write(input)
                process.stdin.close()
            except BrokenPipeError:
                pass
        reason = None
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if time.monotonic() > deadline:
                    reason = "command_timeout"
                    break
                for key, _ in selector.select(
                    min(0.1, max(0, deadline - time.monotonic()))
                ):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stderr":
                        stderr_hash.update(chunk)
                    elif len(output) + len(chunk) > limit:
                        reason = "command_output_limit"
                        break
                    else:
                        output.extend(chunk)
                if reason:
                    break
        if reason:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            reason = "command_timeout"
        process.stdout.close()
        process.stderr.close()
        return CommandResult(
            None if reason else process.returncode,
            bytes(output),
            stderr_hash.hexdigest(),
            reason,
        )

    def read_public(self, path: Path, limit=64 * 1024 * 1024):
        if any(parent.is_symlink() for parent in path.parents):
            raise EvidenceError("public_metadata_ancestor_invalid")
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise EvidenceError("public_metadata_file_invalid")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                raise EvidenceError("public_metadata_file_changed")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            if len(raw) > limit:
                raise EvidenceError("public_metadata_file_oversized")
            return raw
        finally:
            os.close(fd)

    def python(self, executable: str, mode: str, prefix: str = ""):
        result = self.run(
            [executable, "-I", "-S", "-B", "-c", PYTHON_PROBE, mode, prefix]
        )
        if result.returncode != 0:
            raise EvidenceError("python_inventory_failed")
        try:
            data = json.loads(result.stdout)
            binary = Path(executable).resolve(strict=True)
            data["interpreter"]["binary_sha256"] = hashlib.sha256(
                self.read_public(binary)
            ).hexdigest()
            return data
        except (ValueError, UnicodeError, RecursionError):
            raise EvidenceError("python_inventory_invalid") from None

    def stage_database(self, source: Path, destination: Path):
        """Bounded streaming copy: current Trivy databases can exceed appliance RAM."""
        if any(path.is_symlink() for path in (source, *source.parents)):
            raise EvidenceError("trivy_database_path_invalid")
        before = source.stat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= 4 * 1024**3
        ):
            raise EvidenceError("trivy_database_size_invalid")
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        digest = hashlib.sha256()
        size = 0
        try:
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino):
                raise EvidenceError("trivy_database_changed")
            with (
                os.fdopen(fd, "rb", closefd=False) as src,
                destination.open("xb") as dst,
            ):
                destination.chmod(0o600)
                while chunk := src.read(1024 * 1024):
                    size += len(chunk)
                    if size > before.st_size:
                        raise EvidenceError("trivy_database_changed")
                    digest.update(chunk)
                    dst.write(chunk)
            after = os.fstat(fd)
            if size != before.st_size or (
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise EvidenceError("trivy_database_changed")
            return digest.hexdigest()
        finally:
            os.close(fd)

    def trivy(
        self, executable: str, cache: Path, projection: Path, inventory, os_identity
    ):
        result = self.run([executable, "--version"])
        version = re.search(
            rb"^Version: ([0-9][0-9A-Za-z.+-]*)$", result.stdout, re.MULTILINE
        )
        if result.returncode != 0 or not version:
            raise EvidenceError("trivy_identity_unavailable")
        try:
            raw_metadata = self.read_public(cache / "db/metadata.json", 1024 * 1024)
            metadata = json.loads(raw_metadata)
            if (
                set(metadata) != {"Version", "UpdatedAt", "NextUpdate", "DownloadedAt"}
                or metadata["Version"] != 2
            ):
                raise EvidenceError("trivy_database_identity_invalid")
            from datetime import datetime

            for key in ("UpdatedAt", "NextUpdate", "DownloadedAt"):
                datetime.fromisoformat(metadata[key].replace("Z", "+00:00"))
            if datetime.fromisoformat(
                metadata["NextUpdate"].replace("Z", "+00:00")
            ) <= datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00")):
                raise EvidenceError("trivy_database_identity_invalid")
        except (OSError, ValueError, TypeError, KeyError):
            raise EvidenceError("trivy_database_unavailable") from None
        private_cache = self.work / "trivy-cache/db"
        private_cache.mkdir(parents=True, mode=0o700)
        database_sha256 = self.stage_database(
            cache / "db/trivy.db", private_cache / "trivy.db"
        )
        (private_cache / "metadata.json").write_bytes(raw_metadata)
        config = self.work / "trivy-config.yaml"
        config.write_text("{}\n")
        ignores = self.work / "trivy-ignore"
        ignores.write_text("")
        result = self.run(
            [
                executable,
                "--config",
                str(config),
                "--cache-dir",
                str(private_cache.parent),
                "--disable-telemetry",
                "--skip-version-check",
                "rootfs",
                "--scanners",
                "vuln",
                "--pkg-types",
                "os",
                "--list-all-pkgs",
                "--offline-scan",
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--skip-vex-repo-update",
                "--format",
                "json",
                "--exit-code",
                "0",
                "--ignorefile",
                str(ignores),
                str(projection),
            ],
            timeout=180,
        )
        observation = {
            "tool_version": version.group(1).decode(),
            "tool_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
            "database": {
                **metadata,
                "sha256": database_sha256,
                "metadata_sha256": hashlib.sha256(raw_metadata).hexdigest(),
            },
            "returncode": result.returncode,
            "stderr_sha256": result.stderr_sha256,
            "raw_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "raw_size": len(result.stdout),
            "scan_scope": "native_package_metadata",
            "findings": None,
        }
        try:
            parsed = validate_trivy(result.stdout, inventory, os_identity)
        except EvidenceError as error:
            return {"status": "error", "reason": error.code, "data": observation}, None
        observation.update(
            {"findings": parsed["findings"], "coverage": parsed["coverage"]}
        )
        status = parsed["status"] if result.returncode == 0 else "error"
        return {
            "status": status,
            "reason": result.reason
            or ("trivy_invocation_failed" if result.returncode != 0 else None),
            "data": observation,
        }, result.stdout

    def audit(
        self,
        executable: str,
        packages,
        *,
        allowed_skips=None,
        allow_network=False,
        layer="venv",
    ):
        allowed_skips = allowed_skips or {}
        audited = [p for p in packages if p["name"].lower() not in allowed_skips]
        if not audited:
            return {
                "status": "complete",
                "data": {"findings": [], "audited": [], "skipped": allowed_skips},
            }, None
        if not allow_network:
            return {
                "status": "incomplete",
                "reason": "python_advisory_lookup_not_authorized",
                "data": {"findings": None, "skipped": allowed_skips},
            }, None
        identity = self.run([executable, "--version"])
        version = re.fullmatch(rb"pip-audit ([0-9][0-9A-Za-z.+-]*)\s*", identity.stdout)
        if identity.returncode != 0 or not version:
            raise EvidenceError("python_auditor_identity_unavailable")
        requirements = self.work / (layer + "-requirements.txt")
        requirements.write_text(
            "".join(f"{p['name']}=={p['version']}\n" for p in audited)
        )
        result = self.run(
            [
                executable,
                "--requirement",
                str(requirements),
                "--format",
                "json",
                "--no-deps",
                "--disable-pip",
                "--vulnerability-service",
                "pypi",
                "--progress-spinner",
                "off",
                "--cache-dir",
                str(self.work / "python-audit-cache"),
            ],
            timeout=180,
        )
        data = {
            "tool_version": version.group(1).decode(),
            "tool_sha256": hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
            "requirements_sha256": hashlib.sha256(
                requirements.read_bytes()
            ).hexdigest(),
            "returncode": result.returncode,
            "stderr_sha256": result.stderr_sha256,
            "raw_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "raw_size": len(result.stdout),
            "findings": None,
            "skipped": allowed_skips,
        }
        try:
            parsed = validate_pip_audit(result.stdout, audited, {})
        except EvidenceError as error:
            return {"status": "error", "reason": error.code, "data": data}, None
        data.update({"findings": parsed["findings"], "coverage": parsed["coverage"]})
        status = parsed["status"] if result.returncode in (0, 1) else "error"
        return {
            "status": status,
            "reason": result.reason
            or ("python_audit_failed" if result.returncode not in (0, 1) else None),
            "data": data,
        }, result.stdout

    def libraries(self, service: str, library: str):
        from datetime import datetime, timezone

        from native_security_evidence import parse_library_maps

        if service not in {"exitlane.service", "nordvpnd.service"}:
            raise EvidenceError("library_service_not_allowlisted")
        if not re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so(?:\.[0-9]+)*", library):
            raise EvidenceError("library_name_invalid")
        observed = datetime.now(timezone.utc).isoformat()
        data = {
            "service": service,
            "library": library,
            "observed_at": observed,
            "mappings": [],
            "restart_required": None,
            "scope": "selected_service_main_process_only",
        }
        try:
            boot = self.read_public(
                self.root / "proc/sys/kernel/random/boot_id", 128
            ).strip()
            if not re.fullmatch(rb"[0-9a-f-]{36}", boot):
                raise EvidenceError("boot_identity_invalid")

            def process_identity():
                command = self.run(
                    [
                        "/usr/bin/systemctl",
                        "show",
                        service,
                        "--property=MainPID",
                        "--value",
                    ]
                )
                if command.returncode != 0 or not re.fullmatch(
                    rb"[1-9][0-9]*\s*", command.stdout
                ):
                    raise EvidenceError("service_process_unavailable")
                pid = int(command.stdout)
                raw_stat = self.read_public(
                    self.root / f"proc/{pid}/stat", 65536
                ).decode()
                fields = raw_stat[raw_stat.rfind(")") + 2 :].split()
                return pid, int(fields[19])

            before = process_identity()
            data.update(
                {
                    "boot_id_sha256": hashlib.sha256(boot).hexdigest(),
                    "pid": before[0],
                    "start_ticks": before[1],
                }
            )
            raw = self.read_public(
                self.root / f"proc/{before[0]}/maps", 8 * 1024 * 1024
            ).decode()
            mappings = parse_library_maps(raw, library)
            for mapping in mappings:
                current = self.root / mapping["path"].lstrip("/")
                resolved = current.resolve()
                if not (
                    resolved.is_relative_to(self.root / "usr/lib")
                    or resolved.is_relative_to(self.root / "lib")
                ):
                    raise EvidenceError("library_path_not_public")
                try:
                    details = current.stat()
                    mapping.update(
                        {
                            "current_exists": True,
                            "current_device": f"{os.major(details.st_dev):02x}:{os.minor(details.st_dev):02x}",
                            "current_inode": details.st_ino,
                        }
                    )
                except FileNotFoundError:
                    mapping.update(
                        {
                            "current_exists": False,
                            "current_device": None,
                            "current_inode": None,
                        }
                    )
            after = process_identity()
            data["observed_until"] = datetime.now(timezone.utc).isoformat()
            if (
                before != after
                or self.read_public(
                    self.root / "proc/sys/kernel/random/boot_id", 128
                ).strip()
                != boot
            ):
                return {
                    "status": "incomplete",
                    "reason": "library_process_identity_changed",
                    "data": data,
                }
            data["mappings"] = mappings
            if not mappings:
                return {
                    "status": "incomplete",
                    "reason": "selected_library_not_observed",
                    "data": data,
                }
            data["restart_required"] = any(
                m["deleted"]
                or not m["current_exists"]
                or (m["device"], m["inode"])
                != (m["current_device"], m["current_inode"])
                for m in mappings
            )
            return {"status": "complete", "data": data}
        except (OSError, ValueError, IndexError, UnicodeError, EvidenceError):
            return {
                "status": "incomplete",
                "reason": "library_observation_unavailable",
                "data": data,
            }
