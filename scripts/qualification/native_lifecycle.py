#!/usr/bin/env python3
"""One-stage native qualification on explicitly authorized disposable Debian guests.

Plan is the default. This tool does not provision guests or grant execution authority.
Run-state and child logs are private and must never be uploaded as CI artifacts.
"""

from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import json
import os
import re
import secrets
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import tomllib

# Keep exact-source checkouts clean when invoked directly with python3.
sys.dont_write_bytecode = True

import native_lifecycle_state as state

ROOT = Path("/")
RUNS = Path("/root/exitlane-native-qualification")
STAGES = (
    "baseline-install",
    "candidate-install",
    "seed",
    "rollback",
    "upgrade",
    "idempotence",
    "backup",
    "restore",
)
FAULT = """set -Eeuo pipefail
readonly QUALIFICATION_FAULT_MARKER="$2"
source "$1/installer/install-debian.sh"
commit_upgrade() {
  [[ "$UPGRADE_MODE" == 1 && "$UPGRADE_COMMITTED" == 0 ]]
  [[ -n "$RECOVERY_DIR" && -f "$RECOVERY_DIR/exitlane.db" ]]
  printf '%s\\n' qualification_precommit_fault > "$QUALIFICATION_FAULT_MARKER"
  return 97
}
main
"""


class QualificationError(RuntimeError):
    pass


def fail(code):
    raise QualificationError(code)


MAX_PRIVATE = 32 * 1024 * 1024
ROOT_UID = 0
V1_TAG_SHA = "7973d3a6508c08a2949b88dad3750f43544cff48"


def safe_ancestors(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        fail("qualification_private_parent_invalid")
    for parent in path.parents:
        info = parent.lstat()
        # /tmp is usable only through a private root-owned descendant. Sticky
        # ownership prevents another uid renaming that descendant.
        writable = stat.S_IMODE(info.st_mode) & 0o022
        sticky_tmp = parent == Path("/tmp") and info.st_mode & stat.S_ISVTX
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, ROOT_UID}
            or (writable and not sticky_tmp)
        ):
            fail("qualification_private_parent_invalid")


def checked_read(path, maximum=MAX_PRIVATE, *, private=False):
    path = Path(path)
    safe_ancestors(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != ROOT_UID
            or info.st_nlink != 1
            or (private and stat.S_IMODE(info.st_mode) != 0o600)
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_size > maximum
        ):
            fail("qualification_private_file_invalid")
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        value = stream.read(maximum + 1)
        if (
            len(value) > maximum
            or identity(before) != identity(info)
            or identity(info) != identity(os.fstat(stream.fileno()))
            or identity(info) != identity(path.lstat())
        ):
            fail("qualification_private_file_changed")
        return value


def digest(path):
    return hashlib.sha256(checked_read(path)).hexdigest()


def private_read(path, maximum=MAX_PRIVATE):
    return checked_read(path, maximum, private=True)


def private_bytes(path, raw):
    safe_ancestors(path)
    if len(raw) > MAX_PRIVATE:
        fail("qualification_private_file_invalid")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def private_write(path, value):
    private_bytes(path, json.dumps(value, sort_keys=True).encode())


def configuration(path):
    value = json.loads(private_read(path, 16384))
    required = {
        "run_id",
        "hostname",
        "machine_id",
        "authorization_reference",
        "source",
        "source_sha",
        "baseline",
        "baseline_sha",
        "role",
    }
    if not isinstance(value, dict) or set(value) != required:
        fail("qualification_config_invalid")
    if any(not isinstance(item, str) or not item for item in value.values()):
        fail("qualification_config_invalid")
    if (
        not re.fullmatch(r"[a-f0-9]{32}", value["run_id"])
        or not re.fullmatch(r"[a-f0-9]{32}", value["machine_id"])
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", value["hostname"])
        or value["role"] not in {"upgrade", "clean"}
        or not 1 <= len(value["authorization_reference"]) <= 512
    ):
        fail("qualification_config_invalid")
    for name in ("source", "baseline"):
        path = Path(value[name])
        if (
            not path.is_absolute()
            or ".." in path.parts
            or not re.fullmatch(r"[a-f0-9]{40}", value[name + "_sha"])
        ):
            fail("qualification_source_invalid")
    return value


def environment():
    # Do not inherit TARGET, EXITLANE_*, BASH_ENV, functions, proxies or PYTHONPATH.
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def read_command(arguments, *, timeout=30):
    result = subprocess.run(
        arguments,
        env=environment(),
        capture_output=True,
        text=True,
        cwd="/",
        timeout=timeout,
        check=False,
    )
    if result.returncode or len(result.stdout) > 2_000_000:
        fail("qualification_observation_failed")
    return result.stdout.strip()


def verify_source(path, sha):
    source = Path(path)
    safe_ancestors(source)
    if (
        source.resolve() != source
        or source.stat().st_uid != ROOT_UID
        or source.stat().st_mode & 0o022
    ):
        fail("qualification_source_invalid")
    if read_command(["git", "-C", path, "rev-parse", "HEAD"]) != sha:
        fail("qualification_source_identity_mismatch")
    if read_command(
        [
            "git",
            "-C",
            path,
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignored=matching",
        ]
    ):
        fail("qualification_source_dirty")
    for directory, directories, files in os.walk(source, followlinks=False):
        if Path(directory) == source and ".git" in directories:
            gitdir = source / ".git"
            if gitdir.is_symlink():
                fail("qualification_source_invalid")
            directories.remove(".git")
        for name in directories + files:
            item = Path(directory) / name
            info = item.lstat()
            if (
                info.st_uid != ROOT_UID
                or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
            ):
                fail("qualification_source_invalid")
    return read_command(["git", "-C", path, "rev-parse", "HEAD^{tree}"])


def verify_entrypoint(source, entrypoint):
    expected = Path(source) / "scripts/qualification" / Path(entrypoint).name
    if (
        Path(entrypoint).absolute() != expected
        or Path(entrypoint).resolve() != expected
    ):
        fail("qualification_harness_source_mismatch")


def release_upgrade_gate(config):
    if config["role"] != "upgrade":
        return
    if config["baseline_sha"] != V1_TAG_SHA:
        fail("qualification_baseline_identity_mismatch")
    for name, expected in (("baseline", "1.0.0"), ("source", "1.0.1")):
        source = Path(config[name])
        version = tomllib.loads(
            checked_read(source / "backend/pyproject.toml").decode()
        )["project"]["version"]
        if version != expected:
            fail("qualification_release_version_mismatch")


def preflight(config):
    verify_entrypoint(config["source"], Path(__file__))
    verify_entrypoint(config["source"], Path(state.__file__))
    if (
        ROOT != Path("/")
        or os.geteuid() != 0
        or socket.gethostname() != config["hostname"]
    ):
        fail("qualification_host_identity_mismatch")
    if (ROOT / "etc/machine-id").read_text().strip() != config["machine_id"]:
        fail("qualification_host_identity_mismatch")
    if (ROOT / ".dockerenv").exists():
        fail("qualification_host_unsupported")
    release = (ROOT / "etc/os-release").read_text()
    if "ID=debian\n" not in release or 'VERSION_ID="13"' not in release:
        fail("qualification_host_unsupported")
    if read_command(["dpkg", "--print-architecture"]) != "amd64":
        fail("qualification_host_unsupported")
    if not (ROOT / "run/systemd/system").is_dir() or not stat.S_ISCHR(
        (ROOT / "dev/net/tun").stat().st_mode
    ):
        fail("qualification_host_unsupported")
    release_upgrade_gate(config)
    return {
        name: verify_source(config[name], config[name + "_sha"])
        for name in ("source", "baseline")
    }


def installed(source):
    """Compare both directions, excluding only interpreter caches generated at runtime."""
    source = Path(source)
    expected = source / "backend/exitlane"
    actual = ROOT / "opt/exitlane/backend/exitlane"

    def inventory(directory):
        safe_ancestors(directory)
        if not stat.S_ISDIR(directory.lstat().st_mode):
            fail("qualification_installed_source_mismatch")
        result = {}
        for current, directories, files in os.walk(directory, followlinks=False):
            for name in directories + files:
                item = Path(current) / name
                info = item.lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    fail("qualification_installed_source_mismatch")
                if "__pycache__" in item.parts or item.suffix == ".pyc":
                    continue
                if stat.S_ISREG(info.st_mode):
                    result[item.relative_to(directory).as_posix()] = digest(item)
        return result

    if not actual.is_dir() or inventory(expected) != inventory(actual):
        fail("qualification_installed_source_mismatch")
    import tomllib

    version = tomllib.loads((source / "backend/pyproject.toml").read_text())["project"][
        "version"
    ]
    package = json.loads(
        read_command(
            [
                str(ROOT / "opt/exitlane/venv/bin/python"),
                "-c",
                (
                    "import importlib.metadata,importlib.util,json;"
                    'print(json.dumps({"version":importlib.metadata.version("exitlane"),'
                    '"file":importlib.util.find_spec("exitlane").origin}))'
                ),
            ]
        )
    )
    if package.get("version") != version:
        fail("qualification_installed_package_mismatch")
    location = Path(package["file"]).parent
    venv = ROOT / "opt/exitlane/venv"
    if (
        not location.is_relative_to(venv)
        or location.name != "exitlane"
        or location.parent.name != "site-packages"
    ):
        fail("qualification_installed_package_mismatch")
    packaged = inventory(expected)
    # The existing build hook force-includes only these repository resources.
    # Never execute candidate Python to discover its expected contents.
    if (source / "backend/hatch_build.py").is_file():
        catalog = ast.parse(checked_read(expected / "documentation.py").decode())
        definitions = next(
            node.value
            for node in catalog.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "DOCUMENTS"
                for target in node.targets
            )
        )
        documents = [ast.literal_eval(item.args[2]) for item in definitions.elts]
        for relative in (
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
            *("docs/" + name for name in documents),
        ):
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                fail("qualification_installed_package_mismatch")
            packaged[relative] = digest(source / relative)
    if packaged != inventory(location):
        fail("qualification_installed_package_mismatch")
    for name in (
        "exitlane.service",
        "exitlane-killswitch.service",
        "exitlane-provider-egress.service",
        "exitlane-management-routing.service",
        "exitlane-provider-install-nordvpn.service",
        "exitlane-speedtest-install.service",
        "wg-quick@.service.d/exitlane.conf",
    ):
        if digest(source / "systemd" / name) != digest(
            ROOT / "etc/systemd/system" / name
        ):
            fail("qualification_installed_source_mismatch")
    for name in ("nordvpn", "speedtest"):
        if digest(source / "installer" / ("install-" + name + ".sh")) != digest(
            ROOT / "usr/local/libexec" / ("exitlane-install-" + name)
        ):
            fail("qualification_installed_source_mismatch")
    native_runtime()


def native_runtime():
    expected = {
        "EXITLANE_DATA_DIR": "/etc/exitlane",
        "EXITLANE_CONFIG_DIR": "/etc/exitlane",
        "EXITLANE_LOG_DIR": "/var/log/exitlane",
        "EXITLANE_RUNTIME": "native",
        "EXITLANE_PORT": "8787",
    }
    defaults = {}
    for line in checked_read(ROOT / "etc/default/exitlane").decode().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = shlex.split(line, comments=True)
        if len(fields) != 1 or "=" not in fields[0]:
            fail("qualification_native_paths_required")
        key, value = fields[0].split("=", 1)
        if key in defaults or "$" in value or "`" in value:
            fail("qualification_native_paths_required")
        defaults[key] = value
    for key, value in expected.items():
        if defaults.get(key, value) != value:
            fail("qualification_native_paths_required")
    if read_command(
        ["systemctl", "show", "exitlane.service", "--property=DropInPaths", "--value"]
    ):
        fail("qualification_native_paths_required")
    pid = read_command(
        ["systemctl", "show", "exitlane.service", "--property=MainPID", "--value"]
    )
    if not pid.isdecimal() or int(pid) <= 1:
        fail("qualification_health_failed")
    # procfs is kernel-owned; only fixed-value checks, never receipt/log its secrets.
    raw = (ROOT / "proc" / pid / "environ").read_bytes()
    if len(raw) > 1024 * 1024:
        fail("qualification_native_paths_required")
    active = dict(
        part.decode().split("=", 1) for part in raw.split(b"\0") if b"=" in part
    )
    if active.get("EXITLANE_HOST", "0.0.0.0") not in {"0.0.0.0", "127.0.0.1"}:
        fail("qualification_native_paths_required")
    for key, value in expected.items():
        if active.get(key, value) != value:
            fail("qualification_native_paths_required")


def healthy(*, timeout=30):
    """Wait for actual HTTP readiness within one stable systemd invocation."""
    deadline = time.monotonic() + timeout
    observed_identity = None
    previous_success = False
    while time.monotonic() < deadline:

        def observe():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail("qualification_health_deadline")
            value = read_command(
                [
                    "systemctl",
                    "show",
                    "exitlane.service",
                    "--property=ActiveState",
                    "--property=SubState",
                    "--property=MainPID",
                    "--property=InvocationID",
                ],
                timeout=min(2, remaining),
            )
            fields = dict(
                line.split("=", 1) for line in value.splitlines() if "=" in line
            )
            if (
                fields.get("ActiveState") != "active"
                or fields.get("SubState") != "running"
            ):
                return None
            if (
                not re.fullmatch("[a-f0-9]{32}", fields.get("InvocationID", ""))
                or not fields.get("MainPID", "").isdecimal()
                or int(fields["MainPID"]) <= 1
            ):
                return None
            return fields["InvocationID"], fields["MainPID"]

        success = False
        identities = []
        try:
            before = observe()
            if before is not None:
                identities.append(before)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    fail("qualification_health_deadline")
                value = json.loads(
                    read_command(
                        [
                            "curl",
                            "--disable",
                            "--noproxy",
                            "*",
                            "--fail",
                            "--silent",
                            "--max-time",
                            "2",
                            "http://127.0.0.1:8787/api/health",
                        ],
                        timeout=min(2, remaining),
                    )
                )
                after = observe()
                if after is not None:
                    identities.append(after)
                success = (
                    isinstance(value, dict)
                    and value.get("ok") is True
                    and after == before
                )
        except (QualificationError, OSError, ValueError, subprocess.SubprocessError):
            # Connection refusal while Type=simple starts Python is transient.
            success = False
        for identity in identities:
            if observed_identity is not None and identity != observed_identity:
                fail("qualification_health_service_replaced")
            observed_identity = identity
        if success and previous_success:
            return
        previous_success = success
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    fail("qualification_health_failed")


def nft_state():
    value = json.loads(read_command(["nft", "-j", "list", "ruleset"]))
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("nftables"), list)
        or any(not isinstance(item, dict) for item in value["nftables"])
    ):
        fail("qualification_nft_observation_invalid")

    def stable(item, *, counter=False):
        if isinstance(item, list):
            return [stable(child) for child in item]
        if isinstance(item, dict):
            return {
                key: (
                    0
                    if counter and key in {"bytes", "packets"}
                    else stable(child, counter=key == "counter")
                )
                for key, child in item.items()
                if key != "handle"
            }
        return item

    rules = [stable(item) for item in value["nftables"] if set(item) != {"metainfo"}]
    return hashlib.sha256(json.dumps(rules, sort_keys=True).encode()).hexdigest()


def rejected_restore_state():
    """Before/after control-plane invariance, never a protected packet proof.

    Counters are excluded by iptables-save default. Stage execution requires a
    quiescent guest; unrelated rule/route writers invalidate this observation.
    """
    commands = (
        [
            "systemctl",
            "show",
            "exitlane.service",
            "--property=InvocationID",
            "--property=ActiveState",
            "--property=SubState",
            "--property=MainPID",
        ],
        ["ip", "-4", "rule", "show"],
        ["ip", "-6", "rule", "show"],
        ["ip", "-4", "route", "show", "table", "all"],
        ["ip", "-6", "route", "show", "table", "all"],
        ["iptables-save"],
        ["ip6tables-save"],
    )
    observed = [
        hashlib.sha256(
            "\n".join(
                line
                for line in read_command(command).splitlines()
                if not line.startswith("#")
            ).encode()
        ).hexdigest()
        for command in commands
    ]
    staging = []
    for directory, patterns in (
        (ROOT / "etc", (".exitlane-*",)),
        (ROOT / "tmp", ("exitlane-*",)),
    ):
        for pattern in patterns:
            for item in sorted(directory.glob(pattern)):
                info = item.lstat()
                staging.append((str(item), info.st_ino, info.st_mode, info.st_mtime_ns))
    return {"observations": observed, "nft": nft_state(), "staging": staging}


class Run:
    def __init__(self, config):
        self.config = config
        self.directory = RUNS / config["run_id"]
        self.binding = hashlib.sha256(
            json.dumps(config, sort_keys=True).encode()
        ).hexdigest()
        self.harness = {
            name: digest(Path(__file__).with_name(name))
            for name in (
                "native_lifecycle.py",
                "native_lifecycle_state.py",
                "native_lifecycle_api.py",
            )
        }

    def open(self):
        for path in (RUNS, self.directory):
            safe_ancestors(path)
            if not path.exists():
                path.mkdir(mode=0o700)
            info = path.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != ROOT_UID
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                fail("qualification_run_directory_invalid")
        identity = self.directory / "identity.json"
        expected = {
            "config": self.binding,
            "harness": self.harness,
            "type": "native-guest",
        }
        if identity.exists():
            if json.loads(private_read(identity)) != expected:
                fail("qualification_run_identity_mismatch")
        else:
            if any(self.directory.iterdir()):
                fail("qualification_run_directory_not_empty")
            private_write(identity, expected)

    def dependency(self, stage):
        return {
            "seed": "baseline-install"
            if self.config["role"] == "upgrade"
            else "candidate-install",
            "rollback": "seed",
            "upgrade": "rollback",
            "idempotence": "upgrade" if self.config["role"] == "upgrade" else "seed",
            "backup": "idempotence",
            "restore": "backup",
        }.get(stage)

    def previous(self, name):
        path = self.directory / (name + ".json")
        if not path.exists():
            return False
        record = json.loads(private_read(path))
        if json.loads(private_read(self.directory / (name + ".started"))) != {
            "binding": self.binding
        }:
            fail("qualification_receipt_identity_mismatch")
        if (
            record.get("binding") != self.binding
            or record.get("harness") != self.harness
            or record.get("stage") != name
            or record.get("result") != "PASS"
            or record.get("type") != "native-guest-stage"
        ):
            fail("qualification_receipt_identity_mismatch")
        required = {
            "baseline-install": {"baseline-install.log"},
            "candidate-install": {"candidate-install.log"},
            "seed": {"fixture.json", "seed.snapshot", "api-seed.log"},
            "rollback": {
                "rollback-before.snapshot",
                "rollback-after.snapshot",
                "fault-marker",
                "rollback.log",
                "rollback-verify.log",
                "fixture.json",
            },
            "upgrade": {
                "upgrade-before.snapshot",
                "upgrade-after.snapshot",
                "upgrade-legacy-certificate.json",
                "upgrade.log",
                "upgrade-verify.log",
                "fixture.json",
            },
            "idempotence": {
                "idempotence-before.snapshot",
                "idempotence-after.snapshot",
                "idempotence.log",
                "idempotence-verify.log",
                "fixture.json",
            },
            "backup": {
                "backup.snapshot",
                "backup.elb",
                "passphrase",
                "fixture.json",
                "backup-create.log",
                "backup-inspect.log",
                "backup-verify.log",
            },
            "restore": {
                "restore-after.snapshot",
                "canary.snapshot",
                "wrong-passphrase-after.snapshot",
                "tampered-after.snapshot",
                "backup.elb",
                "passphrase",
                "fixture.json",
                "restore-valid.log",
                "restore-wrong-passphrase.log",
                "restore-tampered.log",
                "api-restored-login.log",
                "api-canary.log",
            },
        }[name]
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, dict) or not required <= artifacts.keys():
            fail("qualification_receipt_artifact_mismatch")
        for relative, expected in artifacts.items():
            item = self.directory / relative
            if (
                Path(relative).name != relative
                or relative in {"cookies", ".", ".."}
                or hashlib.sha256(private_read(item)).hexdigest() != expected
            ):
                fail("qualification_receipt_artifact_mismatch")
        dependency = self.dependency(name)
        if dependency:
            if not self.previous(dependency) or record.get("dependency") != {
                "stage": dependency,
                "sha256": digest(self.directory / (dependency + ".json")),
            }:
                fail("qualification_stage_dependency_invalid")
        elif record.get("dependency") is not None:
            fail("qualification_stage_dependency_invalid")
        return True

    def allowed(self, stage):
        if stage not in STAGES:
            fail("qualification_stage_invalid")
        for attempted in self.directory.glob("*.started"):
            name = attempted.stem
            private_read(attempted)
            if name not in STAGES or not self.previous(name):
                fail("qualification_prior_attempt_incomplete")
        if (self.directory / (stage + ".started")).exists() or (
            self.directory / (stage + ".json")
        ).exists():
            fail("qualification_stage_already_attempted")
        if (
            stage in {"rollback", "upgrade", "baseline-install"}
            and self.config["role"] != "upgrade"
        ):
            fail("qualification_stage_role_invalid")
        if stage == "candidate-install" and self.config["role"] != "clean":
            fail("qualification_stage_role_invalid")
        dependency = self.dependency(stage)
        if dependency and not self.previous(dependency):
            fail("qualification_stage_dependency_missing")

    def lock(self):
        path = self.directory / "stage.lock"
        safe_ancestors(path)
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != ROOT_UID
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                fail("qualification_lock_invalid")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def command(self, argv, label, *, stdin=None, expected=0, timeout=1800):
        if not re.fullmatch(r"[a-z][a-z-]+", label):
            fail("qualification_command_label_invalid")
        log = self.directory / (label + ".log")
        safe_ancestors(log)
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with (
            os.fdopen(fd, "wb") as output,
            subprocess.Popen(
                argv,
                env=environment(),
                cwd="/",
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            ) as process,
        ):
            deadline = time.monotonic() + timeout
            pending_input = stdin
            try:
                while True:
                    if time.monotonic() >= deadline:
                        fail("qualification_child_timeout")
                    if os.fstat(output.fileno()).st_size > MAX_PRIVATE:
                        fail("qualification_child_output_limit")
                    try:
                        process.communicate(
                            input=pending_input,
                            timeout=min(0.2, deadline - time.monotonic()),
                        )
                        break
                    except subprocess.TimeoutExpired:
                        pending_input = None
            finally:
                # Kill descendants retaining this process group even when
                # the main child has already exited.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            if os.fstat(output.fileno()).st_size > MAX_PRIVATE:
                fail("qualification_child_output_limit")
            if process.returncode != expected:
                fail("qualification_child_failed")
        return log

    def api(self, action):
        return self.command(
            [
                str(ROOT / "opt/exitlane/venv/bin/python"),
                str(Path(__file__).with_name("native_lifecycle_api.py")),
                action,
                str(self.directory),
            ],
            "api-" + action,
            timeout=120,
        )

    def snapshot(self, name):
        value = state.capture(ROOT)
        private_write(self.directory / (name + ".snapshot"), value)
        return value

    def compare(self, before, after, mode):
        if state.compare(before, after, mode):
            fail("qualification_state_not_preserved")

    def backup_cli(
        self, action, label, *, source="backup.elb", password="passphrase", expected=0
    ):
        return self.command(
            [
                str(ROOT / "usr/local/sbin/exitlane-cli"),
                "backup",
                action,
                str(self.directory / source),
                "--passphrase-file",
                str(self.directory / password),
            ],
            label,
            stdin=b"RESTORE EXITLANE\n" if action == "restore" else None,
            expected=expected,
        )

    def execute(self, stage):
        self.allowed(stage)
        private_write(self.directory / (stage + ".started"), {"binding": self.binding})
        existing = {p.name for p in self.directory.iterdir()}
        artifacts = []
        source = self.config["source"]
        baseline = self.config["baseline"]
        if stage in {"baseline-install", "candidate-install"}:
            if any(
                (ROOT / path).exists()
                for path in ("opt/exitlane", "etc/exitlane", "var/lib/exitlane")
            ):
                fail("qualification_clean_target_required")
            selected = baseline if stage == "baseline-install" else source
            artifacts.append(
                self.command(["bash", selected + "/installer/install-debian.sh"], stage)
            )
            installed(selected)
            healthy()
        elif stage == "seed":
            installed(baseline if self.config["role"] == "upgrade" else source)
            artifacts.append(self.api("seed"))
            self.snapshot("seed")
        elif stage in {"rollback", "upgrade", "idempotence"}:
            installed(baseline if stage in {"rollback", "upgrade"} else source)
            before = self.snapshot(stage + "-before")
            prior = self.dependency(stage)
            previous_snapshot = (
                "seed.snapshot" if prior == "seed" else prior + "-after.snapshot"
            )
            self.compare(
                json.loads(private_read(self.directory / previous_snapshot)),
                before,
                "preserved",
            )
            certificate = None
            if stage == "upgrade":
                certificate = state.legacy_certificate(ROOT, before)
                private_write(
                    self.directory / "upgrade-legacy-certificate.json", certificate
                )
            if stage == "rollback":
                marker = self.directory / "fault-marker"
                artifacts.append(
                    self.command(
                        [
                            "bash",
                            "-c",
                            FAULT,
                            "native-qualification",
                            source,
                            str(marker),
                        ],
                        stage,
                        expected=97,
                    )
                )
                if private_read(marker) != b"qualification_precommit_fault\n":
                    fail("qualification_fault_not_observed")
            else:
                started = time.time() if stage == "upgrade" else None
                artifacts.append(
                    self.command(
                        ["bash", source + "/installer/install-debian.sh"], stage
                    )
                )
            # systemd Type=simple may return before ASGI startup runs the migration.
            # /api/health only observes readiness; it never adopts legacy peer state.
            healthy()
            if stage == "upgrade":
                # Snapshot after startup, before peer/config APIs that may repair lazily.
                after = self.snapshot(stage + "-after")
                finished = time.time()
                if state.compare_v1_upgrade(
                    before, after, certificate, started, finished
                ):
                    fail("qualification_state_not_preserved")
            else:
                self.compare(
                    before,
                    self.snapshot(stage + "-after"),
                    "rollback" if stage == "rollback" else "preserved",
                )
            installed(baseline if stage == "rollback" else source)
            # Separate labels prevent reusing/overwriting API receipts across stages.
            artifacts.append(
                self.command(
                    [
                        str(ROOT / "opt/exitlane/venv/bin/python"),
                        str(Path(__file__).with_name("native_lifecycle_api.py")),
                        "verify",
                        str(self.directory),
                    ],
                    stage + "-verify",
                    timeout=120,
                )
            )
        elif stage == "backup":
            installed(source)
            self.compare(
                json.loads(private_read(self.directory / "idempotence-after.snapshot")),
                state.capture(ROOT),
                "preserved",
            )
            private_bytes(
                self.directory / "passphrase", secrets.token_urlsafe(48).encode()
            )
            self.snapshot("backup")
            for action in ("create", "inspect", "verify"):
                artifacts.append(self.backup_cli(action, "backup-" + action))
        elif stage == "restore":
            installed(source)
            before = json.loads(private_read(self.directory / "backup.snapshot"))
            self.compare(before, state.capture(ROOT), "preserved")
            artifacts.append(self.api("canary"))
            canary = self.snapshot("canary")
            for name in ("wrong-passphrase",):
                private_bytes(self.directory / name, secrets.token_urlsafe(48).encode())
            rejected_state = rejected_restore_state()
            artifacts.append(
                self.backup_cli(
                    "restore",
                    "restore-wrong-passphrase",
                    password="wrong-passphrase",
                    expected=2,
                )
            )
            self.compare(canary, self.snapshot("wrong-passphrase-after"), "preserved")
            if rejected_state != rejected_restore_state():
                fail("qualification_rejected_restore_mutated_runtime")
            damaged = bytearray(private_read(self.directory / "backup.elb"))
            damaged[-1] ^= 1
            private_bytes(self.directory / "tampered.elb", damaged)
            artifacts.append(
                self.backup_cli(
                    "restore", "restore-tampered", source="tampered.elb", expected=2
                )
            )
            self.compare(canary, self.snapshot("tampered-after"), "preserved")
            if rejected_state != rejected_restore_state():
                fail("qualification_rejected_restore_mutated_runtime")
            artifacts.append(self.backup_cli("restore", "restore-valid"))
            healthy()
            restored = self.snapshot("restore-after")
            self.compare(before, restored, "restore")
            if (
                canary["state_files"]["etc/default/exitlane"]
                != restored["state_files"]["etc/default/exitlane"]
            ):
                fail("qualification_restore_mutated_defaults")
            artifacts.append(self.api("restored-login"))
        # Freeze every newly produced file except mutable browser state; include
        # long-lived fixture/backup material in every subsequent dependent receipt.
        artifacts.extend(
            p
            for p in self.directory.iterdir()
            if p.name not in existing and p.name != "cookies"
        )
        artifacts.extend(
            self.directory / name
            for name in ("fixture.json", "backup.elb", "passphrase")
            if (self.directory / name).exists()
        )
        dependency = self.dependency(stage)
        record = {
            "type": "native-guest-stage",
            "stage": stage,
            "result": "PASS",
            "binding": self.binding,
            "harness": self.harness,
            "dependency": (
                {
                    "stage": dependency,
                    "sha256": digest(self.directory / (dependency + ".json")),
                }
                if dependency
                else None
            ),
            "artifacts": {p.name: digest(p) for p in artifacts},
            "scope": "synthetic inactive-provider native lifecycle only; no protected dataplane or live provider proof",
        }
        private_write(self.directory / (stage + ".json"), record)
        if not self.previous(stage):
            fail("qualification_receipt_invalid")
        return {
            "stage": stage,
            "result": "PASS",
            "type": "native-guest-stage",
            "source": self.config["source_sha"],
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        config = configuration(args.config)
        if not args.execute:
            print(
                json.dumps(
                    {
                        "type": "plan-only",
                        "stage": args.stage,
                        "source": config["source_sha"],
                        "hostname": config["hostname"],
                        "executed": False,
                    }
                )
            )
            return 0
        preflight(config)
        run = Run(config)
        run.open()
        fd = run.lock()
        try:
            print(json.dumps(run.execute(args.stage)))
        finally:
            os.close(fd)
        return 0
    except (
        QualificationError,
        state.SnapshotError,
        OSError,
        ValueError,
        KeyError,
        AssertionError,
        subprocess.SubprocessError,
    ):
        print(
            "qualification_failed; retain private run state and inspect before any further mutation",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
