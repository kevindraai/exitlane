#!/usr/bin/env python3
"""Qualify installed provider TLS in one immutable local appliance image.

No pulls, publication, ports, mounts, host network mutation or provider account.
The only container writes are ephemeral private fixture keys in bounded tmpfs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

SOURCE = "https://github.com/kevindraai/exitlane"
ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
SHA = re.compile(r"[a-f0-9]{40}\Z")
CONDITIONS = {"valid": None, "unknown_ca": 20, "wrong_hostname": 62, "expired": 10}
CLIENTS = {"mullvad", "pia_public", "pia_pinned"}


class QualificationError(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise QualificationError(code)


def image_identity(facts, image, revision):
    labels = facts.get("Config", {}).get("Labels") or {}
    require(facts.get("Id") == image, "tls_image_identity_mismatch")
    require(
        facts.get("Os") == "linux" and facts.get("Architecture") == "amd64",
        "tls_image_platform_mismatch",
    )
    require(
        labels.get("org.opencontainers.image.source") == SOURCE
        and labels.get("org.opencontainers.image.revision") == revision
        and labels.get("org.exitlane.runtime") == "container",
        "tls_image_source_mismatch",
    )
    version = labels.get("org.opencontainers.image.version", "")
    require(
        re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?", version),
        "tls_image_version_invalid",
    )
    require(not facts["Config"].get("Volumes"), "tls_image_volume_forbidden")
    return {
        "image_id": image,
        "source": SOURCE,
        "source_revision": revision,
        "version": version,
    }


def container_contract(facts, image):
    host = facts.get("HostConfig", {})
    require(facts.get("Image") == image, "tls_container_image_mismatch")
    require(
        host.get("NetworkMode") == "none"
        and host.get("ReadonlyRootfs") is True
        and host.get("Privileged") is False
        and host.get("CapDrop") == ["ALL"]
        and not host.get("CapAdd")
        and host.get("PidMode") != "host"
        and not host.get("Binds")
        and not host.get("Devices")
        and not host.get("PortBindings")
        and not facts.get("Mounts"),
        "tls_container_boundary_mismatch",
    )
    require(
        host.get("SecurityOpt") == ["no-new-privileges:true"]
        or host.get("SecurityOpt") == ["no-new-privileges"],
        "tls_container_boundary_mismatch",
    )
    require(
        host.get("Tmpfs") == {"/tmp": "rw,noexec,nosuid,mode=0700,size=8m"}
        and host.get("PidsLimit") == 32
        and host.get("Memory") == 134217728
        and host.get("NanoCpus") == 1000000000,
        "tls_container_limits_mismatch",
    )


def safe_probe_receipt(raw):
    """Accept only the fixed public receipt schema, never echo unknown output."""
    require(len(raw) <= 16384, "tls_probe_receipt_invalid")
    value = json.loads(raw)
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "type",
            "scope",
            "checks",
            "openssl",
            "python",
            "clients_sha256",
            "result",
            "code",
        },
        "tls_probe_receipt_invalid",
    )
    require(
        value["type"] == "provider-tls-loopback"
        and value["scope"]
        == "synthetic loopback TLS only; no live provider, routing, packet, host or support acceptance"
        and value["result"] in {"PASS", "FAIL"}
        and (
            value["code"] is None
            if value["result"] == "PASS"
            else value["code"] in {"tls_probe_failed", "tls_positive_control_failed"}
        ),
        "tls_probe_receipt_invalid",
    )
    require(
        isinstance(value["python"], str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["python"])
        and isinstance(value["openssl"], str)
        and re.fullmatch(r"OpenSSL [0-9A-Za-z .()+-]{1,80}", value["openssl"]),
        "tls_probe_receipt_invalid",
    )
    hashes = value["clients_sha256"]
    require(
        isinstance(hashes, dict)
        and set(hashes) == {"mullvad", "pia_api"}
        and all(
            isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item)
            for item in hashes.values()
        ),
        "tls_probe_receipt_invalid",
    )
    rows = value["checks"]
    require(isinstance(rows, list) and len(rows) <= 12, "tls_probe_receipt_invalid")
    observed = set()
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row)
            == {"client", "condition", "result", "http_requests", "verify_code"},
            "tls_probe_receipt_invalid",
        )
        client, condition = row["client"], row["condition"]
        require(
            isinstance(client, str)
            and isinstance(condition, str)
            and client in CLIENTS
            and condition in CONDITIONS
            and (client, condition) not in observed
            and row["result"] == "PASS"
            and type(row["http_requests"]) is int
            and row["http_requests"] == (1 if condition == "valid" else 0)
            and row["verify_code"] == CONDITIONS[condition],
            "tls_probe_receipt_invalid",
        )
        observed.add((client, condition))
    if value["result"] == "PASS":
        require(len(observed) == 12, "tls_probe_receipt_incomplete")
    return value


class Harness:
    def __init__(self, image, revision, docker_config):
        require(
            ID.fullmatch(image) and SHA.fullmatch(revision),
            "tls_immutable_identity_required",
        )
        self.image, self.revision, self.docker_config = image, revision, docker_config
        self.name = "exitlane-tls-" + uuid.uuid4().hex

    def docker(self, *args, data=None, timeout=30):
        # An explicit local daemon and empty config prevent credential/context or
        # proxy environment inheritance. No Docker access is given to the image.
        result = subprocess.run(
            [
                "docker",
                "--host",
                "unix:///var/run/docker.sock",
                "--config",
                str(self.docker_config),
                *args,
            ],
            input=data,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(self.docker_config),
                "LANG": "C.UTF-8",
            },
        )
        require(len(result.stdout) <= 1024 * 1024, "tls_docker_output_invalid")
        return result

    def checked(self, *args, **kwargs):
        result = self.docker(*args, **kwargs)
        require(result.returncode == 0, "tls_docker_operation_failed")
        return result.stdout

    def run(self):
        facts = json.loads(self.checked("image", "inspect", self.image))[0]
        identity = image_identity(facts, self.image, self.revision)
        probe = Path(__file__).with_name("container_tls_probe.py").read_text()
        require(len(probe.encode()) < 65536, "tls_probe_source_invalid")
        receipt = {
            "type": "exact-image-provider-tls",
            **identity,
            "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "probe_sha256": hashlib.sha256(probe.encode()).hexdigest(),
        }
        try:
            self.checked(
                "create",
                "--name",
                self.name,
                "--pull",
                "never",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,mode=0700,size=8m",
                "--memory",
                "128m",
                "--cpus",
                "1",
                "--pids-limit",
                "32",
                "--no-healthcheck",
                "--log-driver",
                "none",
                "--entrypoint",
                "/usr/bin/env",
                "-i",
                self.image,
                "-i",
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "HOME=/tmp",
                "python",
                "-I",
                "-B",
                "-",
            )
            container = json.loads(self.checked("inspect", self.name))[0]
            container_contract(container, self.image)
            outcome = self.docker(
                "start", "--attach", "--interactive", self.name, data=probe, timeout=120
            )
            receipt["probe"] = safe_probe_receipt(outcome.stdout)
            receipt["result"] = (
                "PASS"
                if outcome.returncode == 0 and receipt["probe"]["result"] == "PASS"
                else "FAIL"
            )
            return receipt
        finally:
            require(
                self.docker("rm", "--force", self.name).returncode == 0,
                "tls_cleanup_failed",
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image", required=True, help="immutable local sha256 image ID; no tag or pull"
    )
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="exitlane-tls-docker-") as directory:
            value = Harness(args.image, args.source_sha, Path(directory)).run()
        print(json.dumps(value, sort_keys=True))
        return 0 if value["result"] == "PASS" else 1
    except Exception:  # noqa: BLE001 - terminal fixed-error output boundary
        # Raw Docker/probe stdout, stderr and exception chains are never emitted.
        print(
            json.dumps(
                {
                    "type": "exact-image-provider-tls",
                    "result": "FAIL",
                    "code": "tls_qualification_failed",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
