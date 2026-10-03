#!/usr/bin/env python3
"""Create a new, privileged ExitLane LXC on a Proxmox VE host.

The Debian installer remains the only in-container installer. This helper never
adopts, repairs, stops, or destroys an existing guest.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import selectors
import shlex
import shutil
import struct
import subprocess
import sys
import time
import warnings
from collections import deque
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY = "https://github.com/kevindraai/exitlane.git"
TUN_LINES = (
    "lxc.cgroup2.devices.allow: c 10:200 rwm",
    "lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file",
)
TEMPLATE_PATTERN = re.compile(
    r"debian-13-standard_[A-Za-z0-9.+_-]+_amd64\.tar\.(?:zst|xz|gz)$"
)
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RELEASE_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?$")
INSTALL_LOG = None
KEY_COMMENTS: dict[str, str] = {}
LOG_DIRECTORY = Path("/var/log/exitlane-proxmox")
PVE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class PreflightError(RuntimeError):
    """A host, input, or resource precondition failed."""


def run(
    *args: str, check: bool = True, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    if INSTALL_LOG is not None:
        return INSTALL_LOG.execute(args, check=check, timeout=timeout)
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": PVE_PATH, "HOME": "/root", "LC_ALL": "C"},
        # PVE-generated public guest configuration must remain readable by _apt.
        # Do not inherit a caller's private bootstrap/download umask.
        umask=0o022,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def identifier(value: str, label: str) -> str:
    require(bool(IDENTIFIER.fullmatch(value)), f"Invalid {label}: {value!r}")
    return value


def ipv4(value: str, label: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise PreflightError(f"Invalid {label}: {value!r}") from exc


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ctid", type=int, help="free cluster-wide CTID; default: PVE next ID"
    )
    parser.add_argument("--hostname", default="exitlane")
    parser.add_argument(
        "--storage",
        help="root filesystem storage; default: first active rootdir storage",
    )
    parser.add_argument(
        "--template-storage",
        help="template storage; default: first active vztmpl storage",
    )
    parser.add_argument("--bridge", help="host bridge; default: vmbr0 if present")
    parser.add_argument("--ip", default="dhcp", help="dhcp or static IPv4/CIDR")
    parser.add_argument("--gateway", help="required with static IPv4")
    parser.add_argument(
        "--dns", help="IPv4 DNS resolver; default: PVE host configuration"
    )
    parser.add_argument("--vlan", type=int, help="optional VLAN tag, 1–4094")
    parser.add_argument("--cores", type=int, default=2)
    parser.add_argument("--memory", type=int, default=2048, help="MiB")
    parser.add_argument("--disk", type=int, default=16, help="GiB")
    parser.add_argument("--pool", help="existing PVE resource pool")
    parser.add_argument(
        "--startup", help="PVE startup order, for example order=2,up=30"
    )
    parser.add_argument(
        "--ref", default="v0.3.0-rc.4", help="published ExitLane release tag"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="show planned commands; make no changes"
    )
    parser.add_argument(
        "--yes", action="store_true", help="accept the displayed creation plan"
    )
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument(
        "--output", choices=("standard", "verbose", "quiet"), default="standard"
    )
    parser.add_argument("--ssh-public-key-file", type=Path)
    parser.add_argument("--ssh-password-auth", action="store_true")
    args = parser.parse_args(argv)
    args.root_password = None
    args.ssh_keys = []
    if args.ssh_public_key_file:
        args.ssh_keys = load_keys(args.ssh_public_key_file)
        require(bool(args.ssh_keys), "No valid public keys in file")
    require(
        args.ctid is None or 100 <= args.ctid <= 999999999, "CTID must be 100–999999999"
    )
    require(
        bool(HOSTNAME.fullmatch(args.hostname)), "Hostname must be a single DNS label"
    )
    require(1 <= args.cores <= 128, "CPU count must be 1–128")
    require(512 <= args.memory <= 262144, "Memory must be 512–262144 MiB")
    require(8 <= args.disk <= 4096, "Disk must be 8–4096 GiB")
    require(args.vlan is None or 1 <= args.vlan <= 4094, "VLAN tag must be 1–4094")
    require(
        bool(RELEASE_TAG.fullmatch(args.ref)),
        "Use an explicit published vX.Y.Z or vX.Y.Z-rc.N tag",
    )
    if args.ip == "dhcp":
        require(args.gateway is None, "--gateway requires static --ip")
    else:
        try:
            interface = ipaddress.IPv4Interface(args.ip)
        except ValueError as exc:
            raise PreflightError("Static --ip must be an IPv4 address/CIDR") from exc
        require(
            interface.ip
            not in (
                interface.network.network_address,
                interface.network.broadcast_address,
            ),
            "Static IP cannot be network or broadcast address",
        )
        require(args.gateway is not None, "Static --ip requires --gateway")
        ipv4(args.gateway, "gateway")
    if args.dns:
        ipv4(args.dns, "DNS resolver")
    if args.startup:
        require(
            bool(
                re.fullmatch(
                    r"order=[0-9]+(?:,up=[0-9]+)?(?:,down=[0-9]+)?", args.startup
                )
            ),
            "Invalid PVE startup ordering",
        )
    if args.pool:
        identifier(args.pool, "pool")
    for value, label in (
        (args.storage, "storage"),
        (args.template_storage, "template storage"),
        (args.bridge, "bridge"),
    ):
        if value:
            identifier(value, label)
    return args


def check_host(
    config_dir: Path = Path("/etc/pve/lxc"), tun_device: Path = Path("/dev/net/tun")
) -> None:
    require(os.geteuid() == 0, "Run as root on a Proxmox VE host")
    require(
        platform.machine() in ("x86_64", "amd64"), "Only amd64 PVE hosts are supported"
    )
    require(config_dir.is_dir(), "PVE LXC configuration directory is absent")
    require(
        tun_device.is_char_device(), "The PVE host has no /dev/net/tun character device"
    )
    for command in ("pveversion", "pvesh", "pct", "pveam", "pvesm", "ip"):
        require(
            shutil.which(command, path=PVE_PATH) is not None,
            f"Required PVE command unavailable: {command}",
        )
    require(run("pveversion").returncode == 0, "PVE is unavailable")


def active_storages(content: str) -> list[str]:
    output = run("pvesm", "status", "--content", content, "--enabled", "1").stdout
    return [
        parts[0]
        for line in output.splitlines()[1:]
        if (parts := line.split()) and len(parts) >= 3 and parts[2] == "active"
    ]


def free_ctid(ctid: int | None) -> int:
    if ctid is None:
        value = run("pvesh", "get", "/cluster/nextid").stdout.strip()
        require(value.isdecimal(), "PVE returned an invalid next CTID")
        ctid = int(value)
    require(100 <= ctid <= 999999999, "PVE returned an unsupported CTID")
    # The cluster API checks both containers and VMs, including other nodes.
    result = run("pvesh", "get", "/cluster/nextid", "--vmid", str(ctid), check=False)
    require(
        result.returncode == 0,
        f"CTID {ctid} already exists or cluster availability is unknown",
    )
    return ctid


def select_template(storage: str) -> tuple[str, bool]:
    installed = []
    for line in run("pveam", "list", storage).stdout.splitlines():
        fields = line.split(maxsplit=1)
        if not fields:
            continue
        volume = fields[0]
        if volume.startswith(f"{storage}:vztmpl/") and TEMPLATE_PATTERN.fullmatch(
            volume.split("/")[-1]
        ):
            installed.append(volume)
    if installed:
        return max(installed), False
    available = []
    for line in run("pveam", "available", "--section", "system").stdout.splitlines():
        fields = line.split()
        if (
            len(fields) >= 2
            and fields[0] == "system"
            and TEMPLATE_PATTERN.fullmatch(fields[1])
        ):
            available.append(fields[1])
    require(bool(available), "No PVE-managed Debian 13 amd64 template is available")
    return f"{storage}:vztmpl/{max(available)}", True


def plan(
    args: argparse.Namespace,
    config_dir: Path = Path("/etc/pve/lxc"),
    bridge_root: Path = Path("/sys/class/net"),
) -> tuple[int, str, list[list[str]], bool]:
    check_host(config_dir)
    ctid = free_ctid(args.ctid)
    require(
        not (config_dir / f"{ctid}.conf").exists(),
        "Refusing existing container configuration",
    )
    root_storages = active_storages("rootdir")
    template_storages = active_storages("vztmpl")
    require(bool(root_storages), "No active rootdir storage")
    require(bool(template_storages), "No active template storage")
    storage = args.storage or root_storages[0]
    template_storage = args.template_storage or template_storages[0]
    require(
        storage in root_storages, f"Storage {storage!r} lacks active rootdir capability"
    )
    require(
        template_storage in template_storages,
        f"Storage {template_storage!r} lacks active template capability",
    )
    bridge = args.bridge or "vmbr0"
    require(
        (bridge_root / bridge / "bridge").is_dir(), f"Bridge {bridge!r} is unavailable"
    )
    if args.pool:
        require(
            run("pvesh", "get", f"/pools/{args.pool}", check=False).returncode == 0,
            f"Pool {args.pool!r} does not exist",
        )
    template, download = select_template(template_storage)
    # Leave IPv6 unconfigured. Explicit ip6=manual makes PVE emit a second
    # inet6 stanza; Debian ifupdown2 merges it with inet DHCP and waits for
    # DHCPv6 even on an IPv4-only network, blocking networking.service.
    net = f"name=eth0,bridge={bridge},ip={args.ip}"
    if args.gateway:
        net += f",gw={args.gateway}"
    if args.vlan:
        net += f",tag={args.vlan}"
    create = [
        "pct",
        "create",
        str(ctid),
        template,
        "--arch",
        "amd64",
        "--ostype",
        "debian",
        "--unprivileged",
        "0",
        # PVE requires nesting for systemd's service mount namespaces. Keep
        # the installed service isolation rather than weakening its units.
        "--features",
        "nesting=1",
        "--hostname",
        args.hostname,
        "--cores",
        str(args.cores),
        "--memory",
        str(args.memory),
        "--rootfs",
        f"{storage}:{args.disk}",
        "--net0",
        net,
        "--onboot",
        "1",
    ]
    if args.dns:
        create += ["--nameserver", args.dns]
    if args.pool:
        create += ["--pool", args.pool]
    if args.startup:
        create += ["--startup", args.startup]
    commands = []
    if download:
        commands.append(
            ["pveam", "download", template_storage, template.split("/")[-1]]
        )
    commands += [
        create,
        ["pct", "start", str(ctid)],
        [
            "pct",
            "exec",
            str(ctid),
            "--",
            "apt-get",
            "-o",
            "Acquire::Retries=2",
            "-o",
            "APT::Update::Error-Mode=any",
            "update",
        ],
        ["pct", "exec", str(ctid), "--", "apt-get", "install", "--yes", "git"],
        [
            "pct",
            "exec",
            str(ctid),
            "--",
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            args.ref,
            REPOSITORY,
            "/root/exitlane-source",
        ],
        [
            "pct",
            "exec",
            str(ctid),
            "--",
            "bash",
            "/root/exitlane-source/installer/install-debian.sh",
        ],
    ]
    if args.ssh_keys or args.ssh_password_auth:
        commands[int(download) + 3].append("openssh-server")
    return ctid, template, commands, download


def wait_ready(ctid: int, timeout_seconds: float = 90, interval: float = 2.0) -> str:
    """Require two stable rounds, including DNS as the package sandbox user."""
    deadline = time.monotonic() + timeout_seconds
    last: dict[str, str] = {}
    stable = 0
    previous: tuple[str, str, str] | None = None

    def probe(label: str, *command: str) -> subprocess.CompletedProcess[str] | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last[label] = "deadline exhausted"
            return None
        try:
            observation = run(*command, check=False, timeout=min(5, remaining))
        except subprocess.TimeoutExpired:
            last[label] = "timed out"
            return None
        last[label] = f"rc={observation.returncode}"
        return observation

    def guest(label: str, *command: str) -> subprocess.CompletedProcess[str] | None:
        return probe(label, "pct", "exec", str(ctid), "--", *command)

    def successful(observation: subprocess.CompletedProcess[str] | None) -> bool:
        return observation is not None and observation.returncode == 0

    def addresses(text: str) -> list[str]:
        found = []
        for field in text.split():
            try:
                address = ipaddress.IPv4Address(field)
            except ipaddress.AddressValueError:
                continue
            if (
                not address.is_loopback
                and not address.is_unspecified
                and not address.is_link_local
            ):
                found.append(str(address))
        return found

    while time.monotonic() < deadline:
        running = probe("running", "pct", "status", str(ctid))
        passed = successful(running) and "status: running" in running.stdout
        address = route = resolvers = "unavailable"
        if passed:
            tun = guest("TUN", "test", "-c", "/dev/net/tun")
            ip = guest("IPv4", "hostname", "-I")
            ips = addresses(ip.stdout) if successful(ip) else []
            address = ips[0] if ips else "unavailable"
            routing = guest("default route", "ip", "-4", "route", "show", "default")
            route = (
                " ".join(routing.stdout.split())[:200]
                if successful(routing)
                else "unavailable"
            )
            resolver = guest("resolver configuration", "cat", "/etc/resolv.conf")
            servers = []
            if successful(resolver):
                for line in resolver.stdout.splitlines():
                    fields = line.split()
                    if len(fields) >= 2 and fields[0] == "nameserver":
                        try:
                            servers.append(str(ipaddress.ip_address(fields[1])))
                        except ValueError:
                            pass
            resolvers = ", ".join(servers) if servers else "unavailable"
            readable = guest(
                "_apt resolver access",
                "runuser",
                "-u",
                "_apt",
                "--",
                "test",
                "-r",
                "/etc/resolv.conf",
            )
            passed = (
                successful(tun)
                and bool(ips)
                and route.startswith("default ")
                and bool(servers)
                and successful(readable)
            )
            for hostname in ("deb.debian.org", "security.debian.org", "github.com"):
                dns = guest(
                    f"_apt DNS {hostname}",
                    "runuser",
                    "-u",
                    "_apt",
                    "--",
                    "getent",
                    "ahostsv4",
                    hostname,
                )
                resolved = successful(dns) and bool(addresses(dns.stdout))
                if successful(dns) and not resolved:
                    last[f"_apt DNS {hostname}"] = "rc=0 but no usable IPv4 answer"
                passed = passed and resolved
        last["guest IPv4"] = address
        last["guest default route"] = route
        last["configured resolvers"] = resolvers
        snapshot = (address, route, resolvers)
        stable = stable + 1 if passed and snapshot == previous else int(bool(passed))
        previous = snapshot if passed else None
        if stable >= 2:
            return address
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(interval, remaining))
    facts = "; ".join(f"{label}: {value}" for label, value in last.items())
    raise PreflightError(
        f"CTID {ctid} did not reach stable running/TUN/IPv4/route/_apt DNS readiness "
        f"within {timeout_seconds:g}s; {facts}. Guest preserved; inspect with "
        f"pct config {ctid}, pct status {ctid}, and pct exec {ctid} -- "
        "stat -c '%a %U:%G %n' /etc/resolv.conf. No packages installed."
    )


def public_key(line: str) -> str:
    """Accept bare public keys; deliberately reject authorized_keys options."""
    require(len(line) <= 8192, "Public key is too large")
    fields = line.strip().split()
    require(
        len(fields) >= 2
        and fields[0]
        in (
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ),
        "Expected a bare SSH public key (no private keys or options)",
    )
    try:
        blob = base64.b64decode(fields[1], validate=True)
        size = struct.unpack(">I", blob[:4])[0]
        require(
            blob[4 : 4 + size].decode("ascii") == fields[0], "SSH key type mismatch"
        )
        # ssh-keygen validates the full wire encoding, not merely the prefix.
        validation = subprocess.run(
            ["ssh-keygen", "-lf", "/dev/stdin"],
            input=(fields[0] + " " + fields[1] + "\n").encode(),
            capture_output=True,
            timeout=5,
            check=False,
            env={"PATH": PVE_PATH},
        )
        require(validation.returncode == 0, "Invalid SSH public key encoding")
    except (ValueError, UnicodeError, struct.error, binascii.Error) as exc:
        raise PreflightError("Invalid SSH public key") from exc
    key = " ".join(fields[:2])
    comment = " ".join(fields[2:])
    comment = "".join(c for c in comment if c.isprintable())[:80]
    if comment:
        KEY_COMMENTS.setdefault(key, comment)
    return key


def key_label(key: str) -> str:
    kind, encoded = key.split()
    digest = (
        base64.b64encode(hashlib.sha256(base64.b64decode(encoded)).digest())
        .decode()
        .rstrip("=")
    )
    label = f"{kind} SHA256:{digest}"
    return label + (" " + KEY_COMMENTS[key] if key in KEY_COMMENTS else "")


def load_keys(path: Path) -> list[str]:
    require(
        path.is_file() and path.stat().st_size <= 65536,
        "Public-key file is missing or too large",
    )
    keys = []
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key = public_key(line)
        if key not in keys:
            keys.append(key)
    return keys


def discover_keys(home: Path = Path("/root/.ssh")) -> list[str]:
    keys = []
    for path in sorted(home.glob("*.pub")) + [home / "authorized_keys"]:
        if not path.is_file() or path.stat().st_size > 65536:
            continue
        for line in path.read_text().splitlines():
            try:
                key = public_key(line)
            except PreflightError:
                continue  # Options and malformed lines are never copied or weakened.
            if key not in keys:
                keys.append(key)
    return keys


def interactive(args: argparse.Namespace) -> argparse.Namespace:
    require(
        sys.stdin.isatty() and sys.stdout.isatty(),
        "Interactive mode requires a terminal",
    )
    check_host()
    width = shutil.get_terminal_size((80, 24)).columns
    title = "ExitLane — Proxmox LXC Installer"
    if width >= 50 and os.environ.get("TERM", "dumb") not in ("", "dumb"):
        print("┌" + "─" * 46 + "┐\n│" + title.center(46) + "│\n└" + "─" * 46 + "┘")
    else:
        print(title)
    print(
        f"Smart egress for every network\n✓ Proxmox VE · amd64 · TUN\n✓ Published ExitLane {args.ref}"
    )
    print(
        "Installation\n  1. Recommended: 2 CPU · 2048 MiB · 16 GiB · DHCP\n  2. Advanced\n  3. Exit"
    )
    mode = input("Choose [1]: ").strip() or "1"
    require(
        mode in ("1", "2"),
        "Creation cancelled" if mode == "3" else "Invalid installation mode",
    )
    if mode == "2":
        values = ["--ref", args.ref]
        for group, fields in (
            (
                "Container",
                (
                    "ctid",
                    "hostname",
                    "cores",
                    "memory",
                    "disk",
                    "storage",
                    "template-storage",
                    "pool",
                    "startup",
                ),
            ),
            ("Network", ("bridge", "vlan", "ip", "gateway", "dns")),
        ):
            print(group + " (Enter keeps defaults)")
            for field in fields:
                value = input(field + ": ").strip()
                if value:
                    values += ["--" + field, value]
        args = parse_args(values)
        args.interactive = True
    print(
        "Access — Linux recovery credentials are separate from ExitLane web onboarding"
    )
    if input("Configure console root password? [y/N]: ").lower() == "y":
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                password = getpass.getpass("Console root password: ")
                confirmation = getpass.getpass("Confirm password: ")
        except getpass.GetPassWarning as exc:
            raise PreflightError("Masked password input unavailable") from exc
        require(
            bool(password)
            and len(password) <= 1024
            and password == confirmation
            and not any(c in password for c in "\n\r\x00"),
            "Password confirmation failed or unsupported characters",
        )
        args.root_password = password
        password = confirmation = None
    keys = discover_keys()
    print(
        "SSH public key: 1. Existing host public key  2. Paste  3. Public-key file  4. None"
    )
    choice = input("Choose [4]: ").strip() or "4"
    require(choice in ("1", "2", "3", "4"), "Invalid SSH key choice")
    if choice == "1":
        require(bool(keys), "No safe public keys discovered; select paste or file")
        for index, key in enumerate(keys, 1):
            print(f"  {index}. {key_label(key)}")
        index = input("Key number: ")
        require(
            index.isdecimal() and 1 <= int(index) <= len(keys), "Invalid key selection"
        )
        args.ssh_keys = [keys[int(index) - 1]]
    elif choice == "2":
        args.ssh_keys = [public_key(input("Bare SSH public key: "))]
    elif choice == "3":
        args.ssh_keys = load_keys(Path(input("Public-key file: ")))
        require(bool(args.ssh_keys), "No public key found")
    if mode == "2":
        print(
            "SSH password authentication expands remote authentication exposure; default is key only."
        )
        args.ssh_password_auth = (
            input("Explicitly enable SSH password authentication? [y/N]: ").lower()
            == "y"
        )
    output = input("Output: 1. Standard  2. Verbose [1]: ").strip() or "1"
    require(output in ("1", "2"), "Invalid output mode")
    args.output = "verbose" if output == "2" else "standard"
    return args


class InstallationLog:
    """Stream child output to a private host log and retain only bounded tails."""

    def __init__(self, ctid: int, ref: str, output: str, directory: Path | None = None):
        directory = directory or LOG_DIRECTORY
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(
            not directory.is_symlink() and directory.stat().st_uid == os.geteuid(),
            "Unsafe installation log directory",
        )
        directory.chmod(0o700)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
        self.path = directory / f"ct{ctid}-{stamp}.log"
        fd = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        self.file = os.fdopen(fd, "w", encoding="utf-8")
        self.output = output
        self.tail = deque(maxlen=30)
        self.current = "Preflight"
        self.bytes_logged = 0
        self.truncated = False
        self.last_code = None
        self.file.write(f"CTID {ctid}; ExitLane release {ref}\n")

    def stage(self, label: str) -> None:
        self.current = label
        self.tail.clear()
        self.last_code = None
        self.file.write(f"\nSTAGE {label}\n")
        self.file.flush()
        if self.output != "quiet":
            print(f"[●] {label}", flush=True)

    def execute(self, command, check=True, timeout=30, secret_input=None):
        self.file.write("COMMAND " + shlex.join(command) + "\n")
        self.file.flush()
        captured = deque()
        count = 0
        with subprocess.Popen(
            command,
            stdin=subprocess.PIPE if secret_input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": PVE_PATH, "HOME": "/root", "LC_ALL": "C"},
            umask=0o022,
        ) as child:
            try:
                deadline = time.monotonic() + timeout
                pending = memoryview(secret_input or b"")
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ, "output")
                    if secret_input is not None:
                        os.set_blocking(child.stdin.fileno(), False)
                        selector.register(child.stdin, selectors.EVENT_WRITE, "input")
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            child.kill()
                            child.wait()
                            raise subprocess.TimeoutExpired(command, timeout)
                        for key, _ in selector.select(min(remaining, 0.2)):
                            if key.data == "input":
                                try:
                                    written = os.write(key.fd, pending[:4096])
                                    pending = pending[written:]
                                except BrokenPipeError:
                                    pending = pending[len(pending) :]
                                if not pending:
                                    selector.unregister(key.fileobj)
                                    child.stdin.close()
                                continue
                            chunk = os.read(key.fd, 4096)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            # Access configuration emits no stdout/stderr; suppress all
                            # output on that path, including unexpected tool diagnostics.
                            if secret_input is not None:
                                continue
                            text = chunk.decode(errors="replace")
                            if self.bytes_logged < 32 * 1024 * 1024:
                                self.file.write(text)
                                self.bytes_logged += len(chunk)
                            elif not self.truncated:
                                self.file.write(
                                    "\nOUTPUT LOG LIMIT reached; further output omitted, child still drained.\n"
                                )
                                self.truncated = True
                            self.tail.append(text[-4096:])
                            captured.append(text)
                            count += len(text)
                            while count > 65536 and captured:
                                count -= len(captured.popleft())
                            if self.output == "verbose":
                                print(text, end="", flush=True)
                code = child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except BaseException:
                child.kill()
                child.wait()
                raise
        self.last_code = code
        self.file.write(f"\nEXIT {code}\n")
        self.file.flush()
        stdout = "".join(captured)
        if check and code:
            raise subprocess.CalledProcessError(code, command, output=stdout)
        return subprocess.CompletedProcess(command, code, stdout, "")

    def failure(self):
        self.file.write(f"FAILED {self.current}\n")
        print(
            f"✗ {self.current} failed\nExit code: {self.last_code if self.last_code is not None else 'unavailable'}\nLast output:\n"
            + "".join(self.tail)[-4000:],
            file=sys.stderr,
        )

    def close(self):
        self.file.close()


# stdin contains credentials, never command arguments/environment/files. Guest
# output is suppressed even on error. Use Python framing rather than shell text.
ACCESS_SCRIPT = """import json,os,pathlib,subprocess,sys
settings=json.load(sys.stdin)
password=settings.pop("password",None)
if password:
 p=subprocess.run(["chpasswd"],input="root:"+password+"\\n",text=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
 password=None
 if p.returncode: sys.exit(1)
keys=settings["keys"]
ssh=settings["ssh"]
existing_ssh=pathlib.Path("/usr/sbin/sshd").is_file()
if ssh:
 d=pathlib.Path("/root/.ssh"); d.mkdir(mode=0o700,exist_ok=True); d.chmod(0o700)
 f=d/"authorized_keys"; f.write_text("\\n".join(keys)+"\\n"); f.chmod(0o600)
if ssh or existing_ssh:
 c=pathlib.Path("/etc/ssh/sshd_config.d/00-exitlane-access.conf")
 c.write_text("PermitRootLogin "+("yes" if settings["password_auth"] else "prohibit-password")+"\\nPasswordAuthentication "+("yes" if settings["password_auth"] else "no")+"\\nKbdInteractiveAuthentication no\\nPubkeyAuthentication yes\\nAuthenticationMethods "+("any" if settings["password_auth"] else "publickey")+"\\n")
 pathlib.Path("/run/sshd").mkdir(mode=0o755,exist_ok=True)
 subprocess.run(["sshd","-t"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 effective=subprocess.run(["sshd","-T","-C","user=root,host=localhost,addr=127.0.0.1"],check=True,capture_output=True,text=True)
 facts=dict(line.split(None,1) for line in effective.stdout.splitlines() if " " in line)
 wanted={"passwordauthentication":"yes" if settings["password_auth"] else "no","kbdinteractiveauthentication":"no","pubkeyauthentication":"yes","permitrootlogin":"yes" if settings["password_auth"] else "without-password","authenticationmethods":"any" if settings["password_auth"] else "publickey"}
 if any(facts.get(k)!=v for k,v in wanted.items()): sys.exit(1)
 subprocess.run(["systemctl","enable","--now","ssh"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 # Restart reacquires systemd's listening socket; SIGHUP reload can lose the
 # inherited descriptor on a socket-activated Debian template.
 subprocess.run(["systemctl","restart","ssh"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
"""


def configure_access(ctid: int, args: argparse.Namespace) -> None:
    payload = json.dumps(
        {
            "password": args.root_password,
            "keys": args.ssh_keys,
            "ssh": bool(args.ssh_keys or args.ssh_password_auth),
            "password_auth": args.ssh_password_auth,
        }
    ).encode()
    args.root_password = None
    try:
        INSTALL_LOG.execute(
            ("pct", "exec", str(ctid), "--", "python3", "-c", ACCESS_SCRIPT),
            timeout=30,
            secret_input=payload,
        )
    finally:
        payload = None


def main(
    argv: list[str] | None = None,
    config_dir: Path = Path("/etc/pve/lxc"),
    bridge_root: Path = Path("/sys/class/net"),
) -> int:
    global INSTALL_LOG
    selected = sys.argv[1:] if argv is None else argv
    if selected == ["--bootstrap-capabilities"]:
        print(json.dumps({"schema": 1, "interactive": True}))
        return 0
    args = parse_args(selected)
    if args.interactive:
        args = interactive(args)
    require(
        not args.ssh_password_auth or bool(args.root_password),
        "SSH password authentication requires an interactive console password",
    )
    ctid, template, commands, download = plan(args, config_dir, bridge_root)
    create = commands[int(download)]
    if args.output != "quiet" or not args.yes or args.dry_run:
        print(
            f"New privileged Debian 13 amd64 LXC: CTID {ctid}, {args.cores} CPU, "
            f"{args.memory} MiB RAM, {args.disk} GiB disk"
        )
        print(f"Template: {template}" + (" (download required)" if download else ""))
        print(
            f"Hostname: {args.hostname}; storage: {create[create.index('--rootfs') + 1]}"
        )
        print(f"Network: {create[create.index('--net0') + 1]}")
        print(f"DNS: {args.dns or 'PVE host default'}; pool: {args.pool or 'none'}")
        print(
            f"Startup: {args.startup or 'default'}; on boot: yes; TUN: yes; systemd nesting: yes"
        )
        print(f"ExitLane release: {args.ref}")
        print("Access:")
        print(
            "  Console root password: "
            + ("configured" if args.root_password else "not configured")
        )
        for key in args.ssh_keys:
            print("  SSH key: " + key_label(key))
        print(
            "  SSH password: "
            + (
                "enabled"
                if args.ssh_password_auth
                else "disabled (when SSH configured)"
            )
        )
        if not args.interactive:
            print("Planned operations:")
            for command in commands:
                print("  " + shlex.join(command))
            print(
                "  append only the two documented TUN/device lines to the new CT configuration"
            )
            print(
                "  wait up to 90s for running state, TUN, IPv4 and DNS before package/install steps"
            )
    if args.dry_run:
        print("Dry run: no resources changed.")
        return 0
    if args.interactive and not (
        args.root_password or args.ssh_keys or args.ssh_password_auth
    ):
        require(
            input(
                "No guest login credential will be configured. PVE host/container access remains your recovery path. Continue? [y/N]: "
            ).lower()
            == "y",
            "Creation cancelled",
        )
    if not args.yes:
        require(
            sys.stdin.isatty(),
            "Interactive confirmation required; pass --yes after reviewing --dry-run",
        )
        require(
            input("Create this new container? [y/N]: ").strip().lower() == "y",
            "Creation cancelled",
        )
    # Recheck immediately before mutation. pct itself also refuses an occupied ID.
    free_ctid(ctid)
    require(not (config_dir / f"{ctid}.conf").exists(), "CTID became occupied")
    # Resolve discovery defaults once. Revalidation must never silently select
    # another CTID, storage, bridge or template after the operator confirms.
    frozen = argparse.Namespace(**vars(args))
    frozen.ctid = ctid
    frozen.storage = create[create.index("--rootfs") + 1].split(":")[0]
    frozen.template_storage = template.split(":")[0]
    frozen.bridge = (
        create[create.index("--net0") + 1].split(",bridge=")[1].split(",")[0]
    )

    def recheck_plan() -> None:
        _, new_template, new_commands, new_download = plan(
            frozen, config_dir, bridge_root
        )
        require(
            new_template == template
            and new_commands[int(new_download) :] == commands[int(download) :],
            "PVE resources changed after confirmation; rerun to review a new plan",
        )

    recheck_plan()
    INSTALL_LOG = InstallationLog(ctid, args.ref, args.output)
    creation_attempted = False
    try:
        if download:
            INSTALL_LOG.stage("Debian 13 template")
            run(*commands[0], timeout=900)
            require(
                template in run("pveam", "list", template.split(":")[0]).stdout,
                "Downloaded template is missing",
            )
        # Template download can take minutes; repeat essential checks immediately
        # before pct create. The command itself remains collision-protected.
        recheck_plan()
        offset = int(download)
        INSTALL_LOG.stage("Container creation")
        creation_attempted = True
        run(*commands[offset], timeout=900)
        INSTALL_LOG.stage("TUN configuration")
        with (config_dir / f"{ctid}.conf").open("a", encoding="utf-8") as config:
            for line in TUN_LINES:
                config.write(line + "\n")
        INSTALL_LOG.stage("Starting container")
        run(*commands[offset + 1])
        INSTALL_LOG.stage("IPv4, route and stable _apt DNS")
        address = wait_ready(ctid)
        for label, command in zip(
            (
                "Debian repositories",
                "Installing prerequisites",
                "Downloading ExitLane",
                "Installing ExitLane",
            ),
            commands[offset + 2 :],
            strict=True,
        ):
            INSTALL_LOG.stage(label)
            run(*command, timeout=900)
        if args.root_password or args.ssh_keys or args.ssh_password_auth:
            INSTALL_LOG.stage("Guest access configuration")
            configure_access(ctid, args)
        INSTALL_LOG.stage("Verifying service")
        run(
            "pct",
            "exec",
            str(ctid),
            "--",
            "systemctl",
            "is-active",
            "--quiet",
            "exitlane.service",
        )
        INSTALL_LOG.stage("Health check")
        run(
            "pct",
            "exec",
            str(ctid),
            "--",
            "curl",
            "--fail",
            "--silent",
            "--max-time",
            "10",
            "http://127.0.0.1:8787/api/health",
        )
        INSTALL_LOG.stage("Installation complete")
        print(f"Container CT{ctid} · ExitLane {args.ref} · {address}")
        if args.ssh_keys or args.ssh_password_auth:
            print(
                f"SSH: root@{address} ("
                + ("password enabled" if args.ssh_password_auth else "public key only")
                + ")"
            )
        print(f"ExitLane management: http://{address}:8787")
        print("Complete the first-run wizard on the trusted management network.")
        return 0
    except (KeyboardInterrupt, Exception):
        INSTALL_LOG.failure()
        if creation_attempted:
            print(
                f"CTID {ctid} may have been created or partially allocated and was not deleted. "
                "Inspect pct config/status and storage, and "
                "the guest's ExitLane service logs; this helper never destroys it.",
                file=sys.stderr,
            )
        raise
    finally:
        args.root_password = None
        print(f"Installation log: {INSTALL_LOG.path}")
        INSTALL_LOG.close()
        INSTALL_LOG = None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        PreflightError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as exc:
        print(f"ExitLane PVE helper: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
            if detail:
                print(detail[-4000:], file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted; any created container was retained.", file=sys.stderr)
        sys.exit(130)
