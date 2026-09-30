#!/usr/bin/env python3
"""Create a new, privileged ExitLane LXC on a Proxmox VE host.

The Debian installer remains the only in-container installer. This helper never
adopts, repairs, stops, or destroys an existing guest.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
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
PVE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class PreflightError(RuntimeError):
    """A host, input, or resource precondition failed."""


def run(
    *args: str, check: bool = True, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
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
        "--ref", default="v0.3.0-rc.3", help="published ExitLane release tag"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="show planned commands; make no changes"
    )
    parser.add_argument(
        "--yes", action="store_true", help="accept the displayed creation plan"
    )
    args = parser.parse_args(argv)
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
    net = f"name=eth0,bridge={bridge},ip={args.ip},ip6=manual"
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
            "pct", "exec", str(ctid), "--", "apt-get",
            "-o", "Acquire::Retries=2", "-o", "APT::Update::Error-Mode=any", "update",
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
            if not address.is_loopback and not address.is_unspecified and not address.is_link_local:
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
            route = " ".join(routing.stdout.split())[:200] if successful(routing) else "unavailable"
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
                "_apt resolver access", "runuser", "-u", "_apt", "--", "test", "-r", "/etc/resolv.conf"
            )
            passed = (successful(tun) and bool(ips) and route.startswith("default ")
                      and bool(servers) and successful(readable))
            for hostname in ("deb.debian.org", "security.debian.org", "github.com"):
                dns = guest(
                    f"_apt DNS {hostname}", "runuser", "-u", "_apt", "--",
                    "getent", "ahostsv4", hostname,
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


def main(
    argv: list[str] | None = None,
    config_dir: Path = Path("/etc/pve/lxc"),
    bridge_root: Path = Path("/sys/class/net"),
) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    ctid, template, commands, download = plan(args, config_dir, bridge_root)
    print(
        f"New privileged Debian 13 amd64 LXC: CTID {ctid}, {args.cores} CPU, "
        f"{args.memory} MiB RAM, {args.disk} GiB disk"
    )
    print(f"Template: {template}" + (" (download required)" if download else ""))
    create = commands[int(download)]
    print(f"Hostname: {args.hostname}; storage: {create[create.index('--rootfs') + 1]}")
    print(f"Network: {create[create.index('--net0') + 1]}")
    print(f"DNS: {args.dns or 'PVE host default'}; pool: {args.pool or 'none'}")
    print(f"Startup: {args.startup or 'default'}; on boot: yes; TUN: yes")
    print(f"ExitLane release: {args.ref}")
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
    creation_attempted = False
    try:
        if download:
            run(*commands[0], timeout=900)
            require(
                template in run("pveam", "list", template.split(":")[0]).stdout,
                "Downloaded template is missing",
            )
        # Template download can take minutes; repeat essential checks immediately
        # before pct create. The command itself remains collision-protected.
        recheck_plan()
        offset = int(download)
        creation_attempted = True
        run(*commands[offset], timeout=900)
        with (config_dir / f"{ctid}.conf").open("a", encoding="utf-8") as config:
            for line in TUN_LINES:
                config.write(line + "\n")
        run(*commands[offset + 1])
        address = wait_ready(ctid)
        for command in commands[offset + 2 :]:
            run(*command, timeout=900)
        print(f"ExitLane management: http://{address}:8787")
        print("Complete the first-run wizard on the trusted management network.")
        return 0
    except (KeyboardInterrupt, Exception):
        if creation_attempted:
            print(
                f"CTID {ctid} may have been created or partially allocated and was not deleted. "
                "Inspect pct config/status and storage, and "
                "the guest's ExitLane service logs; this helper never destroys it.",
                file=sys.stderr,
            )
        raise


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
