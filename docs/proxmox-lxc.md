# Proxmox LXC

The qualified container baseline for ExitLane 0.3.0-rc.3 is **Debian 13, `amd64`, privileged LXC**.
Unprivileged containers, other Debian releases and other architectures are not supported release
targets. ExitLane runs natively inside the container and needs systemd, WireGuard, nftables and
permission to administer its network namespace.

## Create the container

Release qualification uses 2 vCPUs, 2 GiB RAM and a 16 GiB disk. These are a reference configuration,
not a guaranteed throughput target. Allow additional storage for encrypted backups and local
installer recovery snapshots.

Run this one-liner as root **on the PVE host**, with an interactive terminal:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/kevindraai/exitlane/main/installer/proxmox.sh)"
```

The ExitLane launcher creates a **new** privileged Debian 13 amd64 LXC. It never adopts,
repairs or destroys an existing guest. Choose **Default settings** for 2 CPUs, 2048 MiB RAM,
16 GiB disk, hostname `exitlane`, DHCP on `vmbr0` and start on boot. The engine discovers a
free cluster-wide CTID, active root/template storage and a PVE-managed Debian 13 template.
**Advanced settings** exposes CTID, hostname, storage, template storage, bridge, static IPv4/CIDR,
gateway, DNS, VLAN, CPU, memory, disk, pool and startup ordering. Empty answers use engine defaults.

New published helpers advertise a side-effect-free bootstrap capability and own the interactive
installer themselves. Recommended settings retain the appliance defaults; Advanced groups container,
network and access choices. Until such a helper is published, the launcher keeps the compatible
older-tag menu. It never substitutes provisioning code from `main`.

### Guest access and installation output

In new tagged installers, both modes offer an optional masked, confirmed console root password and
SSH public-key selection: discover a host public key, paste a bare public key, read a public-key
file, or skip. Discovered keys are shown by type, fingerprint and comment, with duplicates removed.
Private keys and option-prefixed `authorized_keys` entries are rejected; restrictions are never
silently stripped to grant unrestricted root access. No password is generated or printed.

The console password and ExitLane's web administrator are separate credentials. A console password
alone does not install SSH; if the template already provides SSH, that explicit console-password
choice reconciles SSH to key-only authentication. Requesting a key or explicitly enabling password SSH installs OpenSSH
in the new Debian guest and configures its policy. Key-only SSH is the default; Advanced can
explicitly enable SSH password authentication with a configured root password. If all guest login
credentials are skipped, the installer confirms that PVE-managed container access remains the
recovery path. SSH instructions appear only when SSH is configured.

Standard output shows stage progress and suppresses normal package output. Verbose additionally
streams child output; Quiet is intended for explicit-flag automation. Every confirmed provisioning
run records stages, release, CTID, non-secret argv and streamed subprocess output in a root-only
log under `/var/log/exitlane-proxmox/`. Per-run output is capped at 32 MiB while the child continues
to be drained; logs are retained for diagnosis, with host log rotation/retention left to the operator.
Failures show a bounded tail and inspection commands while
retaining the guest. Password transfer uses stdin, with no plaintext password in argv, environment,
plan, log or ordinary temporary file. Local root can still inspect live process memory.

The existing application onboarding remains authoritative for timezone; the helper does not copy
the PVE host timezone. Startup ordering and inherited/local DNS remain explicit plan facts.

For automation with a newly published helper, `--ssh-public-key-file` accepts public keys only and
`--output standard|verbose|quiet` controls output. `--interactive` starts the built-in terminal UI;
limited/narrow terminals use plain output. Root password entry remains interactive and masked.

The tagged Python engine validates and displays one canonical plan before asking for confirmation.
The default answer is no. The published rc.3 engine requires typing `CREATE`; newer engines use
`y` at `[y/N]`. There is no separate dry-run prerequisite or second confirmation. No container,
template download or guest package operation starts before confirmation. Keep management on a
trusted network; the final URL opens the first-run wizard.

### Release selection and trust

The moving `main` launcher only resolves the release and collects arguments. Its **recommended**
channel selects the highest semantic `vX.Y.Z` or `vX.Y.Z-rc.N` version among the first 100 published
GitHub releases; a stable tag sorts above an RC of the same version. RCs are intentionally eligible
while ExitLane is in its release-candidate phase, and are labelled in the terminal. GitHub's
`/releases/latest` excludes prereleases and drafts and is not ExitLane's channel contract.
The current releases have RC tags but GitHub `prerelease=false`; tag syntax therefore matters.
A future stable-only policy requires an explicit reviewed resolver change. Drafts and arbitrary
refs are never accepted. API/network/validation failures stop the invocation.

An explicit published release can be selected without changing the script:

```bash
EXITLANE_VERSION=v0.3.0-rc.3 \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/kevindraai/exitlane/main/installer/proxmox.sh)"
```

The helper is fetched **from that exact tag** and invoked with `--ref` set to the **same tag**;
the guest clones and installs that tag. Releases without the helper fail closed. The launcher
never substitutes `main` or a different helper version. Engine improvements merged on `main`
become available only when included in a new published release.

The convenient one-liner trusts a mutable project GitHub script as root, then the project's
published tag and GitHub HTTPS delivery. Project release discipline forbids tag replacement,
but existing GitHub releases are not platform-enforced immutable. A repository compromise or
maintainer tag change is outside this integrity check's protection. Downloads fail on HTTP errors,
are limited to 30 seconds/2 MiB and must be nonempty. Root-only temporary files are removed on
normal exit, error and handled interruption (SIGKILL/power loss can leave files in `/tmp`).
The private download umask is scoped to the bootstrap. The engine runs with umask `022`,
so PVE-generated public guest configuration remains readable by APT's `_apt` sandbox user.
The helper's Git blob digest and size are checked against GitHub contents metadata for the same
tag. This catches accidental corruption or mismatches; metadata and payload have the **same trust
origin**, so this is not an independent signature. A same-origin checksum manifest would add no
new authentication and is not added.

For inspect-first operation, download and review the launcher before execution:

```bash
curl -fsSL --proto '=https' --connect-timeout 10 --max-time 30 \
  -o proxmox.sh https://raw.githubusercontent.com/kevindraai/exitlane/main/installer/proxmox.sh
less proxmox.sh
bash proxmox.sh
```

Review the selected tag's Python helper and Debian installer as well when auditing the complete
root provisioning chain. ExitLane owns that chain; no Community Scripts code or update service
is fetched or sourced. The terminal UX takes inspiration from the
[Community Scripts launcher](https://github.com/community-scripts/ProxmoxVE/blob/main/ct/rackula.sh).
Release API semantics are documented by [GitHub](https://docs.github.com/en/rest/releases/releases).

### Automation and diagnosis

The independently testable Python helper remains available from a reviewed tagged checkout:

```bash
python3 installer/create-proxmox-lxc.py --ref v0.3.0-rc.3 --dry-run
python3 installer/create-proxmox-lxc.py --ref v0.3.0-rc.3 --yes
```

Use `--help` for the advanced flags described above. The Bash launcher deliberately requires a
TTY; it accepts no raw command options and never passes `--yes`. The engine uses explicit argv,
refuses occupied IDs and appends only the two documented TUN entries. New engine releases use a
single 90-second deadline for two complete successful rounds: running state, TUN, usable IPv4,
default route, resolver configuration, `_apt` access to that configuration, and usable IPv4 DNS
answers for `deb.debian.org`, `security.debian.org` and `github.com` **as `_apt`**. The guest address,
route and configured resolvers must remain unchanged between the successful rounds. Package
operations start only after this gate; actual repository fetching remains a separate hard gate.
APT update uses `Acquire::Retries=2` and `APT::Update::Error-Mode=any`, so even transient repository
fetch failures abort rather than continuing on warning-only/stale indexes. These engine changes
require a new published tag; the existing rc.3 engine retains its earlier readiness/APT behavior.
On partial failure, inspect
`pct config <CTID>`, `pct status <CTID>` and guest logs. No automatic deletion occurs.
New engine releases revalidate frozen resource choices after confirmation and template download;
changed resources require a fresh plan rather than silently changing the approved allocation.

Deterministic launcher/engine tests do not prove actual PVE creation. The first public creation
attempt exposed a root-DNS/APT-readiness false positive; investigation and qualification are
tracked in [deployment wave #87](https://github.com/kevindraai/exitlane/issues/87).
A separate disposable NLFoundry LXC reproduced the same failure when `resolv.conf` was readable
only by root, and installed rc.3 successfully after restoring ordinary public file permissions.
That alternative provisioner is **not** proof of public launcher creation. Public launcher →
tagged engine → create → boot → install qualification remains outstanding.
The helper uses supported [PVE container commands](https://pve.proxmox.com/pve-docs/pct.1.html)
and [storage commands](https://pve.proxmox.com/pve-docs/pvesm.1.html).

#### Root lookup succeeds, APT fails

Do not substitute public DNS servers merely because APT reports a resolution failure. Root's
`getent` can succeed while `_apt` cannot read `/etc/resolv.conf`. Proxmox's guest configuration
writer requests mode `0644`, subject to its process umask; inheriting bootstrap umask `077` can
produce mode `0600`. The launcher and new engine isolate that boundary rather than changing
the operator's DNS settings. A bounded diagnostic comparison is:

```bash
pct exec <CTID> -- stat -c '%a %U:%G %n' /etc/resolv.conf /etc/hosts
pct exec <CTID> -- getent ahostsv4 deb.debian.org
pct exec <CTID> -- runuser -u _apt -- test -r /etc/resolv.conf
pct exec <CTID> -- runuser -u _apt -- getent ahostsv4 deb.debian.org
```

Preserve failed guests and capture their configuration before repair. The reproduced permission
failure explains this specific false-positive boundary; it does not establish the failed guest's
actual permissions without inspecting that guest. Private/local resolvers remain supported.
The relevant contracts are documented in the
[Proxmox configuration writer](https://github.com/proxmox/pve-container/blob/master/src/PVE/LXC/Setup/Base.pm),
[Proxmox file writer](https://github.com/proxmox/pve-common/blob/master/src/PVE/File.pm), and Debian 13's
[APT update error handling](https://manpages.debian.org/trixie/apt/apt-get.8.en.html) and
[bounded fetch retries](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html).

### Manual creation

Create a privileged container from a Debian 13 `amd64` template. Give it a reachable address on
the trusted management network, working DNS and outbound internet access. Keep the Proxmox console
available during initial setup and network recovery.

On the Proxmox host, add these entries to `/etc/pve/lxc/<CTID>.conf` while the container is stopped:

```ini
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

Start the container and verify inside it:

```bash
cat /etc/os-release
dpkg --print-architecture
test -c /dev/net/tun
systemctl --version
```

The OS must report Debian 13 and the architecture must be `amd64`. The installer also checks that
it can create a WireGuard interface. A failed capability check must be resolved in the container
configuration before continuing; installing another VPN application does not supply those privileges.

## Install and connect

Follow the [deployment guide](deployment.md) for the tagged installation command and first-run
checks. Permit the selected WireGuard ingress UDP port from the router to the container; the
default is `51820`. Limit TCP port `8787` to the trusted management network or an explicitly trusted
reverse proxy. Preserve access to Proxmox independently of the ExitLane data path.

For Mullvad, use the [direct WireGuard provider guide](mullvad.md). Do not run the Mullvad app daemon
alongside ExitLane's direct integration. NordVPN uses its own managed Linux client.

## Backup and migration

Keep an encrypted [appliance backup](backup-and-restore.md) outside the container. A Proxmox snapshot
is useful for host recovery but does not replace verification of ExitLane's database, master key,
provider identity and client configuration.

Never start a clone and its original gateway simultaneously with the same restored Mullvad or
WireGuard identity. Shut down the original before migration and validate the restored appliance
before redirecting client traffic. Deleting the original Mullvad device by signing out also revokes
the identity held in its backups.
