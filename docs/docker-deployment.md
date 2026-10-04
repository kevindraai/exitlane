# Docker deployment

This is the v1 operator path for the ExitLane Docker appliance. Native Debian 13 amd64 remains
reference runtime. Docker v1 supports Mullvad, PIA and imported Proton WireGuard; native ExitLane
additionally supports NordVPN. NordVPN is unavailable inside Docker. Live commercial PIA/Proton
interoperability remains unqualified; synthetic qualification is not a live-provider claim.

Publication status: the stable `v1.0.0` source and official image are being delivered. Use the
commands below only after the [v1.0.0 release](https://github.com/kevindraai/exitlane/releases/tag/v1.0.0)
and its image/digest receipt are published. This guide does not assert that publication or final
image qualification has already completed.

## Prerequisites

Use Linux amd64, rootful Docker Engine **28 or newer**, Docker Compose **v2**, Python 3, Git and
curl. Run commands as an operator authorized to access that Docker daemon. The host kernel must
support TUN (`/dev/net/tun`), WireGuard and nftables; provision these host capabilities before
starting ExitLane. Docker Desktop, rootless Docker and other architectures are outside v1 support.

Choose the Docker host's actual IPv4 address on a trusted management LAN. The example below uses
`192.168.10.20`: replace it everywhere with your host's address. Restrict TCP/8787 to that management
network and allow UDP/51820 only for intended WireGuard peers. Verify Docker's actual forwarding
path as well as host firewall rules. Never expose management directly to the internet.

The appliance uses `NET_ADMIN`, TUN, a read-only root filesystem and one persistent volume.
It has no privileged mode, host network/PID, Docker socket or `SYS_ADMIN`. ExitLane manages its
container's nftables/routing; Docker owns host bridge/NAT. Preserve this Compose contract.

## Quick Start

Obtain the matching versioned deployment files and preflight from the stable source:

```bash
git clone --branch v1.0.0 --depth 1 https://github.com/kevindraai/exitlane.git exitlane-v1
cd exitlane-v1
```

Pull the official versioned image and resolve its immutable registry identity. Compare that
identity with the published release's digest receipt before proceeding:

```bash
docker pull ghcr.io/kevindraai/exitlane:v1.0.0
image_digest=$(docker image inspect ghcr.io/kevindraai/exitlane:v1.0.0 \
  --format '{{index .RepoDigests 0}}')
printf '%s\n' "$image_digest"
```

The expected identity has form `ghcr.io/kevindraai/exitlane@sha256:<64 hex characters>`.
The actual published digest must come from the release receipt; no placeholder is a valid pin.
The preflight intentionally requires an immutable digest rather than a mutable tag.
Persist the verified identity and explicit LAN bindings, and export them for preflight:

```bash
umask 077
cat > .env <<EOF_ENV
COMPOSE_PROJECT_NAME=exitlane
EXITLANE_IMAGE=$image_digest
EXITLANE_MANAGEMENT_BIND=192.168.10.20
EXITLANE_INGRESS_BIND=192.168.10.20
EXITLANE_PUBLIC_URL=http://192.168.10.20:8787
EXITLANE_TRUSTED_PROXIES=
EOF_ENV
set -a
. ./.env
set +a
python3 scripts/check_docker_appliance_host.py
docker compose -f docker/compose.appliance.yml up -d
```

Continue only if preflight reports `PASS`. Keep the project name and `.env` consistent for all
lifecycle commands: they select the same persistent volume. The official versioned image is
`ghcr.io/kevindraai/exitlane:v1.0.0`; the saved digest pins precisely the bytes you reviewed.
No `latest` alias is part of this deployment path.

| Variable | Meaning |
| --- | --- |
| `EXITLANE_IMAGE` | Official image identity; use its verified immutable registry digest. |
| `EXITLANE_MANAGEMENT_BIND` | Explicit host IPv4 for management TCP/8787. Default is loopback, not LAN access. |
| `EXITLANE_INGRESS_BIND` | Explicit host IPv4 for WireGuard UDP/51820, reachable by the router. |
| `EXITLANE_PUBLIC_URL` | Browser-facing origin, including scheme and port; direct-LAN example is above. |
| `EXITLANE_TRUSTED_PROXIES` | Verified immediate reverse-proxy peer addresses/CIDRs. Leave empty for direct HTTP. |

For HTTPS termination, follow the [reverse-proxy guide](deployment/reverse-proxy.md). Bind
management to loopback for a host-local proxy, set the external HTTPS public URL, and trust only
the actual immediate proxy peer. A Docker bridge gateway or an entire private subnet is not
implicitly trusted. Recheck login/MFA, HTTPS status and Secure cookies after recreation.

Verify startup:

```bash
docker compose -f docker/compose.appliance.yml ps
docker compose -f docker/compose.appliance.yml logs --tail=100 exitlane
curl --fail --silent --show-error http://192.168.10.20:8787/api/health
docker compose -f docker/compose.appliance.yml exec -T exitlane \
  python -m exitlane.container_entrypoint health
```

Open **http://192.168.10.20:8787** and complete first-run administrator setup and MFA. Configure
WireGuard ingress, import its client profile on the router, then configure and connect one supported
provider. Verify DNS and the expected VPN public exit from an actual routed client. HTTP health
proves management availability; it does not prove protected VPN delivery. Without a proven provider,
including after an explicit disconnect, protected Docker clients remain blocked with no plaintext
fallback. Management remains separate. An unhealthy status alone does not trigger Docker restart.

## Lifecycle and state

Run from the same checkout using the saved `.env`:

```bash
docker compose -f docker/compose.appliance.yml restart exitlane
docker compose -f docker/compose.appliance.yml stop exitlane
docker compose -f docker/compose.appliance.yml start exitlane
docker compose -f docker/compose.appliance.yml logs --tail=100 exitlane
docker compose -f docker/compose.appliance.yml exec -T exitlane \
  python -m exitlane.container_cli status
```

Repeat health/login and routed-client checks after lifecycle changes. Container startup must
prove provider state again; ambiguous or interrupted provider state stays blocked.

The named volume `exitlane_exitlane-state` mounts at `/data` with this project name. It contains
`config/secret.key`, `state/exitlane.db`, ingress/provider state, recovery metadata and encrypted
backups. Directories are root-owned mode 0700, files mode 0600. Database and key are one recovery
unit. Locate the actual Docker-managed host mountpoint with:

```bash
docker volume inspect exitlane_exitlane-state --format '{{.Mountpoint}}'
```

Do not edit files there or run two replicas against the volume. Container removal preserves it;
`docker compose down -v` destroys it and is not a recovery command. Keep recovery journals and
failed state for diagnosis; do not delete guards or regenerate a missing key to bypass refusal.
See the [state/recovery contract](docker-container-recovery.md).

## Backup, export, verify and restore

Use the supervisor for mutations. The following command prompts for a masked passphrase
(at least 12 characters) and returns the generated `.elbackup` basename:

```bash
docker compose -f docker/compose.appliance.yml exec exitlane \
  python -m exitlane.container_cli backup
```

Set `backup_name` to that exact returned basename, then verify the authenticated archive and
export it. Verification reads only the encrypted backup, not an independently mutable database:

```bash
backup_name=REPLACE_WITH_RETURNED_NAME.elbackup
docker compose -f docker/compose.appliance.yml exec exitlane \
  exitlane-cli backup verify "/data/backups/$backup_name"
install -d -m 0700 backups
docker compose -f docker/compose.appliance.yml cp \
  "exitlane:/data/backups/$backup_name" "backups/$backup_name"
chmod 0600 "backups/$backup_name"
```

Copy the encrypted export to a protected off-host location; retain the passphrase separately.
Never put it in argv, environment variables, shell history or logs. Backups contain sensitive
appliance data. Keep `.env`, matching Compose and exact previous image identity separately: those
host settings are not in the portable backup. See [backup format and limits](backup-and-restore.md).

For restore, schedule a traffic interruption and retain host console access. On a compatible
running appliance, put the verified encrypted backup in its private backup directory, enforce
root-only permissions and verify it again before supervisor restore:

```bash
docker compose -f docker/compose.appliance.yml cp \
  "backups/$backup_name" "exitlane:/data/backups/$backup_name"
docker compose -f docker/compose.appliance.yml exec -T exitlane \
  chmod 0600 "/data/backups/$backup_name"
docker compose -f docker/compose.appliance.yml exec exitlane \
  exitlane-cli backup verify "/data/backups/$backup_name"
docker compose -f docker/compose.appliance.yml exec exitlane \
  python -m exitlane.container_cli restore --name "$backup_name" --confirm 'RESTORE EXITLANE'
```

Use backups exported by this root-owned container; check imported files remain root-owned.
Restore validates and stages state under forwarding guards, revokes old browser sessions and
requires a fresh login/MFA. Verify settings, ingress identity, provider state and fresh routed-client
DNS/egress; reconnect explicitly when required. Retain the original backup until recovery passes.
A failed restore retains protection and recovery evidence. Never bypass startup refusal to restore.

## Upgrade and rollback

Before upgrading, create, verify and export a backup. Record the current digest, `.env`, matching
Compose and release notes. Pull the newer explicit version, compare its digest with its release
receipt, and change only `EXITLANE_IMAGE` in `.env` to that verified digest. Obtain any required
matching versioned Compose/preflight changes described by that release. Then:

```bash
set -a
. ./.env
set +a
python3 scripts/check_docker_appliance_host.py
docker compose -f docker/compose.appliance.yml pull exitlane
docker compose -f docker/compose.appliance.yml up -d exitlane
```

Keep the same project name and volume, and repeat health, login/MFA, persisted-settings and
protected-client checks. Do not run the Debian installer inside Docker.

Layout 1 currently declares schema read/write interval `[1,1]`. Rollback can reuse the volume
only if the previous image accepts its current schema/state. Restore the previous digest in `.env`,
use matching Compose/preflight, and recreate as above. If state is incompatible, preserve the
failed volume and recover the verified pre-upgrade backup on a separate clean volume using the
matching compatible image; isolate the old gateway so two copies never use one provider identity.
A previous image tag alone is not proof of cross-release rollback compatibility.

## Security and support

Keep full scan/SBOM/provenance evidence and the source/image/digest binding from the release.
Supported fixes and concrete application/security/isolation defects block release. Reviewed Debian
OS findings with no supported fix remain transparently recorded residual platform risks, with
package/version/CVE, applicability and mitigations retained. They are not hidden or severity-adjusted.
See [SECURITY](../SECURITY.md) and the release's risk receipt for the exact published image findings.

The standalone `docker/Dockerfile` and `docker/docker-compose.yml` are development-only surfaces.
Use `docker/compose.appliance.yml` for this supported appliance path. Kernel/host configuration,
trusted management access and real routed-client validation remain operator responsibilities.
