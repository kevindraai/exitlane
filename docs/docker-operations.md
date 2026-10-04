# Docker operations

Use the [Docker deployment Quick Start](docker-deployment.md#quick-start) for versioned files,
verified official-image digest, explicit LAN bindings, setup and lifecycle commands.
The v1 support matrix is fixed; verify stable image publication and exact-image qualification
in the [v1 release receipts](release-notes/1.0.0.md#release-and-image-receipts) before deploying.
Native Debian 13 amd64 remains reference runtime. The development Compose is a separate surface.

## Capabilities and protected traffic

The container offers the shared WebUI, authentication, MFA, sessions, WireGuard ingress,
Activity, diagnostics and encrypted backup/restore. Mullvad, PIA and imported Proton use
ExitLane-owned WireGuard. Their synthetic container qualification does not establish live
commercial-provider interoperability; PIA and Proton live qualification remains outstanding.
Stock NordVPN is unavailable in Docker; its native Debian integration is unchanged.

Protected clients either use a proven VPN path or remain blocked. This applies during startup,
provider changes, disconnect and recovery, including when no provider is configured. IPv6
protected traffic is blocked; general direct-provider IPv6 egress is unavailable. Management
access stays on its separate route. A healthy WebUI does not prove VPN egress.

Host reboot/shutdown, application restart buttons, host systemd and package management,
native in-place upgrades, host timezone changes and Speedtest are unavailable. Resource
metrics describe the container. Use the Docker host's administration tools for container
lifecycle; the application has no Docker socket or authority over the host.

## Start and access the appliance

Use the [Docker deployment Quick Start](docker-deployment.md#quick-start). It provides the
exact v1.0.0 source checkout, official versioned image and digest verification, saved `.env`,
explicit host LAN bindings, immutable-image preflight and Compose startup commands.
Use Linux amd64, rootful Engine >=28 and Compose v2 with kernel WireGuard/nftables and TUN.
The development Compose and historical candidate build instructions are separate surfaces.

Run lifecycle commands from that same deployment directory, with its saved `.env` and project
name. Open the configured management address on port 8787, complete administrator/MFA setup,
configure WireGuard ingress and connect a supported direct provider. Setup may finish without
a provider; protected clients remain blocked. Verify DNS and the expected VPN public exit from
an actual routed client after connecting.

For HTTPS, follow the [reverse-proxy guide](deployment/reverse-proxy.md). Trust only the
verified immediate proxy peer. A bridge gateway or an entire private subnet is not implicitly
trusted. Recheck login, MFA and proxy behavior after recreation.

## Diagnose blocked traffic

Start with the authenticated Diagnostics and Activity views. On the Docker host, inspect
bounded logs and the supervisor's public-safe state:

```bash
docker compose -f docker/compose.appliance.yml logs --tail 100 exitlane
docker compose -f docker/compose.appliance.yml exec exitlane python -m exitlane.container_cli status
```

Separate management readiness from the protected dataplane. Check the selected provider,
ingress configuration, DNS and routed-client traffic. A connected status or handshake alone
does not prove delivery. Docker's unhealthy status alone does not automatically restart a
container. Preserve the error and image identity before recovery; inspect logs privately before
sharing any excerpts. Never share tokens, private profiles, keys, database files or cookies.

If state/key/schema validation or network ownership fails, keep traffic blocked and retain
the volume and recovery journal. Do not regenerate a missing key, delete the journal, remove
guards or modify Docker-owned firewall rules to make startup succeed. Where deliberate
restart is appropriate, use `docker compose -f docker/compose.appliance.yml restart exitlane`
and verify fresh provider/client readiness afterwards. Pending or ambiguous provider state
can remain blocked across restart and requires diagnosis, not repeated restarts.

## Backup and restore

One private `/data` volume contains the database, matching master key, ingress configuration,
encrypted provider state, recovery journal and encrypted backups. Preserve it as one unit;
never run two containers against it. The [backup format guide](backup-and-restore.md) describes
encryption and validation; its native CLI commands are not the container mutation interface.

Create a backup through the supervisor, using a masked interactive passphrase prompt:

```bash
docker compose -f docker/compose.appliance.yml exec exitlane python -m exitlane.container_cli backup
```

The result identifies the generated backup under `/data/backups`. Follow the
[Docker backup/export/verify/restore commands](docker-deployment.md#backup-export-verify-and-restore)
to verify and copy that encrypted file to a protected off-host location. Retain the passphrase separately. Do not put a passphrase in
arguments, environment variables, logs or shell history. Automated supervisor calls accept
one bounded passphrase line on stdin with `--passphrase-stdin`.

Restore a verified backup already present under `/data/backups`, replacing `BACKUP.elbackup`
with its basename. Schedule traffic interruption and retain Docker-host console access:

```bash
docker compose -f docker/compose.appliance.yml exec exitlane python -m exitlane.container_cli restore --name BACKUP.elbackup --confirm 'RESTORE EXITLANE'
```

Restore validates the encrypted candidate, holds protected forwarding and replaces state
through the supervisor transaction. Successful restore revokes old browser sessions; sign in
again with MFA and verify settings, ingress identity, provider state, management access and
fresh routed-client DNS/egress. Failed recovery retains guards and recovery evidence. See the
[state and interrupted recovery contract](docker-container-recovery.md) before local intervention.

## Image replacement and recovery

Before replacement, retain a verified encrypted backup, the previous immutable image identity
and the matching Compose/host configuration. Layout 1 currently accepts schema interval
`[1,1]`; a label-only replacement test does not prove arbitrary cross-release compatibility.

Select the reviewed compatible target image in `EXITLANE_IMAGE`, rerun the host preflight
and recreate with the appliance Compose file. Follow the
[upgrade/rollback commands](docker-deployment.md#upgrade-and-rollback) and verify the published
image digest against its release receipt. The official versioned image is
`ghcr.io/kevindraai/exitlane:v1.0.0`; no `latest` alias is defined.
Keep the existing volume. Verify login/MFA, saved state and fresh protected client traffic.

Rollback may reuse the volume only if the previous image accepts its state/schema. Otherwise,
use the matching pre-upgrade image and verified backup under the recovery contract. Preserve
failed state for diagnosis. Never use `down -v` as a recovery step or run the Debian installer
inside the container.
