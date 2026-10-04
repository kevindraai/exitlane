# Docker operations

Use the [Docker deployment Quick Start](docker-deployment.md#quick-start) for versioned files,
verified official-image digest, explicit LAN bindings, setup and lifecycle commands.
The v1 support matrix is fixed; stable image publication and exact-image qualification are pending.
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

## Start and access the candidate

Use the reviewed appliance Compose file from the matching source checkout. The target is
rootful Linux Docker Engine 28 or newer, Compose v2 and amd64, with host WireGuard/nftables
and TUN prerequisites. See the [candidate build and deployment contract](docker-appliance-candidate.md).
Supply `EXITLANE_IMAGE` as the exact reviewed image digest or local immutable image ID.
Keep that identity and the matching Compose configuration for recovery.

Both management TCP and ingress UDP bind to loopback by default. Set
`EXITLANE_INGRESS_BIND` to the intended host address for the router. Direct trusted-LAN
management requires an explicit `EXITLANE_MANAGEMENT_BIND`. Keep management access limited
to the intended network; check Docker's actual forwarding path as well as host firewall policy.

From the matching source checkout on the Docker host:

```bash
python3 scripts/check_docker_appliance_host.py
docker compose -f docker/compose.appliance.yml up -d
docker compose -f docker/compose.appliance.yml ps
```

Open the configured management address on port 8787, complete administrator/MFA setup and
configure WireGuard ingress and a direct provider. Setup may finish without a provider;
protected clients remain blocked. Verify DNS and the expected public VPN exit from an actual
routed client after connecting.

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

The result identifies the generated backup under `/data/backups`. Copy that encrypted file
to a protected off-host location and verify it with the compatible backup verification tooling
described in the backup guide. Retain the passphrase separately. Do not put a passphrase in
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
and recreate with the appliance Compose file. Pull only an explicitly reviewed image digest
when a published image becomes available. The official stable target is `ghcr.io/kevindraai/exitlane:v1.0.0`; verify publication and its
digest receipt first. No `latest` alias is defined.
Keep the existing volume. Verify login/MFA, saved state and fresh protected client traffic.

Rollback may reuse the volume only if the previous image accepts its state/schema. Otherwise,
use the matching pre-upgrade image and verified backup under the recovery contract. Preserve
failed state for diagnosis. Never use `down -v` as a recovery step or run the Debian installer
inside the container.
