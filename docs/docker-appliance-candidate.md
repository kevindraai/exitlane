# Experimental Docker appliance candidate

D5 packages the same ExitLane core behind its container supervisor. D6 has now
qualified the candidate on a disposable whole Docker host, including synthetic
provider failure cases and packet-level no-fallback checks. This remains an
experimental candidate under [#90](https://github.com/kevindraai/exitlane/issues/90),
not a supported release. D7 adds the manually invoked publication workflow; image
publication and a support declaration remain separately gated.
Native Debian 13 amd64/LXC remains the reference implementation. The existing
`docker/Dockerfile` and `docker/docker-compose.yml` remain development surfaces.

## Build and inspect

The appliance Dockerfile uses a digest-pinned Debian 13/Python 3.13 base, a shared
application wheel and hash-locked runtime dependencies. The installed image has
public CA certificates, the PIA CA, timezone data and licensing, without the
repository checkout, tests, development dependencies or appliance state.

Build only from the source revision you intend to review. The package version
and exact source SHA are separate OCI metadata; a candidate built after rc.3
does not become the published rc.3 application merely because its package version
has not yet advanced.

```bash
version=$(PYTHONPATH=backend python3 -c 'import exitlane; print("v" + exitlane.__version__)')
revision=$(git rev-parse HEAD)
docker build -f docker/Dockerfile.appliance \
  --build-arg EXITLANE_VERSION="$version" \
  --build-arg EXITLANE_REVISION="$revision" \
  -t exitlane-appliance:candidate .
export EXITLANE_IMAGE=$(docker image inspect exitlane-appliance:candidate --format '{{.Id}}')
docker run --rm --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --entrypoint python \
  -i "$EXITLANE_IMAGE" - < scripts/check_container_image.py
```

The content checker reads installed package/tool/license facts and public hashes;
it does not open the appliance volume or import application startup.
Canonical deployment identity is the image digest or local immutable image ID.
Moving tags, including `latest`, are not rollback identities. The D7 workflow
accepts only an already published ExitLane release tag whose exact source commit
is on qualified `main`; it publishes that version tag and records its registry
digest. It creates no `latest` or channel alias. No production image is published
by this implementation. The publisher checks GitHub Packages first and refuses to
replace an existing exact version tag; a failed post-push run therefore needs a
separately reviewed recovery path. The image digest, not the human-readable tag,
is the immutable deployment identity. GitHub makes a newly created container
package private by default. The workflow does not change package visibility; a
release owner must separately make the package public and verify anonymous pulls
before announcing a public image.

## Deployment contract

The first support target is rootful Linux Docker Engine >=28, Compose v2 and
amd64. Engine versions before 28 have a documented loopback-published-port
exposure limitation; the older shared development daemon is not a production
qualification target. See Docker's [port publication documentation](https://docs.docker.com/engine/network/port-publishing/).

The candidate Compose file provides a private bridge, `NET_ADMIN` only,
`/dev/net/tun`, `no-new-privileges`, read-only root, bounded private tmpfs and one
durable `/data` volume. Namespaced forwarding/ping sysctls, CPU/memory/PID limits
and rotated Docker logs are explicit. ExitLane owns its namespace policy; Docker
owns host bridge/NAT. Kernel WireGuard/nftables and TUN are host prerequisites.

Before starting, validate the immutable image and resolved Compose configuration:

```bash
python3 scripts/check_docker_appliance_host.py
docker compose -f docker/compose.appliance.yml up -d
```

Both TCP management and UDP ingress default to loopback. For router access, set
`EXITLANE_INGRESS_BIND` to the intended host address. Direct management on a
trusted LAN similarly requires an explicit `EXITLANE_MANAGEMENT_BIND`; never
use an unspecified address. Host/network access controls remain the operator's
responsibility, including Docker's actual forwarding path. The preflight is
read-only and rejects forbidden privileges, mounts and implicit bindings.

The web administrator is configured through the shared first-run UI. Docker v1
offers Mullvad, PIA and imported Proton direct WireGuard providers. Protected
clients remain provider-or-block even when no provider is configured or an
operator disconnects. NordVPN, host power/systemd/package actions, native
in-place upgrade and Speedtest installation are unavailable. API enforcement
and the capability projection accompany hidden/unavailable UI actions.

## Proxy and management checks

For a host-local HTTPS reverse proxy, keep management bound to loopback and
measure its actual peer address as received by ExitLane. A Docker bridge gateway
is not automatically trusted. For a containerized proxy, use a dedicated narrow
network/address contract; trust only its verified peer, not all private addresses.
Set `EXITLANE_PUBLIC_URL` and `EXITLANE_TRUSTED_PROXIES` accordingly. The proxy
must overwrite Host/X-Forwarded-For/Proto and discard supplied forwarding chains.
Uvicorn proxy rewriting is disabled: the shared ExitLane validator sees the real
immediate peer. See the [reverse-proxy guide](deployment/reverse-proxy.md).

Verify a fresh login and MFA flow, origin rejection, Secure cookies and HTTPS
status after recreation. Forwarded headers sent directly from an untrusted peer
remain ignored. The synthetic candidate qualification uses a real separate proxy
peer to exercise this boundary; its simulated HTTPS headers are an application
trust test, not external TLS certificate qualification.

## Lifecycle, recovery and upgrades

The supervisor remains the sole ingress owner. It establishes maintenance and
permanent guards before exposing ingress. The worker receives a one-use inherited
startup grant while the supervisor holds the mutation lease. After initialization,
readonly HTTP health and network postconditions must pass before maintenance
protection is released. Ordinary API/session/monitor/CLI writers take that lease.
Ingress API operations use narrowly bounded subordinate commands; they do not
transfer arbitrary commands or configuration scripts to the parent.

Persisted active generations require fresh dataplane proof. Pending or ambiguous
state stays blocked; restart does not register new provider identities. Guard or
ownership uncertainty retains protection and refuses unsafe recovery. HTTP health
is management availability, not proof of a working VPN. The Docker healthcheck
also checks supervisor recovery/worker readiness; an unhealthy state alone does
not make Docker restart a container.

The [state/recovery contract](docker-container-recovery.md) describes the complete
DB/key/provider inventory and native encrypted backup format. Backup and restore
use the supervisor's root-only local control rather than another independent DB
writer. Passphrases use masked input or bounded stdin, never arguments or env.

```bash
docker compose -f docker/compose.appliance.yml exec exitlane \
  python -m exitlane.container_cli backup
docker compose -f docker/compose.appliance.yml exec exitlane \
  python -m exitlane.container_cli restore --name <backup-basename> \
  --confirm 'RESTORE EXITLANE'
```

Before image replacement, export and verify an encrypted backup and record the
current digest and schema interval. Layout 1/schema `[1,1]` can be reused only by
a compatible image. An incompatible image must refuse startup, not alter the
volume. Use `docker compose pull`/`up -d` with an explicit version/digest when a
reviewed published image becomes available. Roll back only to an image whose
declared state/schema interval accepts the volume; otherwise use the matching
pre-upgrade image and verified backup. Never run two replicas on one volume.

## Qualification, publication and remaining gates

After building the candidate, run:

```bash
python3 scripts/qualification/container_appliance.py --image "$EXITLANE_IMAGE"
```

The harness creates only UUID-owned containers, network and state volume, and
cleans only its own resources. It tests real application startup, authentication,
MFA, readonly/minimal-privilege inspect, digest-based recreation, actual proxy
peer handling and supervisor backup/restore. It creates a second immutable image
identity by adding only a qualification label to the same installed code, proves
replacement and return to the previous identity with schema `[1,1]`, and injects
an incompatible schema into the stopped synthetic state to prove startup refusal.
Removing that synthetic fault is not an application schema migration. These checks
do not claim compatibility across different application releases. Synthetic credentials are carried
on stdin/in memory and omitted from receipts. It does not restart a shared
daemon/host, contact commercial provider accounts or publish an image.

D6 passed on the separately disposable Docker host recorded in issue #96. Its
packet receipts cover the synthetic router/client, ExitLane, provider and external
target points, including provider switching/failure, DNS UDP/TCP, IPv6 attempts
and daemon/host restart cases. No commercial provider credentials were used.

D7's manual workflow builds only `linux/amd64`, verifies image contents, runs the
appliance qualification, blocks on HIGH/CRITICAL OS/Python vulnerabilities and
secrets, emits an SPDX SBOM, publishes only the exact version tag, pulls/verifies
the resulting digest, and attaches provenance and SBOM attestations. The workflow
is not run as part of this PR. Docker remains experimental and unsupported until
the #90 support decision and release criteria are complete. Schema compatibility
remains `[1,1]`; the workflow does not claim cross-release compatibility beyond
that declaration.
