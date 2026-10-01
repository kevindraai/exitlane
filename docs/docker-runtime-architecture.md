# Docker runtime architecture and implementation program

- Decision date: 2026-09-30
- Status: independently reviewed architecture, **APPROVE**; D1–D6 delivered,
  D7 manual release integration in review; **Docker is not supported**
- Governing deployment wave: [#87](https://github.com/kevindraai/exitlane/issues/87)
- Reference implementation: native Debian 13 amd64, including privileged Proxmox LXC
- Historical decision: [issue #76 feasibility assessment](docker-appliance-feasibility.md),
  2026-09-30, classified the development container **not yet suitable**.

The proposed design is feasible subject to the gates below. It does not overturn that operational
classification. One application core, backend, frontend and provider transaction model gain two
explicit runtime implementations. There is no repository fork or duplicated product.

```text
                         ExitLane core
                 auth / settings / providers
                 routing / guards / recovery
                             |
                +------------+------------+
                |                         |
        Native systemd runtime     Container runtime
        Debian installer           versioned OCI image
        all native providers       direct providers first
```

## Support contract and hard decisions

Docker v1 targets rootful Linux Docker Engine, a private user-defined bridge/network namespace,
Debian 13 amd64 userspace and the host's kernel WireGuard/nftables support. Qualification starts
on a disposable Debian 13 amd64 host with Engine >=28 and Compose v2; D6 records exact kernel,
Engine and Compose versions and bounds the actual supported range. Docker Desktop, rootless,
Swarm, Kubernetes, other architectures and host-network deployments are outside v1.

Drop all capabilities and add `NET_ADMIN`; map `/dev/net/tun`; retain `no-new-privileges` and the
Docker default seccomp profile. Run as root **inside the container**, consistent with the current
network-owning process; this is not host root authority. Add no `NET_RAW` by default. D2/D3 must
prove existing interface-bound DNS/dataplane/latency probes under that set. Prefer ICMP datagram
sockets and a bounded namespaced ping-group range if needed. A concrete indispensable raw-socket
operation may justify a separately reviewed `NET_RAW` addition with evidence; capture privileges
belong to the external harness, not the appliance. No runtime package installs or file-capability
escalation under `no-new-privileges`.

Required sysctls are namespaced `net.ipv4.ip_forward=1` and IPv6 forwarding disabled. Retain explicit
IPv6 protection even on an IPv4-only bridge. Evaluate only the exact rp_filter/source-mark sysctls
that shared routing needs; qualify them before adding. Kernel modules are host prerequisites,
never loaded by ExitLane. Root filesystem should be read-only with intentional writable `/data`
and tmpfs `/run` and `/tmp`; D5 proves this against tooling rather than promising it untested.

Production support is blocked if an essential invariant requires `--privileged`, host network,
Docker socket, host PID, `SYS_ADMIN`, broad host filesystem mounts or arbitrary host-firewall
mutation. Investigate eliminating that requirement; otherwise retain experimental/not-suitable
status and stop the production program. Native security behavior must never be relaxed to pass
Docker gates. No production image is published by this document.

Docker documents capabilities and namespace isolation in its
[container run reference](https://docs.docker.com/engine/containers/run/). These are configuration
possibilities, not proof of ExitLane correctness. Docker's
[nftables backend](https://docs.docker.com/engine/network/firewall-nftables/) is currently experimental;
v1 initially qualifies the normal Docker iptables backend. ExitLane's container-local nftables
must coexist with Docker DNS rules and must never flush a ruleset or alter Docker-owned tables,
including any Docker rules inside the namespace. Host bridge/NAT rules remain Docker-owned.

## Capability matrix

“Target” means intended Docker v1 acceptance after implementation and qualification, not support today.
API authorization remains shared; capability denial applies even to an authenticated administrator.

| Capability | Native reference | Docker v1 target |
| --- | --- | --- |
| WebUI/API, auth, MFA, sessions, first run | Existing behavior | Shared unchanged, full route/security regressions |
| SQLite/settings/Activity, encrypted provider state | Existing behavior | Shared logic, complete persistent state contract |
| WireGuard ingress | systemd wg-quick units | Container adapter; protection before interface activation |
| Mullvad / PIA / imported Proton | Direct WireGuard | Target; same provider parsers/transactions, container dataplane proof |
| Direct-to-direct switching | Existing transaction and rollback | Same generation/claim model, container lifecycle implementation |
| NordVPN | Managed client/daemon | Unavailable; excluded by runtime provider registry |
| Killswitch / DNS / management routing | Native rules and boot units | Same invariants inside container namespace |
| Intentional direct Internet egress | Native product capability | Unavailable for protected ingress in Docker v1; no plaintext fallback |
| Backup / verified restore | Native CLI and systemd callbacks | Shared format/security controls, container transaction adapter |
| Upgrade | Transactional Debian installer | Operator replaces versioned image; no in-place upgrade endpoint |
| Restart ExitLane | Restart application systemd unit | Controlled worker restart under container supervisor; guard retained |
| Reboot / shutdown host | Native fixed actions | Unavailable in API and hidden in UI |
| apt / managed provider or Ookla installation | Native bounded helpers | Unavailable; no host/service helper exposure |
| Diagnostics | Native host/service/network facts | Container process, owned interfaces/routes/guards and bounded probes |
| CPU/RAM/disk metrics | Native appliance metrics | Cgroup-aware container usage/limits and volume space, labelled accurately |
| systemd hardening / journal / timezone mutation | Native authoritative facts | Unavailable; stdout logs and application IANA timezone only |
| HTTPS proxy awareness | Shared peer/origin validation | Shared validation, explicit actual proxy peer and binding tests |
| Speedtest | Explicit native install/terms/measurement | Deferred from v1; no silent package install or false availability |

Docker v1's protected ingress always uses provider-or-block behavior, including an explicit
disconnect or no provider configured. The native optional killswitch/direct-egress choice remains
unchanged. Docker first-run may finish with no provider, but must state that routed clients are
blocked; diagnostics and management remain usable. If intentional direct egress is later desired
for Docker, it needs a distinct product/security decision and packet qualification.

UI receives one runtime-capability projection (for example `/api/runtime/capabilities` plus the
existing public setup projection). The backend enforces it in setup, ordinary endpoints, local CLI
and provider discovery. Unsupported actions return a stable `runtime_capability_unavailable`
error with no subprocess execution. Do not rely on hiding buttons. No fallback detection from
“systemctl missing”; an explicit allowlisted runtime selection fails closed when unknown.

## Small source-derived adapter boundary

| Current boundary | Shared code retained | Runtime-specific change |
| --- | --- | --- |
| `main.py` system actions, timezone/service/status facts | Auth, request models, Activity, response contracts | Small `RuntimeCapabilities` and `RuntimeLifecycle` implementation |
| `main.py:activate_wireguard_interface`, regeneration/disable paths | Validated ingress configuration, atomic files, immutable interface identity | `WireGuardLifecycle.activate/deactivate/observe`; native wraps existing symlink/units; container runs fixed wg-quick argv |
| `services/provider_wireguard.py:ProviderWireGuard` | Egress config, guards, exact-peer handshake, route proof, dataplane commit/rollback | Keep direct lifecycle; inject runner/paths and coordinate startup through runtime |
| `services/management_routing.py` | Prefix validation, kernel-derived routes, locks, owned-route reconciliation | Runtime startup/recreation calls replace systemd hooks, same postconditions |
| `providers/registry.py` and existing provider adapters | Provider-neutral registry/state/transactions and direct provider parsers | Capability-filter registry and API operations; omit Nord on container |
| `lifecycle.py:restore_backup` callbacks; `cli.py` systemd actions | Encryption, archive bounds, hostile-file validation, manifest/schema checks, snapshots | Explicit `RestoreCoordinator`; reuse transaction with container callbacks and writer quiesce |
| `core.py`, auth key paths, configuration/WG paths | DB/schema/security semantics | One validated `RuntimePaths`; native defaults unchanged, container `/data` layout |
| `systemd/*.service`, `wg-quick@` drop-in and installer | Native ordering/hardening/install unchanged | Container PID1/supervisor invokes equivalent core guard/reconcile functions |

Introduce only interfaces with these actual consumers: immutable capability facts, lifecycle,
ingress WireGuard lifecycle, paths, restore orchestration and upgrade availability/strategy.
No generic plugin framework. Construct `NativeSystemdRuntime` or `ContainerRuntime` once at the
composition root; pass narrow dependencies into consumers. Shared routes/rules do not contain
scattered `if docker` branches. Native command sequences and ordering are regression contracts.
D1 extracts these boundaries with a native-only implementation first; no Docker networking yet.

The direct-provider implementation already uses `wg-quick` directly, a dedicated policy table
(`51820`), protocol `196`, ingress/bound-probe and exact provider-source rules, an unreachable
default and exact-peer plus dataplane proof. Keep these controls; a handshake alone cannot commit.
No copied backend/provider implementation is necessary. Review `main.py` fully during D1 to find
all ingress restart, diagnostic, speedtest, install and timezone callers, rather than extracting
only the first obvious `systemctl` call.

## Network architecture and invariants

```text
synthetic/router protected client
      | encrypted ingress UDP via explicit host port
      v
wg-office (inside ExitLane network namespace)
      | protected IPv4; IPv6 always blocked
      v
provider policy table + nftables guard
      +-- unreachable / DROP until proven
      +-- wg-mullvad / wg-pia / wg-proton
               | encrypted provider UDP
               v
         eth0 -> veth -> Docker bridge/NAT -> host uplink
```

The host may see encrypted **ingress** and encrypted **provider** packets plus normal explicitly
unprotected management/control traffic. It must see no protected-client plaintext, even after NAT
rewrites source addresses. The container's main route stays available for management, provider
endpoint encapsulation and bounded provider/catalog API traffic. Provider-assigned source packets,
including kernel-generated replies, remain table-selected/blocked after teardown as on native.
Management exceptions must never match protected-client forwarding merely because a destination
is a management prefix. Validate this against the existing management-routing contract; narrow
any Docker-specific exceptions rather than broadening the shared native model.

D3 adds a container invariant stronger than “the optional killswitch is enabled”: protected
forwarding may exit only an explicitly proven direct-provider interface, never eth0. Install this
owned nftables guard before any ingress interface. Keep unreachable RPDB fallback as independent
protection. Enable a provider only after generation, exact peer, routes, IPv4 dataplane and DNS
proof. If either safety mechanism cannot be established/observed, leave ingress down. Do not flush
Docker NAT/conntrack or host routes. Clear only proven owned rules with explicit identity.

DNS UDP and TCP from protected clients follow the provider path or drop. Never redirect client
queries to Docker's embedded resolver (`127.0.0.11`) or host DNS. Container process catalog/control
DNS may use Docker DNS on eth0, as explicitly separate control-plane traffic. Use destination,
source, protocol and uniquely tagged query payloads in qualification to distinguish the two.
Ingress config advertises the validated provider/client DNS choice; D3 proves changed DNS state,
TCP fallback, external DNS attempts and restoration. IPv6 attempts drop independently of whether
Docker enables IPv6, including IPv6 DNS and locally generated provider-source replies.

## Container lifecycle and recovery

Use a small Python supervisor/entrypoint plus Docker `init: true` for signal forwarding/reaping.
Keep network ownership and guard coordination in the supervisor; run Uvicorn as one child process,
not with reload or multiple uncoordinated workers. The existing cross-process lifecycle lock covers backup/restore; ordinary app/provider mutations
currently have separate mutation claims/network locks and do not acquire that lifecycle lock.
D1 defines the coordination contract and D4 implements one supervisor-owned mutation lease for
container app, CLI, provider monitor, restore and migration operations. No systemd-in-container.

The supervisor is the sole owner of the container lifecycle lease and grants bounded operations
through the fixed-command socket. The CLI sends a request without holding a lock the supervisor
must reacquire. App mutations obtain that lease before the existing provider mutation claim and
network locks. Global order is lifecycle lease → provider mutation claim → network/routing locks;
never reverse it or await supervisor IPC while holding an inner lock. A restore request first blocks
new claims, waits boundedly for the active writer or aborts safely, then stops/joins worker and
monitor tasks before snapshots. It must not deadlock behind a worker it is trying to terminate.
D1/D4 add concurrent CLI/app/switch/restore and crash-release tests; the native runtime gets an
explicit behavior-preserving orchestration contract, not an invented claim of existing locking.

Startup sequence, on every new or reused namespace:

1. Validate runtime/paths/permissions, kernel/tools/sysctls and volume identity. Read persisted
   state without starting a network interface; reject inconsistent generations or unsupported schema.
2. Install permanent protected-ingress egress restriction and IPv6 deny. Restore optional/shared
   killswitch and direct-provider pending/active unreachable guards. Observe rule postconditions.
3. Reconcile management routes; absent ingress gets the existing unreachable protected destination.
   Persisted active/pending direct state may reconnect under the guard; failure stays blocked.
4. Bring up only validated ingress configuration after guards pass; invoke management reconciliation
   after creation. Provider plaintext cannot exit even before reconnection proves a provider.
5. Start the application worker. Management readiness reports availability separately from dataplane
   state. Bootstrap failure exposes only a minimal recovery status/local CLI, not ordinary mutation.

On SIGTERM: claim lifecycle lock, retain/arm guards, stop ingress, quiesce provider, terminate worker
with bounded wait, then exit. On SIGKILL/OOM the kernel guards remain in a surviving namespace;
new namespaces cannot expose ingress before step 2. A worker crash must not clear network rules;
the supervisor detects it, closes ingress or maintains independently observed protection, then
restarts boundedly. Repeated crashes leave protected traffic blocked and report recovery required.
A supervisor crash must terminate the whole container, not leave an orphan serving unguarded
traffic; Docker init/PID1 exit semantics are part of D6 proof. External root deletion of guards is
outside the trust model, but ordinary interface/bridge recreation and partial internal failures
are within qualification scope.

Persist transition intent before network mutation; clear/commit only after dataplane proof.
Conflicting/stale generations never auto-enable ingress/provider forwarding. Retain exact source
rules until namespace destruction; rebuild active/pending identity rules on restart. Process
restart, container restart, daemon restart, live-restore behavior and host reboot are separate
failure cases, not interchangeable evidence.

## Durable state and volume contract

Use one named volume `exitlane-state` mounted at `/data`. An empty volume creates root-owned `0700`
directories and a `0600` 32-byte master key; a nonempty database with missing/invalid key is an
error, never an instruction to generate a replacement. Do not run two replicas against one volume
or duplicate provider/ingress identity. The development `/data` layout requires a reviewed local
migration before production use; it is not silently adopted as qualified appliance state.

| Path | Durable content / handling |
| --- | --- |
| `/data/config/secret.key` | Master encryption key; pair with DB in every recovery operation |
| `/data/state/exitlane.db` and SQLite sidecars | Settings, users, MFA, sessions, Activity, caches, encrypted provider secrets and generation/intent metadata |
| `/data/state/wireguard/` | Canonical validated ingress configs and any durable direct-provider configuration; private keys `0600` |
| `/data/state/provider-egress/` | Current `ProviderWireGuard` root (`core.DATA / "provider-egress"`): generated root-only direct-provider configs, reconstructed only from validated encrypted committed/pending state under guards |
| `/data/recovery/` | Version/schema/source identity, protected pre-migration/pre-restore snapshots and transaction journal |
| `/data/backups/` | Optional encrypted operator backups; export off-host after verification |

Runtime mapping: `EXITLANE_CONFIG_DIR=/data/config`, `EXITLANE_DATA_DIR=/data/state` and canonical
WG directory `/data/state/wireguard`. Current `core.WG_DIR` derives from DATA; remove hardcoded
`main.py` system paths from the container implementation. `/etc/wireguard` may be a fixed
image-owned link to the canonical directory where tooling requires it, not an additional volume.
Provider private state (Mullvad device/account/keys, PIA credentials/generations, imported Proton
keys/profiles/preshared keys) remains encrypted in the shared provider secret store. Generated
plaintext ingress WG files are root-only and included in recovery inventory. Preserve the existing
provider-egress directory path explicitly. Direct-provider generated configs are ephemeral projections
within the durable volume: snapshot them for local transaction rollback, but portable restore regenerates
them from encrypted provider state after strict validation under the guard, never executes old config
hooks. Missing generated files are reconstructible; missing DB/key/generation identity is not. D4 must
prove reconstruction for all three direct providers and interrupted generations, and clean only owned
stale generated files after protection exists. API tokens stay memory-only.
Do not move provider private fields into environment/Compose arguments.

`/run/exitlane` contains transient supervisor sockets, locks and observed state; tmpfs means these
must be regenerated. Logs go to stdout with existing redaction; durable Activity stays in SQLite.
No auth keys, DB, imported profiles, WireGuard files or recovery receipts may live only in the
writable image layer. Backup inventory explicitly covers DB, key, WG files and recovery metadata;
cache loss may be acceptable only when labelled reconstructible. Exported portable backups do
not recursively include other backups or plaintext recovery snapshots. D4 adds a versioned state
layout manifest and completeness tests; native backup-format compatibility must be reviewed.

## Backup/restore transaction

Reuse `lifecycle.py` cryptography, archive budgets/paths, strict privileged-config parser, schema
compatibility and root-only CLI. Do not accept arbitrary imported wg-quick hooks. Container
orchestration differs from `cli.py` systemd callbacks, not from validation/security controls.

The supervisor owns a root-only fixed-command local control socket in `/run/exitlane` (never a
Docker socket). `docker compose exec` runs the local CLI in the same container; the host operator
chooses source files and enters passphrases interactively. Only that runtime may quiesce writers;
a standalone concurrent Uvicorn restart or `docker exec` background daemon is not a restore design.

Restore ordering:

1. Decrypt/validate/stage all contents and compatibility before mutation; acquire lifecycle lock.
2. Guard the union of old and restored ingress identities. Stop ingress; stop the application child
   and all provider-monitor writers; keep supervisor and guards alive. Disconnect active provider
   under protection while retaining exact source/unreachable rules.
3. Snapshot DB through SQLite backup plus key/config/journal as one recovery set, with `0700/0600`
   staging in the same volume. Atomically replace individual files under the transaction journal;
   multi-file atomicity is provided by quiesce plus recovery, not falsely claimed by rename.
4. Revoke old sessions/challenges/enrollments. Validate restored config/state, rebuild guards before
   provider activation, reconnect if intent allows, prove exact routes/peer/dataplane/DNS.
5. Start app; check management/auth/schema and guard postconditions. Reopen ingress only after
   those postconditions; a disconnected restored state may reopen protected ingress while its
   permanent provider-or-block policy keeps all clients blocked.
6. On any failure, stop candidate writers, restore the entire old recovery set, reconcile and prove
   guards/network/health before reopening. Failed rollback keeps ingress down, guard retained,
   recovery snapshot and a stable CLI error. Startup journal reconciliation completes interrupted
   transactions safely, never mixing a new DB with an old master key.

D4 must prove backup consistency during concurrent connect/switch/settings updates, staged
malicious-config rejection, both restoration and rollback packet evidence, session revocation,
wrong-key detection and kill-at-each-transaction-stage recovery. Native restore tests remain shared.

## Image replacement and schema rollback

Production image identity is `ghcr.io/kevindraai/exitlane:vX.Y.Z[-rc.N]` with recorded digest,
source SHA, package/app version and supported state/schema interval. Exact tags are never
republished; digest is the strongest deployment identity. Optional `rc` and `stable` convenience
tags may advance only after corresponding support/release gates. `latest` is absent until the
project explicitly adopts a stable-release policy. No alias is a durable rollback identity.

Operator workflow: create/verify/export encrypted backup; record current image digest and schema;
`docker compose pull`; `docker compose up -d`; validate management/auth, guards, ingress and proven
provider dataplane. ExitLane does not call Docker from inside the container. Incompatible state
fails before a writer starts; migration uses exclusive lock, a complete protected recovery set and
transaction journal before opening networking. Define per-release read/write schema intervals and
state-layout compatibility in image metadata and release notes; no blanket downgrade guarantee.

Rollback to the previous digest is allowed only if its declared schema/state interval still accepts
the volume. Otherwise restore the verified pre-upgrade state with the matching previous image
while ingress is quiesced; newer post-upgrade changes may be lost and operator confirmation is
required. Never run an older image against a partially migrated volume or overwrite remote provider
identities. D4/D5 prove same-schema replacement, incompatible-schema refusal, interrupted migration
and backup-assisted rollback before upgrade instructions claim support.

## Production image and publication CI

D5 creates a separate explicitly production Dockerfile/Compose surface in the same repository;
the development surface stays clearly labelled. Evaluate Debian 13/Python 3.13 base pinned by
digest with a reviewed update process, shared wheel and only required network/runtime packages:
wireguard-tools, iproute2, nftables, CA/TLS/DNS utilities and bounded diagnostics. Inspect the
shared ingress generated hooks to retain required iptables utilities until safely migrated;
removing tools because provider routes use nft is not justified. Install application at build time;
exclude tests, dev venv, cache, Git, local databases/key/profile/backup artifacts. Preserve public
provider CA files and legal notices. No secrets in build args/layers or image metadata.

Set version/source/runtime OCI labels, an unprivileged HTTP management-health probe inside the
container, startup deadline, shutdown grace period, resource limits and bounded logs. A separate
readiness/security status verifies guards/state; HTTP health alone is not VPN qualification.
Docker healthcheck does not itself restart an unhealthy container; supervisor/recovery behavior
must be explicit. Compose publishes only explicit host TCP/UDP addresses/ports and durable state.
Validate effective capabilities/devices/sysctls, mount inventory and read-only behavior from inspect.

D7 adds a manual-only release workflow, enabled from `main` after D1–D6 acceptance and
independent security/architecture review. It requires an already published application release,
an exact source SHA/tag match, ancestry from the D6-qualified main baseline and an explicit
tag-and-SHA confirmation. It builds only `linux/amd64`; Actions are full-SHA pinned and permissions
are minimized. Only the publication job receives `packages:write`, `attestations:write` and
`id-token:write`. It emits an SPDX SBOM, scans OS/Python and secrets, checks installed image
contents, runs the appliance qualification, publishes only the exact release version tag (no
`latest`/channel alias), captures its immutable digest, pulls and rechecks that digest, then attaches
and verifies provenance and SBOM attestations. HIGH/CRITICAL findings block publication; no
automatic risk exception is defined. Attestations document source/build provenance, not packet
safety. This workflow was not dispatched by the implementation PR. First production publication
and any Docker support declaration remain separate gates.

## Management binding and proxy contract

Default production management bind remains `127.0.0.1:8787:8787` for a host-local reverse proxy.
Direct LAN exposure requires an explicit trusted host LAN IP such as `192.0.2.10:8787:8787` and
operator host/network access controls; never omit the host IP. The example address is illustrative.
Publish ingress UDP separately to the intended router-facing address. Do not assume Docker port
publication honors a generic host firewall front end; verify the actual Docker forwarding path.
Docker warns that unspecified bindings expose ports externally and documents a localhost exposure
limitation before Engine 28 in its [port publication guide](https://docs.docker.com/engine/network/port-publishing/).
This is why the production target starts at Engine >=28; the current older shared dev daemon is
not a production qualification target.

For a containerized reverse proxy, use an explicit dedicated proxy bridge with no management
host-port publication where possible; constrain its peers. The proxy connects to ExitLane's
bridge address/service name, but trust only the actual stable peer IP or narrow CIDR observed by
ExitLane, never every RFC1918 address or every container on a shared bridge. A host-local proxy
may appear as the Docker bridge gateway rather than loopback; measure it before setting trust.
Recreation may change dynamic IPs; a dedicated configured subnet/address contract and verification
must prevent stale/broad trust. The dedicated proxy subnet must not overlap protected client ranges.

Use `EXITLANE_PUBLIC_URL=https://exitlane.example.internal` (the actual variable, not bare
`PUBLIC_URL`), `EXITLANE_TRUSTED_PROXIES` and secure-cookie policy with existing precedence.
Proxy overwrites Host/X-Forwarded-For/Proto and discards attacker-supplied chains. Share existing
CSRF/origin/Host and right-to-left validation; X-Forwarded-Host remains untrusted. Container facts
must never reinterpret an untrusted Docker NAT gateway as a trusted proxy automatically. D5/D6
prove direct spoofed headers ignored, actual proxy trust, HTTPS cookies/HSTS/origin, login/MFA,
trusted/untrusted LAN reachability and container recreation. Host firewall remains operator-owned.

## Disposable packet qualification harness

D6 creates an explicitly disposable **whole Docker host VM**, with a labelled allocation and
cleanup authorization. Shared development/reference appliances are not this target. Pin host
kernel/Engine/Compose/image source; retain safe receipts before separately authorized cleanup.
Host/daemon reboot tests require that entire dedicated host, not a reused application container.
No real commercial-provider credentials or outbound provider traffic are needed.

Harness owned by this repository (proposed `scripts/qualify_docker_appliance.py` and fixture module):

- synthetic client/router network namespace with WireGuard ingress and uniquely marked TCP/UDP,
  ICMP, DNS UDP/TCP, IPv4 and IPv6 probes;
- ExitLane candidate on its private Docker bridge, ingress reached through the actual published
  host UDP port (exercise Docker DNAT, not only direct container-IP traffic);
- two synthetic direct-provider WireGuard peer namespaces for switches, independent DNS/external
  target namespaces and a separate management/proxy client;
- a host uplink-equivalent veth into an isolated WAN namespace, Docker bridge/NAT through it;
  suppress real WAN access in the disposable harness and capture at both sides;
- fixed synthetic **globally classified IPv4 addresses** on the isolated WAN link where provider
  endpoint validation requires `is_global`; reserve harness-only addresses with a host route and
  physical outbound isolation. Do not weaken production endpoint validators to accept RFC1918 or
  documentation ranges, and never contact the corresponding real public host;
- packet captures/counters at client cleartext/ingress UDP, ExitLane wg ingress/provider/eth0,
  host veth/bridge/uplink, both provider peers and external target. Capture includes OUTPUT and
  kernel-generated provider-source replies, not just FORWARD counters.

Generate ephemeral synthetic keys, never commit keys/pcaps from real appliances. Captures are
root-only, bounded/rotated and sanitized before attaching public receipts. Record configuration,
source/image digests, host versions, timeline, rule/route snapshots, exit codes, pcap digests and
machine-readable verdict per scenario. Require zero dropped capture packets; dropped/incomplete
capture or missing probe synchronization makes the case inconclusive, never a PASS.

Continuously send unique protected payloads before/during/after every transition, with separate
control probes. Correlate sequences across captures after NAT using payload/destination/protocol,
not original source IP alone. Assert zero plaintext markers, DNS names and provider-assigned-source
cleartext on container eth0 and bridge/uplink. Assert success payloads only at provider/external
paths. Verify captures positively detect an intentionally unsafe **synthetic control gateway**
on the isolated host, never by weakening the candidate. This calibrates detection and distinguishes
“no leak” from “no traffic/capture”. Record bounded recovery readiness with exact-peer plus a
lossless steady-state probe; late/demand-driven handshake is not immediate usable dataplane.

### Failure matrix

For all rows, management/control-plane remains available when the container/host exists, reports
accurate degraded state and remains separate from client forwarding. During an actual stop/reboot,
management is temporarily unavailable and must recover after startup; it must never be used as
proof of protected dataplane. Every row uses continuous marked probes and all capture points above.

| Scenario / deterministic injection | Expected protected traffic | Expected recovery and specific evidence |
| --- | --- | --- |
| No provider configured/connected | Block IPv4, IPv6 and DNS | Management usable; guards present before ingress, no eth0 marker |
| Provider connect | Block until full proof, then provider-only | Generation/route/peer/DNS/dataplane commit; payload appears behind peer |
| Provider loss / peer traffic blackhole | Provider-or-drop, never eth0 | Monitor marks degraded; bounded reconnect under guard |
| Provider interface deletion | Immediate unreachable/drop | Source/ingress rules retained; recreated interface cannot bypass guard |
| Handshake absent | Block | Deadline fails, no connected claim; peer/eth0 captures |
| Late handshake | Block until post-handshake dataplane proof | Bounded late recovery; steady-state lossless probes |
| Handshake without usable dataplane | Block/unusable, no committed connection | Synthetic peer drops forwarding/DNS; handshake alone fails |
| Failed connect (tool/API/config stage) | Block | Pending generation protected; stable error; no unproven commit |
| Switch success A→B | A, transition block, then B only | Exact generation and peer captures, never two active paths |
| Target B failure | Block during transition; proven A after rollback | Rollback proof incl. DNS, Activity and route identity |
| Failed rollback | Remain block | Manual recovery state, retained guards and journal |
| Container restart / namespace recreation | Block across outage/startup | Guard-before-ingress timeline and persisted identity |
| Worker/process crash / supervisor death / OOM | Proven provider or block, never fallback | Old namespace guard, bounded restart or container exit; management outage labelled |
| Docker daemon restart with and without live-restore | Existing safe path or block | Distinct namespace/supervisor observations, reconnect proof |
| Host reboot | Block until recreated guarded namespace | External persistent capture/probe coordinator across host outage |
| Ingress/provider interface recreation | Block until observed postconditions | Shared management route posthooks and exact rules re-established |
| Docker bridge recreation/change of gateway | Provider-or-block | Management/endpoint route rediscovery; no stale permissive exception |
| DNS outage/wrong server | DNS block, no host/embedded resolver fallback | Marked queries absent on uplink; meaningful degraded diagnostics |
| DNS UDP / DNS TCP fallback | Provider-only or drop | Query markers at synthetic resolver, zero plain uplink DNS |
| IPv4 TCP/UDP/ICMP and kernel replies | Provider-only or drop | Capture both forwarding and OUTPUT/retired provider source |
| IPv6 attempts / IPv6 DNS | Always block in v1 | IPv6 enabled in test topology; zero protected cleartext uplink |
| Stale/conflicting generation | Block | Reject stale completion, no wrong provider activation |
| Backup/restore success and faults | Block while quiesced; prove before reopen | Consistent DB/key/WG, session revocation, staged parser and rollback captures |
| Container recreation with same volume | Provider-or-block from first ingress packet | DB/key/Activity/identity intact; missing key refuses startup |
| Image replacement and rollback | Block across transition, prove before reopen | Digest/schema records, compatible reuse, incompatible refusal, backup-assisted rollback |

Use unit fault injection for every transaction stage, lightweight container scenarios for relevant
PRs, and whole-host restart/boot/capture matrix at integration/release gates. Do not pretend a
mocked daemon restart proves actual daemon restart. Live Mullvad/PIA/Proton interoperability is a
separate optional/credential-authorized gate; synthetic security proof does not claim live account
qualification. Existing native PIA/Proton live limits remain accurately documented.

## Ordered delivery and CI cost

One implementation PR at a time, with independent review, all current exact-head CI/security
checks, native test-LXC gates for shared runtime changes and fresh-main reconciliation. Shared core
tests remain one suite; add adapter contract parametrization only where behavior actually differs.
Documentation-only planning uses ordinary required CI and no artificial runtime changes.

| Slice | Dependencies / deliverable | Acceptance gate and CI scope |
| --- | --- | --- |
| D1 Runtime capability boundary | First: capabilities, composition root, native paths/lifecycle/ingress/restore adapters; native-only behavior preserved | API/UI/CLI unavailable-action contracts; native command/ordering regressions; exact-head native LXC; no container networking |
| D2 Container-native WG lifecycle | D1; supervisor, signal/reaping, direct ingress start/stop/observe, permanent startup protection | Synthetic namespace/container only; no provider auth; guard-before-ingress and crash tests with minimal privileges |
| D3 Routing/killswitch/DNS dataplane | D2; shared direct providers integrated in private namespace | Synthetic two-peer packet proof, connect/switch/failure/rollback/IPv6/DNS/OUTPUT; relevant-change lightweight container CI |
| D4 State/restore/recovery | D3; full volume inventory, journal, quiesce callbacks, migration/rollback contracts | Key/DB pairing, recreation, adversarial archive corpus, kill-stage restore/recovery and packet reopening gates |
| D5 Image/Compose management surface | D4; production build, read-only mounts/capabilities/health, bindings and proxy docs | Build-content/version/secret sentinels, image inspect, health/security readiness, proxy/auth matrix; CI image checks on image/runtime/dependency changes |
| D6 Disposable-host qualification | D5; executable harness and complete matrix above, exact supported host/runtime inventory | Delivered in #96 / PR #110; synthetic packet no-fallback and daemon/host restart evidence |
| D7 GHCR/release integration | D6 PASS and reviewed support decision; exact-release manual workflow, digest/metadata/provenance/SBOM and operator upgrade guide | In review in #97; CI workflow gates run without publishing; first public image needs separate authorization |

The synthetic D2 lifecycle implementation and runnable lightweight proof are documented in
[container lifecycle qualification](docker-container-lifecycle.md). They do not enable the full
application container runtime or satisfy D3–D6 dataplane/recovery/support acceptance.

The D3 implementation and isolated packet harness are described in
[direct-provider dataplane qualification](docker-container-dataplane.md). They reuse shared
provider transactions with a container-specific lifecycle adapter. Full application runtime
selection was disabled through D4; the experimental D5 image now supplies the composition
boundary described in [the image candidate contract](docker-appliance-candidate.md). The experimental
[durable state and recovery mechanisms](docker-container-recovery.md) retain the
native encrypted archive format and add supervisor-owned mutation leases and
journalled container orchestration. D5 supplies a one-use, supervisor-held worker startup
handoff; D6 must qualify daemon/host restart on an independently disposable host.

The subsequent deployment-wave work order authorizes sequential D1–D7 implementation.
D1 establishes a native-only composition root (`exitlane.runtime`); unsupported runtime names
fail before state initialization. Native paths preserve existing independent historical defaults
and explicit environment overrides; this extraction does not migrate appliance state. D2–D7 remain dependency-blocked until predecessor
acceptance evidence exists. If D2/D3 privilege or packet gates fail, stop before product packaging;
D5 cannot turn a failed dataplane into a supported appliance. A future NordVPN design is a separate
[research issue #98](https://github.com/kevindraai/exitlane/issues/98) outside D1–D7.

## GitHub implementation program

Umbrella [#90](https://github.com/kevindraai/exitlane/issues/90) owns acceptance; deployment wave
[#87](https://github.com/kevindraai/exitlane/issues/87) records the Proxmox and planning evidence.
D1–D4 are delivered; D5 is the current implementation slice. Sequential issues:

- [D1 — #91](https://github.com/kevindraai/exitlane/issues/91)
- [D2 — #92](https://github.com/kevindraai/exitlane/issues/92)
- [D3 — #93](https://github.com/kevindraai/exitlane/issues/93)
- [D4 — #94](https://github.com/kevindraai/exitlane/issues/94)
- [D5 — #95](https://github.com/kevindraai/exitlane/issues/95)
- [D6 — #96](https://github.com/kevindraai/exitlane/issues/96)
- [D7 — #97](https://github.com/kevindraai/exitlane/issues/97)

Each successor requires predecessor acceptance. These are bounded delivery slices, not permission
to bypass the documented merge, infrastructure, qualification or publication gates.

## NordVPN research disposition

The [official NordVPN Docker instructions](https://support.nordvpn.com/hc/en-us/articles/20465811527057-How-to-build-the-NordVPN-Docker-image)
show a local client daemon started through init.d and a container granted NET_ADMIN. That suggests
containment is possible; it does not prove compatibility with ExitLane's firewall/routing ownership.
Its example's IPv6 wording conflicts with the shown sysctl value, another reason not to adopt its
recipe as security evidence. Docker v1 therefore excludes NordVPN. Future research must establish
single firewall ownership, lifecycle ordering, contained auth/state and leak/rollback proof without
host dependencies, systemd-in-container or any forbidden privileges. A feasibility finding must
precede implementation and must not block the direct-provider program.

## Acceptance and retained gates

This architecture is a delivery contract, not runtime evidence. The program becomes supported only
when D1–D7 gates and a reviewed release/support decision pass. Remaining unknowns are bounded:
minimal-capability tooling (including ping/DNS), read-only root compatibility, container guard
ordering, Docker NAT/source/proxy behavior, crash/restore/schema recovery and whole-host packet
qualification. Each has a slice and test gate. The original architecture PR performed no
runtime changes, image builds, publication or Docker host mutation. Subsequent bounded
implementation PRs supply experimental evidence; they do not imply production support or
authorize publication before D6 and the explicit first-publication gate.
