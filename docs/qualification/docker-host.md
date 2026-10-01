# Disposable Docker-host qualification (D6)

D6 qualifies the D5 experimental appliance on a disposable full Debian 13 amd64
Docker host. It does not publish an image or establish support from a management
health check. The complete acceptance contract remains the failure matrix in
[Docker runtime architecture](../docker-runtime-architecture.md#failure-matrix).
Native Debian/LXC remains the reference implementation.

## Isolation and authority

Use two explicitly disposable hosts. The candidate uses rootful Docker Engine
28 or newer and Compose v2. A separate peer host keeps the synthetic router,
providers, target, numbered pressure and external captures alive across candidate
process death, daemon restart and reboot. Never run whole-host faults on a shared
development daemon. The coordinator requires exact hostnames, pinned SSH host
keys, an explicit restart authorization and UUID-labelled Docker resources. It
refuses foreign containers and namespace/interface ownership changes.

The actual candidate has a private bridge, NET_ADMIN only, capability drops,
TUN, no-new-privileges, read-only root, bounded private tmpfs and one durable
volume. It has no Docker socket, host network/PID, SYS_ADMIN or host filesystem
mount. Management remains loopback-bound. Only ingress UDP is explicitly bound
to the candidate's selected address. Root packet injectors/observers are separate
qualification processes on disposable hosts; they do not enlarge the appliance's
capabilities.

Only the existing Mullvad and PIA upstream API factories are replaced in the
qualification derivative. Their responses register the real application-generated
public WireGuard keys with synthetic peers. The real supervisor, worker, mutation
lease, provider adapters, parsers, guards, route proofs, persistence and recovery
remain unchanged. Proton uses normal profile import. No real provider credentials
are required. A derivative image is test infrastructure, never a production image.

## Traffic and evidence

The router enters through the host-published WireGuard UDP port. Two independent
provider namespaces reach a synthetic external target. Globally classified
synthetic endpoint addresses are routed explicitly to this peer host; fixture
namespaces have no Internet default route. Exact fixture routes persist before
Docker startup. ExitLane never changes Docker's host firewall ownership.

The mandatory continuous witness contains exactly seven logical points: client,
provider A, provider B, target A link, target B link, target normal uplink and the
external WAN equivalent. Candidate epochs add wg-office, the active provider,
container eth0, Docker bridge and physical uplink. Record namespace/interface
identity, timestamps and observer code identity. Stop an old namespace observer
before destroying its container: the observer must not keep a dead namespace
alive. Candidate outage/recreation creates a labelled capture gap and a new epoch;
it is not a zero-packet observation. The independent witness spans the outage.

Numbered protected UDP, TCP SYN-with-data, ICMP, DNS UDP and DNS TCP pressure
must all be present. SYN payload proves forwarding isolation before a handshake;
separate positive application TCP/DNS probes prove successful application traffic.
Identity follows phase/protocol/sequence across NAT, not source address or port.
Calibrate every point with every stream, including deliberately unsafe synthetic
normal-uplink traffic from a separate injector. Keep that positive control outside
accepted safety windows. Start observers and acknowledge their phase before
starting pressure. Preserve failed calibration epochs.

Kernel filters exclude unrelated traffic before socket queuing. Ethernet/VLAN
and raw WireGuard frames are supported. Interface hardware is read from the
current namespace using a read-only ioctl, not a possibly foreign sysfs mount.
Any drops, backlog, missing streams/points, unknown phase/sequence, unobserved
source attempts, unsupported frames or collector failure invalidates evidence.

The continuous witness shares the peer host's clock. Supplementary candidate
captures use bounded clock intervals measured before and after a phase: candidate
C0, authenticated existing peer RPC timestamp R, candidate C1. The proven offset
interval is [R-C1, R-C0]. Measurements must bracket the sender window, overlap,
remain bounded and retain provenance. Local capture windows and interface
identity remain strict. An arbitrary timestamp tolerance is not accepted.

## Execution and retained state

The repository-owned components live under `scripts/qualification/`:

- `container_host.py` owns bounded remote execution, resource identity and packet phases.
- `container_host_peer.py` owns the isolated synthetic upstream/client/target namespaces.
- `container_host_packets.py` parses frames, installs narrow kernel filters and validates receipts.
- `container_host_sender.py` and `container_host_ipv6.py` provide independent numbered pressure.
- `container_host_ipv6_qualify.py` rotates and archives IPv4 observers before calibrating and
  validating a separately captured IPv6-blocking phase.
- `container_host_upstream.py` implements the bounded synthetic response boundary.
- `container_host_matrix.py` drives resumable whole-host restart components.
- `container_host_providers.py`, `container_host_failures.py` and
  `container_host_application.py` prove real provider APIs and application round trips.
- `container_host_state_matrix.py` proves owned lifecycle/state/recovery mechanisms.
- `container_host_generation.py` crashes the actual worker during a persisted
  cross-provider pending generation, then restores the original clean backup.

They require only Python's standard library and the declared
Linux/Docker/WireGuard tools.

Configuration, session cookies, fixture tokens and profiles are root-private
JSON transferred over SSH stdin. Never put them in argv, environment, public
receipts or shell tracing. Unit/fixture logs and packet artifacts are private.
Archive candidate epochs before reboot because `/run` is volatile. Retain image
identity, source revision, package-content proof, boot IDs, daemon live-restore
state, process identity, state-pair digests, rule snapshots, sender receipts and
raw captures. Do not automatically delete guests or retained failure evidence.

Prepare daemon mode outside the measured fault: shutdown uses the running
daemon's mode. A live-restore test requires that mode beforehand and unchanged
container/process identity afterward; a normal daemon restart requires actual
process recreation. Management recovery alone is never packet qualification.

## Ordered component execution

Prepare private configuration/session/handle JSON according to the checked
contracts in `HostHarness`, `private_json` and `validate_handles`. Root-owned
configuration and receipts use directories mode 0700 and regular files mode
0600. Receipt reads use bounded no-follow, nonblocking file descriptors; FIFOs,
symlinks and other nonregular artifacts are rejected.

Every mutable capture/sender handle also carries the D6 run ID and hashes of
its exact systemd unit and stdin configuration. Before writing a control file,
the coordinator verifies those hashes against root-owned remote files, confirms
the unit description binds run and role, and checks that its config points back
to the same private receipt root. Legacy or mixed handles fail closed before
any stop/control operation.

The restart driver accepts only the next pending stage. For example:

```bash
python3 scripts/qualification/container_host_matrix.py \
  --config /root/d6/config.json \
  --captures /root/d6/captures.json \
  --session /root/d6/session.json \
  --receipts-dir /root/d6/restarts \
  --stage next
```

A failed/interrupted row requires inspection. It is never rerun automatically.
The driver always reports partial D6 status: successful restart rows cannot
satisfy missing provider, network or recovery components.

Authenticate/import through `ProviderQualification` and obtain exact public
selection/profile identifiers. Prove normal direct-provider switches, then
use `container_host_application.qualify`
for actual echo and DNS UDP/TCP answers under the same continuous pressure.
Raw SYN markers alone do not establish completed TCP connections.

`FailureQualification` binds the current source and requested target to their
actual public endpoint records before faulting a peer. Handshake failure drops
only outer WireGuard UDP in the owned peer namespace; the observed interface
stays up. Unusable inner dataplane drops tunnel INPUT and forwarding while
preserving encrypted handshakes. DNS failure drops both UDP and TCP 53 without changing tunnel lifecycle. Retained rejected observer epochs remain invalid.
For cross-provider rollback, pin each synthetic catalog to one endpoint and
qualify a fresh real worker before activation. Readback plus fresh-worker
identity excludes stale cached/random selection; do not alter the core cache.

Run authenticated operations before successful restore, which intentionally
revokes browser sessions. `StateQualification` verifies exact UUID resource
ownership, durable schema/key/manifest/user count, selected provider generation
and derived public-key fingerprints. It retains the volume across namespace,
image and bridge replacement. A separate deleted-interface transition and
strict blocked phase precede explicit recovery. If an externally deleted owned
ingress leaves a cached parent identity, API regeneration deliberately refuses
that missing ownership rather than adopting a replacement. Ingress recovery
therefore recreates only the UUID-owned container namespace with the same image
and durable volume, validates both persisted ingress keypairs before/after, reconciles the owned
synthetic router from that existing profile through stdin, and requires fresh
protected packet delivery. This profile read creates no credentials and retains
the router's owned interface identity. The original regeneration attempt is
retained as failed/inconclusive because its exact HTTP response was unavailable;
deterministic controller/API reproduction proves the refusal boundary but does
not retroactively qualify that attempt. The OOM injector must increase
actual owned cgroup `oom_kill`; it claims cgroup/injector OOM, not worker OOM.
Worker/supervisor death is proved independently.

The real supervisor CLI accepts backup/restore passphrases on stdin. After
backup, deliberately change the bounded application polling setting through
the normal API. Wrong-passphrase restore must leave that canary and networking
unchanged. Correct restore must recover the original setting, revoke the old
session and prove a fresh protected dataplane before acceptance. Never initialize
or edit SQLite directly to create this evidence.

A healthy-provider restore exposed an ordering defect at `reset_egress`:
the parent attempted to arm an ingress-only policy before removing the committed
provider's owned default route and probe selector. The unchanged shared ownership
validator correctly returned `provider_egress_resource_conflict`. Read-only
preflight reproduced rejection without an egress identity and acceptance with
the proven active identity. Pending-generation restore had passed because its
old provider route was already absent. In the healthy case, namespace restart
recovered the old journalled state; fresh traffic, healthy management and the old
session therefore proved recovery, not successful restore.

The container reset fix observes maintenance and the existing permanent guard,
validates every surviving provider against its persisted key/peer/endpoint/address
and interface identity, then removes only its exact owned route and probe selector
before deleting the interface. It cleans the exact old ingress selector before
arming canonical ingress policy. Historical source guards and unreachable routes
remain in place. Foreign resources, ambiguous defaults and interface changes fail
closed; native ownership validation is unchanged. Deterministic regressions cover
this boundary. The exact previously failing encrypted backup subsequently restored
successfully on reviewed application source `09c34d3f98d0353534dec58012a39262d848037a`: the
canary reverted, provider identities remained unchanged and fresh protected packet
delivery passed. The old cookie projected `authenticated: false` and received
401 from the protected settings endpoint. Public provider reads during incomplete
first-run setup are not a session-revocation oracle. Failed attempts and the
corrected HTTP-contract assertion are retained; no successful restore was retried
to change its result. This component does not establish full D6 acceptance.

The pending-generation component verifies the exact pending generation and public
keys before killing the pinned worker. A transport interruption is distinct from
a successful API action. Healthy management may remain available while protection
stays blocked; it is not evidence of a committed provider. Require unchanged
pending identity, no automatic promotion, a strict blocked packet window and
clean-backup restore with original identities and fresh protected delivery.
Container startup must also converge the shared temporary killswitch table
after proving the permanent container guard and a fresh committed generation.
Restoring settings that disable the optional shared killswitch must not leave an
old transaction table blocking an otherwise proven provider. Pending or unproven
generations retain protection; shared reconciliation failure prevents startup
acknowledgement and maintenance release.

The label-only second qualification image and rollback to the prior exact digest
prove replacement at schema 1. They do not prove compatibility of an unknown
future release or downgrade. Incompatible-schema/missing-key startup refusal
uses the D5 actual-image negative gates alongside this continuous witness.

## Daemon-mode preparation

Establish each daemon mode before its measured restart fault. Docker 29.8.2
has an important mode-transition boundary: the old daemon with live-restore
keeps tasks alive, but a new daemon started with live-restore disabled stops
those surviving tasks. See the [tagged daemon source](https://github.com/moby/moby/blob/docker-v29.8.2/daemon/daemon.go#L434)
and [live-restore contract](https://docs.docker.com/engine/daemon/live-restore/).
The retained true-to-false preparation failed before packet pressure or the
measured restart began; it is not evidence that an unchanged-mode restart passed
or failed. Explicit recovery started only the same owned container and proved
its unchanged durable pair and fresh protected delivery.

The harness now skips changes when the desired mode already matches. When it
changes mode, it first proves the exact UUID-owned running container, image,
mounts and durable pair, stops that container, edits/restarts the daemon, verifies
the mode and retained identity, and starts it once. It requires health, identity,
state-pair and final mode readback. This preparation is outside measured pressure;
errors stop without retry or recreation. The actual unchanged-mode fault remains
under continuous pressure; live-restore must preserve the process identity.

## IPv6 sensitivity and blocking

Use fresh IPv6 collector epochs after retaining/draining IPv4 evidence. Calibrate
all five IPv6 streams (including ICMPv6 and DNS UDP/TCP) independently on every
actual interface. Pin the owned namespace, ifindex and explicit fixture MACs.
No calibration changes host routes, neighbors or firewall policy.

Run the repository-owned coordinator with root-private configuration and old
external capture handles. It retains old capture files before stopping those
observers and leaves every failed attempt intact:

```bash
python3 scripts/qualification/container_host_ipv6_qualify.py \
  --config /root/d6/config.json \
  --captures /root/d6/ipv4-handles.json \
  --expected-image sha256:<exact-disposable-image-digest> \
  --receipts-dir /root/d6/ipv6-<unique-run-id>
```

WireGuard L3 links may have no `address` key in `ip -j link`; only Ethernet
interfaces require a MAC for synthetic frame construction. Missing Ethernet
address data and unsupported link types fail closed.

A raw outgoing packet on WireGuard can appear at the packet tap while the driver
rejects delivery with ENOKEY. Only calibration on a stable ARPHRD_NONE interface
records that specific downstream rejection, explicitly with `delivery=false`.
Acceptance still requires all five actual decoded collector markers. Pressure
sending rejects ENOKEY and every other send error; an injector receipt alone
never proves observation or encapsulation.

The client has explicit synthetic IPv6 source/route/AllowedIPs. The real v1
server's IPv4-only ingress AllowedIPs rejects its IPv6 source. Require client
plaintext sensitivity and numbered attempts, opaque WireGuard traffic during the window,
and zero protected plaintext at every other calibrated plane. This proves
IPv6 blocking, not IPv6 forwarding support. A generic WireGuard packet counter
does not correlate each IPv6 attempt with a specific encapsulated ingress packet.

## Current status

Historical D6 synthetic disposable-host qualification passed in
[issue #96](https://github.com/kevindraai/exitlane/issues/96) /
[PR #110](https://github.com/kevindraai/exitlane/pull/110), on the exact source/image and host
inventory retained with that evidence. It includes the required provider, packet, recovery,
daemon-mode and host-reboot components. Failed and inconclusive attempts described above remain
retained; a connected baseline or one successful component alone never completes the matrix.

The later D7 implementation supplies gated release infrastructure, not publication. Docker remains
experimental/unsupported and no official production image has been published. Historical D6
acceptance does not automatically qualify the rc.4 source or a rebuilt image; exact candidate
checks and refreshed scans remain release gates in the
[rc.4 release notes](../release-notes/0.3.0-rc.4.md). First GHCR publication and any support decision
remain separately authorized.
