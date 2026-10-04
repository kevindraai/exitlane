# Synthetic direct-provider dataplane (D3)

> Historical implementation/qualification record. Older unsupported/publication-hold
> and all-HIGH scanner policy statements describe the original delivery boundary.
> The executive order fixes v1 support and authorizes publication under the residual-risk
> policy. Use [Docker deployment](docker-deployment.md) and [SECURITY](../SECURITY.md)
> for the current operator/support contract. Final source/image receipts are recorded in the
> [published v1.0.0 release](https://github.com/kevindraai/exitlane/releases/tag/v1.0.0).

## Dated implementation evidence

Docker remains unsupported. D3 extended the isolated D2 lifecycle; that slice alone did not
enable full application container selection or publish an image. D4–D7 subsequently delivered
durable recovery, supervisor leases, experimental appliance composition, historical D6 synthetic
host qualification and release infrastructure. Debian/systemd remains the reference runtime.
No official production image has been published. See the
[candidate contract](docker-appliance-candidate.md) and
[rc.4 release notes](release-notes/0.3.0-rc.4.md) for current receipts and pending release gates.

## Shared transactions, bounded runtime difference

`ContainerWireGuardEgress` implements the existing direct-provider lifecycle
interface. Mullvad, PIA and imported Proton profiles continue using their existing
parsers, encrypted state, generation ownership, connect/switch and rollback
transactions. Their new `committed` lifecycle callback is a native no-op. It runs
after active state is saved and the owned transition completes successfully;
containers use it to authorize the exact proven generation. No copied provider
implementation or Docker-specific application fork is introduced.

The container lifecycle owns one private namespace policy lock and candidate epoch
shared across provider adapters. Starting a candidate first revokes forwarding.
Two bounded proof rounds require the exact peer, handshake, route, source OUTPUT
guard, lossless ICMP and interface-bound DNS over both UDP and TCP. A fresh proof
receipt and final observation are required at commit. Observation can revoke
forwarding; it cannot authorize a provider or reopen a revoked generation.

The separate permanent `inet exitlane_container_guard` table permits protected
IPv4 only toward the committed provider interface. All other protected forwarding,
including IPv6, remains blocked. Namespaced client NAT provides the provider's
expected client source address. Ingress/source unreachable policy routing remains
installed through disconnect. This invariant is independent of the optional
native killswitch setting. Foreign policy under the owned table name is refused.
ExitLane never modifies Docker's host bridge, NAT or firewall policy.

Protected DNS cannot use the container's local resolver as a fallback. INPUT rules
block protected ingress/source UDP and TCP port 53. Docker's embedded resolver
also translates locally generated DNS to a different port before filtering;
a separate OUTPUT chain runs after destination translation and blocks registered
provider source addresses on every destination port unless the selected output
interface is the exact candidate/current WireGuard interface. Addresses are
registered before assignment or probing and retained after disconnect or interface
deletion. The bounded historical inventory never evicts a protected address;
exhausting it fails closed. Restart recognizes only the exact owned policy shape
and restores that inventory with forwarding and probe allowances closed.
Provider DNS probes bind directly to the provider interface and
validate the transaction, question and response framing. Container management and
provider endpoint traffic retain their ordinary namespace uplink.

## Isolated packet qualification

On an explicitly disposable/authorized rootful Docker test surface:

```bash
docker build -f docker/testing/Dockerfile.lifecycle -t exitlane-dataplane:test .
python3 scripts/qualification/container_dataplane.py --image exitlane-dataplane:test
```

The harness refuses overlapping host routes, Docker networks or resolver addresses
before creating resources. It cleans only invocation-owned containers/networks and
retains bounded root-only evidence in its reported temporary artifact directory.
It never restarts Docker or the host.

The test-only image includes a fixture that injects this adapter into the actual
provider registry and switch handler. Only remote API/catalog responses and
optional telemetry are synthetic. No real provider account is used. Ephemeral
keys enter through a private FIFO and WireGuard stdin, never command arguments or
HTTP control requests.

The host harness creates unique Docker bridges and only its own disposable
resources. A synthetic client enters over WireGuard; two synthetic
provider peers forward to a synthetic external target. An additional namespaced
relay supplies a usable ordinary fallback route. Separate positive control proves
that plaintext delivery is possible in the topology without weakening the
candidate's policy. The fake global endpoint and target addresses are confined to
the test networks. Fixture namespaces have no upstream default route; the
candidate's ordinary default route points only to the synthetic relay, which has
no upstream route. Docker's internal-network destination filtering would hide a
plaintext fallback before it reaches that relay, so the normal bridge uses the
standard Docker filter with masquerading disabled. The external bridge remains
internal. Explicit small address ranges preserve globally classified fake
endpoints; preflight refuses host route, Docker IPAM or resolver overlap. All
fixture DNS points to the synthetic resolver. No Internet destination is contacted.

The candidate uses `cap-drop ALL`, `NET_ADMIN`, TUN, namespaced forwarding,
`no-new-privileges` and Docker init. It has no privileged/host network/PID mode,
Docker socket, SYS_ADMIN or host filesystem mount. Separate read-only observer
processes join only these test namespaces and receive NET_RAW to capture packets;
this capture permission is not an appliance requirement.

Observers count synthetic protected markers and marked DNS on ingress, provider,
ordinary uplink and relay interfaces. WireGuard outer packets are counted as
encrypted metadata, not plaintext markers. Interface recreation causes capture
rebinding. Packet drops, capture failures or the bounded capture-size limit fail
the evidence gate. Root-only bounded pcaps contain only synthetic qualification
traffic; no provider configuration or private keys are included.

The matrix covers each direct provider's connect/disconnect, source-address-changing
switches, stale generations, absent and late handshakes, a handshake with unusable
dataplane, separate UDP/TCP DNS failure, target failure with successful and failed
rollback, the outer application's paused switch, optional configured killswitch,
interface deletion, protected source sockets and decrypted IPv6 attempts. Normal
management DNS and a separately unsafe synthetic forwarding control must work;
otherwise a zero-packet negative result is insufficient evidence.

This is a lightweight namespace/dataplane proof. Its harness cannot establish Docker daemon
restart, host reboot, physical-uplink capture, durable restore or image replacement acceptance;
those have separate historical D6 disposable-host receipts. Passing D3 or the later synthetic
matrix does not confer production support or authorize publication.
