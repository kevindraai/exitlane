# Disposable network-integration runner

Status: proposed separate workstream. This document does not register or deploy a runner.

## Purpose

Run privileged, real-network acceptance that GitHub-hosted jobs cannot safely perform: network
namespaces, nftables, policy routing, WireGuard interface lifecycle, tunnel interruption, reboot and
provider dataplane/DNS leak checks.

## Trust boundary

The ExitLane repository is public. A persistent self-hosted runner attached to ordinary pull-request
jobs would let untrusted code reach the runner and any resident credentials. Network jobs must run
only from a trusted manually dispatched or protected-branch workflow at an immutable reviewed SHA.
Prefer an ephemeral/JIT runner rebuilt from a known image for every job; a separate private
integration repository is an acceptable stronger boundary. Never expose the runner label to
fork-originated or Dependabot pull-request code.

The privileged job is additive: all hosted required checks must already have passed on the exact
same immutable candidate SHA. An offline, missing or stale runner produces an explicit non-passing
qualification state; it never downgrades the gate to skipped or successful.

## Runner contract

- Dedicated Debian 13 `amd64` VM with a snapshot reset before every run, never a developer,
  production or general-purpose homelab host.
- Disposable filesystem and network identity per run; outbound access limited to Mullvad's control
  plane/relays and explicit test endpoints, with no route to unrelated homelab segments; no Docker
  socket or unrelated secrets.
- `/dev/net/tun`, root network administration, `ip`, `wg`, `nft`, `tcpdump`, `dig` and `curl`.
- Mullvad test account secret supplied only to the protected job environment and removed with the
  ephemeral runner; no secret values in argv, logs or artifacts.
- Concurrency one, explicit timeout, guaranteed teardown, device reconciliation and evidence
  redaction.
- Artifact evidence contains candidate SHA, OS/tool versions, safe relay identifier, route/rule/nft
  summaries, exact-peer handshake timestamps, probe results and packet-count assertions—never keys,
  tokens, account numbers or full configurations.

## Required scenarios

1. Clean install and legacy Mullvad daemon/table conflict refusal.
2. Device create, timeout/retry reconciliation and exact-device sign-out.
3. Three cold connects, relay switch, disconnect/reconnect and reboot recovery.
4. Forwarded IPv4 and Mullvad DNS success from the actual ingress namespace.
5. Zero plaintext protected IPv4, IPv6 or DNS on the physical uplink during connect, failure,
   switch and teardown.
6. Continuous SSH/WebUI/API management reachability over the host main route.
7. Tunnel deletion leaves the provider table unreachable and the nftables killswitch closed where
   configured.

Promotion/release policy may require this workflow only after its trust model, runner lifecycle,
secret source, environment protection and cleanup procedure receive a separate review.
