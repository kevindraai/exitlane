# ADR 002: ExitLane-owned direct WireGuard provider egress

- Status: accepted
- Date: 2026-09-09

## Context

The first Mullvad implementation embedded the Mullvad Linux app and daemon. That introduced a
second owner for default routes, nftables policy, DNS, startup ordering and tunnel state alongside
ExitLane. Its package lifecycle and early-boot firewall behavior made management preservation and
fail-closed forwarding depend on version-specific upstream internals.

ExitLane already owns the appliance forwarding policy and has a distinct WireGuard ingress from
routers. Mullvad officially supports standard WireGuard configurations and publishes a reference
tool that uses its account-device and relay endpoints.

## Decision

Mullvad uses an ExitLane-owned direct WireGuard egress interface. The generic provider-egress layer
owns a dedicated interface, a dedicated IPv4 policy table, rules selected by protected ingress,
bound probe interface and exact provider source address, an unreachable fallback, exact-peer
handshake observation and active dataplane probes.
The host default route remains in `main`. Ingress and egress share validation primitives only; they
do not share interface lifecycle or configuration files.

The Mullvad adapter owns only account/device registration, relay catalog validation and translation
to the generic egress configuration. Device intent is persisted before remote mutation and
reconciled by public key. Account and private-key state is encrypted with the appliance master key;
short-lived API tokens remain in memory. Initial scope is IPv4, single-hop WireGuard with MTU 1380.

Boot restores the unreachable provider table before networking when an active generation was
persisted. A connect or relay change commits only after exact routing, peer handshake and dataplane
proof. Failure restores the prior proven generation or remains guarded. An active Mullvad daemon or
provider-owned nftables table is a hard conflict and is never deleted automatically.

Qualification on 2026-09-25 found that kernel-generated TCP resets can retain the provider source
address without an ingress or bound output interface. An exact IPv4 `/32` source rule therefore
precedes management routing while preserving the kernel local-table rule. It shares table `51820`
and protocol `196`. Assigned addresses already present on another local interface are rejected.
The source rule and unreachable default survive disconnect, sign-out and restore until reboot,
covering late queued replies. These rules contain no account or key data. After reboot only the
persisted active/pending identity is restored; old kernel packets no longer exist.

## Consequences

- ExitLane is the sole firewall/routing owner for the direct Mullvad dataplane.
- The Mullvad app, CLI, package repository and daemon are not runtime dependencies.
- Management/API traffic stays outside provider egress by construction.
- API schema drift must fail safely and be covered by live qualification because these endpoints
  are not a separately versioned public integration contract.
- IPv6, multihop, DAITA, obfuscation and provider app features require later explicit decisions.
