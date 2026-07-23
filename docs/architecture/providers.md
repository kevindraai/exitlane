# VPN provider architecture

Exitlane has one active egress provider at a time. NordVPN is the only implementation shipped
today, but the application shell, routes, state, and management UI consume a provider contract
rather than a fixed provider name.

## Boundaries

`ProviderMetadata` contains the stable machine identifier, display strings, local icon identifier,
provider type, and authentication method. `Provider` defines status, connect, disconnect, and
conservative optional operations. Unsupported capabilities default to `false`; the UI must not
infer support from a method name or provider brand.

`ProviderRegistry` owns shared provider instances and deterministic lookup. The stored
`vpn.provider_id` selects the active provider and defaults to the registry default for installations
created before this setting existed. Authentication state, installation state, and connection
state are separate. WireGuard is ingress and is deliberately outside this registry.

Generic authenticated routes live below `/api/vpn/providers/{provider_id}`. The older
`/api/vpn/*` and `/api/providers/nordvpn/*` routes remain compatibility aliases during migration.
Mutating aliases and generic routes use the same `vpn_operations.begin()` lifecycle, so conflict
claims remain atomic and cleanup remains in the existing `finally` paths.

The frontend loads the provider catalog only after the administrator session check succeeds.
Metadata creates sidebar entries, Overview cards, provider headings, and wizard choices. Provider
status and polling start only while the authenticated provider view is active; logout/session
expiry stops pollers and clears the catalog and provider slices.

## Adding a provider

1. Implement `Provider` in `backend/exitlane/providers/` and provide local, non-secret metadata.
2. Register one shared instance in the central registry.
3. Return explicit installation, authentication, connection, and capability states.
4. Implement only supported actions and keep all provider CLI parsing and error classification in
   the provider module.
5. Add contract, route, lifecycle, capability, secret-redaction, and frontend metadata tests.
6. Add provider-specific setup controls only inside the provider implementation boundary.

Do not add provider conditionals to navigation or Settings. Do not model provider authentication
as tunnel connectivity, expose credentials in metadata/events, or advertise a capability before
its backend operation is safe. Provider killswitch management is not part of this architecture.

## Overview metrics boundary

The VPN Overview displays only values observed through the generic provider status contract and
the existing latency cache. Exitlane does not currently expose a reliable provider connection
start time or map provider tunnels to sampled interface counters. Throughput and session duration
therefore remain intentionally absent. Adding them requires monotonic samples, elapsed-time rate
calculation, and a trustworthy provider-to-interface mapping; that belongs in a later VPN
hardening/monitoring sprint rather than this provider abstraction.
