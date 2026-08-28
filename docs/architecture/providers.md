# VPN provider architecture

ExitLane ships NordVPN and Mullvad VPN integrations. Either or both may be installed and signed in,
but exactly one registered provider can be selected as active egress. Only that active provider may
receive a connect, reconnect, location-selection, or latency-selection mutation from ExitLane.

## Boundaries

`ProviderMetadata` contains the stable machine identifier, display strings, local icon identifier,
provider type, and authentication method. `Provider` defines status, connect, disconnect, and
conservative optional operations. Unsupported capabilities default to `false`; the UI must not
infer support from a method name or provider brand.

`ProviderRegistry` owns one shared instance per provider and deterministic lookup. The stored
`vpn.provider_id` selects the active provider and defaults to the registry default for installations
created before this setting existed; that backward-compatible default remains NordVPN.
Registration, installation, authentication, active selection, and connection are separate states.
WireGuard is ingress and is deliberately outside this registry.

Generic authenticated routes live below `/api/vpn/providers/{provider_id}`. The older
`/api/vpn/*` and `/api/providers/nordvpn/*` routes remain compatibility aliases during migration.
Mutating aliases and generic routes use the same `vpn_operations.begin()` lifecycle, so conflict
claims remain atomic and cleanup remains in the existing `finally` paths. Provider mutations are
serialized globally: a provider switch first observes and, when needed, disconnects the old
provider, verifies it is disconnected, and only then persists the new active ID. Failure keeps the
old selection. An inactive-provider connect fails with `provider_not_active`. Observing two
connected providers, or an externally connected inactive provider, produces
`provider_connection_conflict`; a configured ExitLane killswitch treats that ambiguity as closed.

The frontend loads the provider catalog only after the administrator session check succeeds.
Metadata creates sidebar entries, Overview cards, provider headings, and wizard choices. Provider
status and polling start only while the authenticated provider view is active; logout/session
expiry stops pollers and clears the catalog and provider slices.

First-run onboarding accepts none, NordVPN, Mullvad VPN, or both. Selected providers are processed
in deterministic registry order and may be skipped independently. Exactly one ready provider is
activated automatically. Multiple ready providers require an explicit active choice. The persisted
`setup_provider_deferred` choice is distinct from provider authentication: it allows onboarding to
continue with no provider while status remains honestly signed out or unavailable. In that mode,
WireGuard ingress uses the appliance's normal internet route.
When an administrator later opens an uninstalled provider, its management page exposes the same
protected, resumable installation operation as onboarding. A status retry is reserved for states
where managed installation is unavailable and can therefore provide useful new information.

Provider logo metadata resolves only to repository-local assets. Generic icon identifiers are
validated against the allowlist in `static/js/icons.js` and use `shield-check` as the safe fallback.
License and source details are recorded in `THIRD_PARTY_NOTICES.md`.

## Provider and credential boundaries

Each provider translates its native CLI into the generic installation, authentication,
connection, location, capability, and network-facts contracts. CLI output is untrusted: parsers
use `LC_ALL=C`, validate identifiers, return only allowlisted fields, and reduce failures to safe
codes. The generic authentication request uses `credential`; the older NordVPN token payload and
routes remain compatibility boundaries.

NordVPN uses its verified private PTY flow. Mullvad invokes the fixed argv
`mullvad account login`, supplies the 16-digit account number through stdin, captures and wipes the
account-bearing output buffer, and never returns or logs it. Credentials are neither stored by
ExitLane nor included in Activity metadata. Provider-specific authentication controls live in
small rendering boundaries selected by `authentication_method`; navigation, installation,
connection, and location UI remain generic.

The provider owns tunnel-interface discovery. NordVPN maps its verified client contract; Mullvad
validates the interface reported by machine-readable status. The generic killswitch and WireGuard
forwarding code never hardcode either name. Existing exact legacy WireGuard rules that forwarded
to `nordlynx` are migrated atomically to provider-neutral default-route forwarding and restored if
activation of the migrated rules fails.

Mullvad package installation is a separate systemd/package trust boundary. APT runs with
`SYSTEMD_OFFLINE=1`, so upstream package scripts may enable units but cannot start them through PID
1. ExitLane-owned drop-ins prevent the early-boot firewall initializer from ever running and gate
the daemon behind a transient controlled-start marker or a post-validation completion marker. The
helper observes inactive units and no provider firewall table after APT, starts the daemon once,
applies and reads back the unauthenticated management baseline, verifies disconnected network
state, and only then persists completion. Settings that Mullvad exposes only with an account are
applied and verified immediately after login and before activation. No generic provider or
killswitch code deletes provider-owned firewall state.

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
