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
serialized globally. A connected-provider switch is one transaction:

1. inspect only network-independent dependency, local-control and tunnel state for both
   providers;
2. arm ExitLane's provider-neutral transition protection;
3. disconnect the source and verify its local tunnel state is fully disconnected;
4. run the target's network-dependent authentication/readiness check, prepare it, connect it and
   prove protected egress and management routing; and
5. persist the target as canonical only after those postconditions hold, then converge transition
   protection to the operator's configured killswitch policy.

The initial preflight must never call a target account, catalog, DNS or other remote endpoint: the
connected source may legitimately own exclusive DNS or firewall policy. Failure after source
disconnect rolls back to the previous provider while transition protection remains armed. A failed
rollback leaves forwarded client traffic closed and preserves the previous canonical provider for
local recovery; it never guesses that the target is active. An inactive-provider connect fails with
`provider_not_active`. Observing two connected providers, or an externally connected inactive
provider, produces `provider_connection_conflict`.

After source handoff, remote target readiness remains provider-specific. The generic transaction
may retry only a failure that the target adapter classified from a concrete operation as transient.
Retries have a small attempt limit, per-attempt timeout, total readiness deadline and backoff; the
transition guard and previous canonical provider remain unchanged throughout. Mullvad classifies
only structured API timeout/unavailability from device readiness as retryable. Authentication,
configuration, protocol and unclassified provider failures remain terminal. A connect
command is never started twice merely because its caller timed out: ExitLane first reconciles the
local tunnel state and accepts a late Connected state only after full target status, protected
egress and management routing are proven.

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

Each provider translates its native control plane into the generic installation, authentication,
local-status, connection, location, capability, and network-facts contracts. `local_status()` is
the conservative, network-independent handoff boundary; full `status()` may verify the account or
other remote readiness and therefore runs only after the source has released its policy. Provider
responses and CLI output are untrusted: parsers enforce bounds and schemas, validate identifiers,
return only allowlisted fields, and reduce failures to safe codes. The generic authentication
request uses `credential`; the older NordVPN token payload and
routes remain compatibility boundaries.

NordVPN uses its verified private PTY flow. Mullvad calls a fixed HTTPS origin, keeps access tokens
memory-only, and encrypts its account, device binding and WireGuard private key with the appliance
master key. Pending device intent is durable before remote mutation and reconciled by exact public
key. Secrets are never included in Activity metadata. Provider-specific authentication controls live in
small rendering boundaries selected by `authentication_method`; navigation, installation,
connection, and location UI remain generic.

The provider owns tunnel-interface discovery. NordVPN maps its verified client contract. Direct
providers use a generic ExitLane-owned egress layer with a dedicated interface, ingress-selected
policy table, unreachable fallback, exact-peer handshake and dataplane proof. WireGuard ingress is
separate and never shares lifecycle/configuration with provider egress. The generic killswitch and
WireGuard forwarding code consume reported network facts. Existing exact legacy WireGuard rules that forwarded
to `nordlynx` are migrated atomically to provider-neutral default-route forwarding and restored if
activation of the migrated rules fails.

Policy routing protects a small set of exact non-provider destinations: discovered management
networks, explicitly configured routed management prefixes, and the configured WireGuard ingress
client network. It never treats all private address space as trusted. WireGuard contributes only
canonical subnet/interface intent from application settings; the routing service derives the
actual connected-device or gateway path from the kernel's `main` table. It rejects a path over a
discovered provider default interface. Destination rules normally select `main`; when an earlier
provider-owned policy table would win, only ExitLane-owned `proto 196` copies of the derived path
are placed in that table. NordVPN rule priorities, table identifiers and tunnel interfaces remain
provider-owned and dynamically discovered. Direct-provider egress uses ExitLane route protocol
`196`, fixed table `51820`, interface `wg-mullvad`, and rules scoped only to protected ingress.

An unavailable configured local path is represented by an exact owned `unreachable` route in
`main` and any relevant earlier provider table. That is a successful safety transition but remains
a stable operational error until the real route returns. Reconciliation is idempotent across
provider connect/reconnect/switch, provider table recreation, WireGuard provisioning/recreation,
application startup, and the early-boot preparation unit. Removing or changing canonical
WireGuard configuration also removes stale owned rules and routes. The WireGuard unit's post-stop
hook installs the temporary exact block after interface removal, while its post-start hook restores
the derived local path after recreation.

Mullvad is not a package/daemon integration. ExitLane validates the public relay catalog and exact
bound device, renders a root-only `Table = off` WireGuard configuration, and owns only the direct
provider interface/table/rules. Host management and API traffic stay in `main`. The direct table is
armed unreachable before interface replacement and restored at early boot when an active
generation is persisted. An active legacy Mullvad daemon or `table inet mullvad` blocks activation;
no ExitLane code deletes provider-owned firewall state automatically.

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
