# Architecture

Exitlane is a small, self-hosted control plane for network egress. Its architecture favors a
single deployable appliance over distributed components so that installation, recovery, and
operation remain understandable for a home lab or small network.

## Components and responsibilities

The FastAPI backend owns privileged operations and presents one application API. It also serves
the single-page frontend, keeping the UI and API on the same origin and allowing one service to be
installed and supervised.

The browser application uses central application state as the shared source for session,
navigation, dashboard, provider, and WireGuard status. Views render that state instead of each
maintaining independent copies. This reduces inconsistent screens and makes startup, logout, and
refresh behavior explicit.

Frontend markup is divided into functional HTML partials that the backend composes for `GET /`.
The browser still receives one complete DOM before `app.js` initializes; partials are structural
ownership boundaries rather than runtime components and never require client-side requests. New
application views belong in their own view partial, new wizard steps in their own wizard partial,
and global shell changes remain in `index.html`, `header.html`, or `sidebar.html`.

Integrated Help uses the repository Markdown under `docs/` as its only content source. The backend
exposes a fixed allowlisted catalog and projects selected documents into typed headings,
paragraphs, lists, notices, tables and code blocks. It does not render or return trusted HTML. The
browser constructs the document view with DOM methods and `textContent`, validates links again,
and never loads remote scripts, styles, fonts or images. Documentation routes remain behind the
normal administrator session boundary.

SQLite stores local durable state. It fits the single-appliance model, avoids a separate database
service, and supports transactional updates. The database is not intended as a coordination layer
for multiple active Exitlane nodes.

The browser, FastAPI process, SQLite/filesystem, privileged provider and WireGuard subprocesses,
Linux/systemd host, and router are explicit trust boundaries. Setup temporarily exposes a fixed
bootstrap route allowlist; completion changes the API to default-authenticated. See the
[security threat model](security/threat-model.md) and
[security testing guide](security/security-testing.md).

Structured application events are a separate backend responsibility. Stable event codes and
per-code metadata allowlists are stored in SQLite; the browser translates them at render time.
Event writes are best-effort so audit storage cannot break the primary action. This Activity log
is intentionally distinct from systemd/journald operational logs.

The explicitly stored ExitLane timezone is the source of truth for a managed appliance. Settings
applies a validated IANA identifier through one fixed `/usr/bin/timedatectl set-timezone` argument
vector, verifies the observed Debian timezone, and persists SQLite only after that verification.
If persistence fails, the system timezone is restored and verified. Startup reconciles a valid
explicit setting before normal operation; invalid or unreadable state remains visible in Settings
and Activity rather than being silently treated as UTC.

Dashboard system metrics are collected directly from Linux interfaces available on both bare-metal
hosts and LXC containers. Memory comes from `/proc/meminfo`, uptime from `/proc/uptime`, CPU time
from the aggregate line in `/proc/stat`, and filesystem usage from the configured dashboard path.
CPU utilisation is the change in non-idle time divided by the change in total time between
consecutive dashboard samples. A single cumulative `/proc/stat` reading cannot express current
utilisation, so the first reading only establishes a baseline and the API intentionally returns
`null` until the next sample; the browser displays an em dash during that interval.

The provider registry and contract are the VPN boundary; see
[VPN provider architecture](architecture/providers.md). NordVPN and Mullvad VPN are registered
implementations. Exitlane delegates VPN tunnel ownership to mature local clients. WireGuard is the
ingress boundary: routers and clients send selected traffic to Exitlane without requiring
router-specific logic in the core.

Provider status keeps installation, authentication, and tunnel connection as separate states and
includes backend-determined capabilities. The capability model currently exposes sign-in,
sign-out, connect, disconnect, and location-selection decisions. The VPN view remains visible
while signed out, but its provider-dependent controls and data loaders stay inert until
`authentication.state` is `signed_in` and `can_select_location` permits them. The backend enforces
the same boundary before catalog, latency, server, or connection work. The model reserves
`can_manage_killswitch`, which remains `false`. Killswitch management is intentionally outside the current scope: enabling it later
requires separate security, routing, DNS, failure-mode, and privilege design rather than only a UI
toggle.

WireGuard setup and management share one configuration service. It generates both key pairs,
transactionally replaces mode-0600 server and client files, activates the interface, and restores the
last working pair when activation fails. See [WireGuard client configuration](wireguard-configuration.md).

VPN mutations and active-provider switches are globally serialized in the FastAPI process. A
switch cannot persist until a connected old provider is disconnected and re-observed. A bounded
CLI timeout is followed by a fresh provider status check; recovery is available only to providers
whose verified contract advertises it. Recovery is limited to two attempts per ten minutes.
Analytics or journal messages are observability signals only and never trigger recovery.

Connection lifecycle state is keyed by a stable connection ID instead of stored in an anonymous
singleton. Providers use `provider:<provider_id>`; the state contract includes the
connection kind, provider, interface, requested location and server-selection generation. This
keeps the current single-egress behavior while preventing a later WireGuard instance from sharing
or overwriting another connection's operation state. Latency measurement is non-exclusive
telemetry. A connect action performs its own awaited selection and falls back to the validated
provider country when no measured server is reachable.

Authenticated connection diagnostics use transient, in-process runs. Each probe owns a fixed
segment and progresses through pending, running, passed, warning, or failed. Automatic probes use
fixed command arguments and endpoints; raw subprocess output is reduced to allowlisted fields
before it crosses the API boundary. Speedtest is an explicit, single-flight action and never part of
an automatic run. On Debian 13 `amd64`, separately confirmed administrators may ask a fixed-purpose
systemd helper to install one digest-pinned official Ookla package; it owns the shared package lock,
and its allowlisted status can be reconciled after a browser reload. The helper adds neither a
repository nor signing key, and installation never starts a measurement. See
[Connection diagnostics](diagnostics.md) and
[ADR-001](architecture/adr-001-managed-ookla-speedtest-installation.md).

## Design boundaries

- The backend, not the browser, performs privileged host and network actions.
- Provider-specific behavior stays behind a provider integration.
- Router policy routing remains the router's responsibility.
- Durable configuration lives on the appliance; transient UI state lives in the browser.
- The current design targets one Exitlane instance, one active VPN provider, and a trusted
  management network.

These boundaries keep the current beta candidate small while leaving room for additional providers,
backup and restore, and a supported API in later releases.
