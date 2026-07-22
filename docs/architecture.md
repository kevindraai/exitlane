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

SQLite stores local durable state. It fits the single-appliance model, avoids a separate database
service, and supports transactional updates. The database is not intended as a coordination layer
for multiple active Exitlane nodes.

Structured application events are a separate backend responsibility. Stable event codes and
per-code metadata allowlists are stored in SQLite; the browser translates them at render time.
Event writes are best-effort so audit storage cannot break the primary action. This Activity log
is intentionally distinct from systemd/journald operational logs.

NordVPN CLI is currently the provider boundary. Exitlane delegates VPN tunnel ownership to a
mature local client while presenting provider-neutral concepts where practical. WireGuard is the
ingress boundary: routers and clients send selected traffic to Exitlane without requiring
router-specific logic in the core.

## Design boundaries

- The backend, not the browser, performs privileged host and network actions.
- Provider-specific behavior stays behind a provider integration.
- Router policy routing remains the router's responsibility.
- Durable configuration lives on the appliance; transient UI state lives in the browser.
- The current design targets one Exitlane instance, one active VPN provider, and a trusted
  management network.

These boundaries keep the current alpha small while leaving room for additional providers,
backup and restore, and a supported API in later releases.
