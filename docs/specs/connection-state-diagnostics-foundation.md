# Connection state and diagnostics foundation

Status: implementation issue

Branch: `feat/connection-state-diagnostics-foundation`

Baseline: `0c5c9d1` (`origin/main`, fetched 2026-08-22)

## Problem

Country latency refresh currently claims the same process-wide VPN operation slot as connect and
disconnect. A user who selects a country while automatic latency work is still running therefore
receives `vpn_action_in_progress`; retrying after the latency appears succeeds. The current global
operation dictionary also has no stable connection identity, which makes a later second egress or
WireGuard instance ambiguous. Existing setup diagnostics return untyped booleans and are not a
usable authenticated connection-health workflow.

## Scope and decisions

1. Replace the anonymous VPN operation singleton with a connection-state store keyed by a stable
   connection ID. Preserve the current API fields while exposing `connection_id`, `kind`,
   `provider_id`, lifecycle state and selection state. The first connection is
   `provider:nordvpn`; the shape deliberately supports later WireGuard entries without adding
   multi-instance management in this iteration.
2. Treat latency as telemetry, not an exclusive VPN mutation. Country measurement may run beside
   connect. Connect performs/awaits its own server selection, records `selecting` and then either
   `selected` or `fallback`; no reachable latency result falls back to the provider's validated
   country target instead of becoming a connection error. A selection generation prevents stale
   results from a superseded country request being published as current state.
3. Add an authenticated diagnostics API with short-lived in-memory runs. A run progresses through
   `pending`, `running` and a terminal `passed`, `warning` or `failed` status per probe. Automatic
   probes cover the ExitLane host/default network route, VPN interface/handshake/egress route, DNS,
   internet reachability and public IP. Results use fixed codes and bounded, sanitized details;
   raw command output is not returned.
4. Add explicit POST-only diagnostic actions for validated ping and DNS targets, fixed-endpoint
   external-IP lookup, and an optional speed test. Speed test is never part of automatic runs and
   only executes after a user click. Missing host tooling produces `warning`, not an unsafe shell
   fallback.
5. Add a Diagnostics view showing Device > ExitLane > VPN > Internet. Nodes and links render
   pending/running/passed/warning/failed state, and each link has translated troubleshooting
   details. The page polls only its own active run and offers the manual actions below the flow.

## API outline

- `POST /api/diagnostics/connection-runs` -> `202` run snapshot
- `GET /api/diagnostics/connection-runs/{run_id}` -> current run snapshot
- `POST /api/diagnostics/actions/{ping|dns|external-ip|speedtest}` -> structured result

The legacy `GET /api/diagnostics` remains the setup-system check and keeps its existing contract.
All new routes use the normal authenticated API, same-origin and CSRF boundaries.

## Verification and acceptance

- Regression tests cover connect during pending latency, unreachable latency fallback, direct
  connect after selection, and repeated country changes with stale selection completion.
- Unit/API tests cover state isolation, every diagnostics status, safe target validation,
  authorization, bounded output and the explicit-only speed-test boundary.
- Frontend tests cover the four-node flow, line-state aggregation, polling and translations.
- Run Ruff, backend pytest, frontend Node tests, i18n validation, JS/Python/shell syntax, Bandit,
  dependency audit and package build. Appliance-only host integration remains an explicit PR risk
  unless the configured test LXC is reachable from this environment.

## Explicit follow-ups

- Integrated, versioned in-app documentation and error-to-doc deep links.
- Split-screen login hero artwork for large screens.
- Persistent multi-WireGuard instance CRUD, routing policy by source IP/FQDN, and management UI.
- Durable/cross-process diagnostics history if ExitLane later runs with multiple workers.
