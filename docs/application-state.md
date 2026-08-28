# Application state

The frontend has a central application-state layer for data shared across views. Authentication,
application mode, provider status, WireGuard status, dashboard data, and system status otherwise
risk drifting apart as users navigate or background refreshes complete.

Each asynchronous data area represents its data together with loading, error, freshness, and
last-update information. This lets the interface keep useful previous data visible during a
refresh while still communicating that it may be stale.

Views subscribe to the state they need. Network requests update state, and rendering reacts to
those updates. The separation gives startup and logout one place to clear authenticated data and
prevents a view from becoming an accidental second source of truth.

## Source of truth

The backend is the operational source of truth. It observes the host, VPN provider, WireGuard
interface, persisted settings, and authenticated session; frontend state is a projection of the
last response the backend confirmed.

The frontend may retain and display the last confirmed status while a refresh is running or has
failed. It must distinguish that retained status from fresh data rather than infer a new
operational state. This keeps transient network failures from making known information disappear.

A mutating action is not complete merely because the user initiated it or the interface sent a
request. Completion is represented only after the backend confirms the resulting state. Where an
operation takes time, the interface remains pending until a later backend observation establishes
the outcome.

## Invariants

- Application mode is established before mode-specific data loading begins. A wizard, login, or
  dashboard failure therefore cannot expose a different mode's interface or start its lifecycle.
- Every piece of shared status has exactly one state owner. Multiple views may subscribe to a
  slice, but they do not maintain competing copies of its meaning.
- A refresh failure records an error and marks retained data as stale; it does not remove the last
  confirmed data.
- Logout and an authentication failure stop all authenticated polling and clear provider,
  WireGuard, dashboard, and system state before returning to login.
- Exitlane authentication, provider authentication, active-provider selection, and tunnel state
  are independent gates. Central provider status may be refreshed while a provider is signed out
  or inactive, but countries, servers, latency checks, and VPN mutations start only after explicit
  provider capabilities permit them. Only the active provider receives connection mutations.

Not every form field belongs in central state. Short-lived input and purely presentational state
can remain local. Central state is reserved for information that crosses views, participates in
the application lifecycle, or is refreshed asynchronously.

## Diagnostics state

The diagnostics slice owns the latest transient run shown in the Diagnostics view. Starting a run
replaces the old browser snapshot; polling is bounded to that run ID and stops at passed, warning,
or failed. Opening the view starts one run when none has been requested in the current authenticated
browser lifecycle. Individual ping, DNS, external-IP, and speed-test results remain local to the
view because they are explicit one-off actions, not shared application status.

## Active-server latency

The active VPN latency is telemetry for the exact normalized server hostname or validated relay
address reported through the active provider contract. ExitLane trims whitespace, compares hostnames
case-insensitively, and removes an optional trailing dot, while keeping short
names distinct from fully qualified domain names. A fresh cache row is reused
only when that normalized hostname matches exactly.

If an active server has no fresh row, one deduplicated measurement probes that
validated provider target over TCP/443 and stores the result under the same
normalized hostname. Concurrent provider polls share the in-flight probe. An
unreachable server produces optional `—` telemetry and never changes the VPN's
connected state. Country summaries may reuse the row only when their measured
catalog hostname is the same exact server; country averages and recommended
servers are not substituted into the active metric.

## System actions

`POST /api/system/actions/{action}` accepts only `restart`, `reboot`, or
`shutdown`. The normal authenticated-session, origin, host, and CSRF boundaries
apply. The API records the administrator and returns `202 Accepted` before
launching one fixed absolute `systemctl` argv without a shell. `restart` targets
only `exitlane.service`; `reboot` and `shutdown` affect the full instance.

Shutdown cannot be reversed from ExitLane because the web application is no
longer running. Starting the instance again requires host, hypervisor, or
physical access.
