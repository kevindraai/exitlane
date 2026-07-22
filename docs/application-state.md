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

Not every form field belongs in central state. Short-lived input and purely presentational state
can remain local. Central state is reserved for information that crosses views, participates in
the application lifecycle, or is refreshed asynchronously.
