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

Not every form field belongs in central state. Short-lived input and purely presentational state
can remain local. Central state is reserved for information that crosses views, participates in
the application lifecycle, or is refreshed asynchronously.
