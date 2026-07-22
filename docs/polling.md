# Polling

Exitlane polls because provider, WireGuard, and host state can change independently of browser
actions. Periodic requests suit the current single-appliance deployment and have a simpler failure
model than a persistent event channel.

## Domain pollers

Three pollers serve different views:

- The provider poller observes VPN provider state while the VPN view is active.
- The WireGuard poller observes ingress state while the WireGuard view is active.
- The dashboard poller obtains the combined dashboard, host, provider, and WireGuard summary while
  the dashboard view is active.

Each poller writes confirmed results into the shared slice for its domain. Provider and WireGuard
views therefore consume the same state that the dashboard uses; views do not own separate status
copies.

Dashboard data intentionally updates the dashboard and system slices as well as the shared
provider and WireGuard slices. Its backend response is already a confirmed combined observation,
so discarding those domain fields would leave other views stale. Reusing them also means that the
provider and WireGuard pollers do not need to call their individual backend endpoints while the
dashboard poller is active. Only the poller for the visible view runs, avoiding duplicate backend
calls for status the dashboard response already contains.

## Lifecycle and failures

Polling starts only in authenticated dashboard mode and follows the active view. A mode or view
transition stops pollers that are no longer relevant and starts the one that has become relevant.
Changing the refresh interval restarts this lifecycle with the new preference.

A poller allows only one request at a time. Manual and scheduled refreshes share an in-flight
refresh instead of creating overlapping work. Requests are bounded by a timeout, and stopping a
lifecycle cancels work that is no longer relevant.

A transient failure marks the corresponding slice as stale but preserves its last confirmed data.
Later polling continues so the interface can recover without a page reload. Logout and HTTP 401
responses stop polling and clear authenticated slices, preventing data from one session from
remaining visible in another.

Push updates may become useful if Exitlane later gains high-frequency events or multiple remote
consumers. Until then, view-scoped lifecycle-aware polling minimizes both backend load and state
coordination.
