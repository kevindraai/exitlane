# Polling

The dashboard polls because VPN and host status can change independently of browser actions. A
small periodic request is appropriate for the current single-appliance deployment and avoids the
operational complexity of a persistent event channel.

Polling runs only while the authenticated dashboard is active. It stops when the user leaves the
view or loses the session, and restarts when the refresh preference changes. Only one dashboard
request may be active at a time, preventing slow responses from creating an accumulating queue.

Requests have a timeout. A transient failure is represented as stale or unavailable data, while
later polling continues so the dashboard can recover without a page reload. The interval is a
user preference and should balance responsiveness against work on the appliance and VPN client.

Push updates may become useful if Exitlane later gains high-frequency events or multiple remote
consumers. Until then, lifecycle-aware polling is the simpler failure model.
