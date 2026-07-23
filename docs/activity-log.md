# Activity log

Exitlane records a bounded, structured history of important administrator and appliance events.
It is an operational activity overview, not a viewer for systemd, journalctl, provider output, or
arbitrary process logs.

Each append-only record contains a UTC timestamp, level, category, stable event code, optional
administrator snapshot, allowlisted metadata, and an optional action correlation ID. The frontend
translates the code and parameters, so changing language rerenders existing records without an API
request. Actions create authentication, setup, settings, provider, configuration, notification,
and system-start events. WireGuard configuration is action-driven. Status polls establish a
baseline and create interface or handshake events only on a confirmed transition, never per poll.

Metadata never includes passwords, provider or session tokens, cookies, private keys, complete
WireGuard configurations, callback URLs, request headers, IP addresses, file paths, environment
variables, raw stdout/stderr, stack traces, or uncontrolled exception details. Login failures use
a generic reason and omit the submitted username.

Retention defaults to 5,000 events and 90 days, configured with
`EXITLANE_EVENT_RETENTION_MAX_COUNT` and `EXITLANE_EVENT_RETENTION_MAX_DAYS`. Cleanup occurs in the
same transaction after an event write. There is deliberately no clear or delete API.

Future event producers must add a stable definition and explicit safe metadata keys in
`exitlane.events`, add translations in both locales, and test that sensitive source data cannot
reach storage or the API.

Self-service administration records successful password changes, local password resets,
NordVPN-token updates, and WireGuard regeneration. These events contain no password, token,
hash, private key, configuration, or submitted value.
