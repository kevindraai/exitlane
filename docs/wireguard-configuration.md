# WireGuard client configuration

The authenticated WireGuard management page exposes the single current router client profile. An
administrator can reveal it, copy it, or download the exact same content as
`exitlane-wireguard.conf`. Configuration responses are private and use `Cache-Control: no-store`;
private keys are never written to application events or error responses.

The same authenticated configuration source is encoded on demand as an in-memory SVG QR code
with Segno 1.6.6. The QR response is never persisted and uses `Cache-Control: no-store`. Closing
the dialog removes the SVG image source from the DOM; regeneration also clears any displayed QR
before replacing the key material.

Settings contains a compact link to this page rather than a second implementation. The WireGuard
page remains the single source of truth for status, reveal, download, and regeneration.

Regeneration is an explicit `POST` action protected by the normal session and same-origin checks.
It creates new server and client key pairs, transactionally replaces both configuration files
through mode-0600 temporary files, activates the interface, and returns the new client profile. ExitLane restores
both previous files and reactivates them if generation or reload fails. Concurrent generation
requests receive `wireguard_generation_in_progress`.

Regeneration replaces the existing client identity. The old profile will no longer authenticate
and every device using it must import the newly generated profile. ExitLane continues to manage
one interface and one client profile; multiple clients and per-device revocation remain outside
the current architecture.

## API

- `GET /api/ingress/wireguard/config` returns the current profile or an explicit empty state.
- `GET /api/ingress/wireguard/config/download` downloads that same profile.
- `GET /api/ingress/wireguard/config/qr` generates an SVG QR code from that same profile.
- `POST /api/ingress/wireguard/config/regenerate` atomically replaces and activates the profile.

All four endpoints require an authenticated administrator after setup. Missing or inconsistent
server/client key material produces a stable error code without returning filesystem, command, or
key details.
