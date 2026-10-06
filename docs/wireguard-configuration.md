# WireGuard ingress device management

The authenticated WireGuard page manages named devices on one ingress interface. Each router,
laptop, container or other consumer gets a durable peer ID, a human name, an optional description,
its own keypair and a unique tunnel IPv4 address. All active peers use the same ExitLane egress
provider and the same subnet-wide routing and killswitch policy. This is not per-device provider
or country selection.

Settings links to this page; setup creates the first peer through the same configuration service.
The shared interface, subnet, listen port and endpoint remain appliance settings. A device name
can change without changing its peer ID, keypair or tunnel IP.

## One profile per consumer

Use a separate ExitLane WireGuard peer for every device or consumer. Do not copy one profile to
multiple devices. WireGuard associates one public key with one current endpoint; sharing a profile
can make endpoints alternate and disrupt traffic. Separate profiles also give accurate status and
traffic attribution, independent revocation and useful audit history.

For example, create `UniFi Gateway` for the router and `Deluge - Synology` for a container on a NAS.
Import each configuration only into its intended consumer. The router still owns policy routing
for its selected clients or VLANs; a container can connect directly with its own peer.

```text
UniFi Gateway ---------+
Deluge container on NAS +-- WireGuard ingress -- ExitLane -- active VPN provider -- Internet
Other consumer --------+
```

## Lifecycle

- **Add device:** enter a name and optional description. ExitLane allocates a free address and
  creates new client keys without rotating the server or any other peer. The new configuration
  can be revealed, copied, downloaded or displayed as a QR code immediately.
- **Edit:** change the name or description without rotating keys or changing the address.
- **Regenerate:** explicitly replace only the selected peer's keys. Its previous configuration
  stops authenticating; import the newly generated configuration. Other peers retain their keys
  and addresses. Regenerating a revoked peer explicitly provisions it again with fresh keys.
- **Revoke:** remove the peer from the live server. Its old configuration can no longer establish
  a tunnel and its configuration is no longer available through normal reveal/download/QR routes.
  The device name and audit metadata remain visible.
- **Delete:** permanently remove a revoked peer's metadata. An active peer must be revoked first.
  Activity events are retained according to the normal Activity retention policy.

The server keeps its existing tunnel address. Every active peer has one unique `/32` from the
configured subnet. The allocator respects subnet boundaries and reserves the server address and,
where applicable, network/broadcast addresses. A revoked peer keeps its address reserved until
its metadata is deleted; explicit regeneration reuses that address. Small subnets can fill; creation returns
`wireguard_address_pool_exhausted` rather than assigning an overlapping address.
The encrypted backup inventory also caps retained peer configurations at 253 (including revoked
peers); a larger subnet returns `wireguard_peer_limit_reached` at that boundary.

## Status

WireGuard does not have a conventional connected/disconnected session. The page therefore shows
**Active recently**, **Inactive**, **Never connected** or **Revoked**, alongside the last handshake.
The central recency rule considers a handshake recent for 180 seconds, accommodating the
default 25-second persistent keepalive. A successful handshake in the past does not mean a
device is still reachable. Status maps the
kernel's public key to the stored device identity, so endpoint and RX/TX counters belong to the
correct human name. Traffic counters reflect the current kernel interface lifetime, not permanent
billing or historical accounting.

## Security and configuration changes

Reveal, download and QR are explicit authenticated private endpoints with
`Cache-Control: no-store, private` and `Pragma: no-cache`. QR images are generated in memory.
Treat downloaded files, clipboard contents and QR images as credentials: each contains the
client private key. List/status responses and Activity events never include private keys or full
configurations. Download names use a safe human-readable filename, independent of the internal ID.

Client configurations and key material remain root-only: private directories use mode `0700` and
configuration files use mode `0600`. Private keys are not stored as ordinary SQLite metadata. The additive `wireguard_peers` table
stores identity and public metadata within the existing schema version 1. The migrated default
peer retains its existing root-only client file; new files use `peer-<uuid>.conf`. Human names
never select filesystem paths. Names and
descriptions are bounded and reject control characters and unsafe path components.

Peer mutations share one mutation lock. ExitLane validates and stages the new state, publishes
configuration atomically, applies the live change and commits metadata only when activation
succeeds. Failure restores the previous valid configuration and runtime state; uncertain rollback
is reported rather than silently declaring success. Normal peer updates preserve the shared
server identity and avoid rebuilding the interface.

All peers share the existing ingress-subnet protection boundary. On native appliances, keep the
optional killswitch enabled when clients must remain blocked after an explicit provider
disconnect. Docker always enforces provider-or-block. Adding peers never creates a plaintext
fallback exception. See [Killswitch](killswitch.md).

## Upgrade from v1

A valid existing v1 single-client installation migrates automatically to a first named peer.
ExitLane preserves the server and client keys, client IP, subnet, endpoint, DNS, port, AllowedIPs
and keepalive. The previously downloaded router configuration remains usable; no reimport or
manual identity replacement is required. The existing `wireguard_client_name` supplies the
initial device name where valid. Migration is idempotent: subsequent starts do not generate keys
or import the same peer again. Inconsistent legacy state fails safely instead of being repaired
by silently replacing identities.

Create and verify an [encrypted backup](backup-and-restore.md) before an upgrade. Backup/restore
includes peermetadata and root-only configuration state; restoration preserves identities and
revocation. Do not activate the original and restored appliance simultaneously with the same
server identity.

## API

All peer routes require the normal administrator authentication. Mutations also use the existing
same-origin checks. Requests use the durable `peer_id`, never a display-name slug.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/ingress/wireguard/peers` | List device metadata and runtime status |
| POST | `/api/ingress/wireguard/peers` | Create a named device |
| GET | `/api/ingress/wireguard/peers/{peer_id}` | Read one device |
| PATCH | `/api/ingress/wireguard/peers/{peer_id}` | Edit name/description |
| GET | `/api/ingress/wireguard/peers/{peer_id}/config` | Reveal an active device configuration |
| GET | `/api/ingress/wireguard/peers/{peer_id}/config/download` | Download that configuration |
| GET | `/api/ingress/wireguard/peers/{peer_id}/config/qr` | Generate its SVG QR code |
| POST | `/api/ingress/wireguard/peers/{peer_id}/regenerate` | Replace that device's keys |
| POST | `/api/ingress/wireguard/peers/{peer_id}/revoke` | Remove that device from the server |
| DELETE | `/api/ingress/wireguard/peers/{peer_id}` | Delete revoked-device metadata |

The v1 `/api/ingress/wireguard/config`, `/config/download`, `/config/qr`,
`/config/regenerate` and legacy client-download routes remain compatibility aliases for the
original/default peer. New integrations should use peer routes so the target is explicit.
`GET /api/ingress/wireguard/status` retains shared ingress status and includes multiple peers.
Missing, malformed or inconsistent state returns stable errors without keys, full configurations,
filesystem paths or command output.
