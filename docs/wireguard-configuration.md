# WireGuard ingress device management

Use the WireGuard page to connect routers, hosts and containers to ExitLane. Each named device
gets its own keypair and tunnel IP on one shared ingress interface. Every peer uses the same active
egress provider and protection policy, so a provider or country change affects them all.

Setup creates the first peer. Add more in **WireGuard**, which is also linked from Settings. You
can rename a device without changing its keys or tunnel IP.

## One profile per consumer

Create one ExitLane peer for each consumer that connects directly. Do not copy one profile to
multiple devices: sharing a WireGuard key can make endpoints alternate and disrupt traffic.
Separate peers also give accurate traffic attribution and independent revocation.

For example, create one peer for a router and another for a container that connects directly.
Import each configuration only into its intended consumer. The router still chooses which of its
clients or VLANs use the tunnel.

```text
Router ---------------+
Container ------------+-- WireGuard ingress -- ExitLane -- shared egress -- Internet
Other device ----------+
```

### Connect a host or container

For a router or host, create a named device in **WireGuard**, download its configuration, and
import that file into its WireGuard client. Keep the file private and allow the consumer to reach
ExitLane's UDP endpoint. Route only the workloads you intend to protect: on a router, select the
clients or VLANs in its policy rules; on a host, select the traffic in its own routing policy. A
router forwarding several LAN clients needs one peer, while a directly connected host gets another.
From an intended workload, verify DNS and the expected protected public exit. Then check the
peer's handshake and traffic in ExitLane. A handshake alone does not prove protected delivery.

For a container with its own WireGuard client, create a separate peer and give that container only
its own configuration. As one example, [Gluetun's custom WireGuard provider](https://github.com/qdm12/gluetun-wiki/blob/main/setup/providers/custom.md)
accepts an INI file mounted read-only at `/gluetun/wireguard/wg0.conf`:

```yaml
services:
  gluetun:
    image: qmcgaw/gluetun
    cap_add: [NET_ADMIN]
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      VPN_SERVICE_PROVIDER: custom
      VPN_TYPE: wireguard
    volumes:
      - ./exitlane-peer.conf:/gluetun/wireguard/wg0.conf:ro
```

Replace `exitlane-peer.conf` with that container's downloaded peer file and restrict access to
it: the file contains its private key. Route only the intended container workloads through
Gluetun, then verify their DNS and public exit. [Gluetun's WireGuard options](https://github.com/qdm12/gluetun-wiki/blob/main/setup/options/wireguard.md)
give file values precedence over environment variables. Gluetun's custom-provider documentation
currently requires a numeric endpoint IP, so check the downloaded profile if ExitLane uses a
hostname. Follow Gluetun's own documentation for the rest of the container setup.

## Lifecycle

- **Add:** enter a name and optional description. ExitLane assigns a free tunnel IP and new client
  keys. Reveal, copy, download or scan its configuration to set up the consumer.
- **Edit:** change the name or description without changing its keys or IP.
- **Regenerate:** replace this peer's keys. Its old profile stops working; import the new one.
  Other peers keep their keys and IPs. Regenerating a revoked peer makes it active again.
- **Revoke:** stop this peer from authenticating. Its profile is no longer available through the
  normal reveal, download and QR actions; its name and Activity history remain.
- **Delete:** remove a revoked peer's metadata. Revoke an active peer first.

Every active peer has a unique `/32` address from the configured subnet. A revoked peer keeps its
address reserved until deletion; regeneration reuses it. ExitLane reports an error if the subnet
has no free address or the backup inventory reaches its 253-peer limit, including revoked peers.

## Status

The page shows **Active recently**, **Inactive**, **Never connected** or **Revoked** for each peer.
"Active recently" means its last handshake was within 180 seconds; it does not guarantee current
reachability. The endpoint and RX/TX counters belong to that peer's key. Counters cover the
current interface lifetime, not long-term traffic history.

## Security and configuration changes

Treat downloaded files, clipboard contents and QR codes as credentials: each contains the client
private key. Reveal, download and QR require administrator authentication and are served without
caching. ExitLane keeps configuration files root-only; the device list and Activity events contain
no private keys or full profiles.

Changes apply to the selected peer while preserving the server and other peers. If activation
fails, ExitLane restores the previous configuration or reports that rollback is uncertain.

All peers share the existing ingress-subnet protection boundary. On native appliances, keep the
optional killswitch enabled when clients must remain blocked after an explicit provider
disconnect. Docker always enforces provider-or-block. Adding peers never creates a plaintext
fallback exception. See [Killswitch](killswitch.md).

## Upgrade from v1

A valid v1 single-client installation becomes the first named peer automatically. ExitLane keeps
the server and client keys, client IP and connection settings, so the router's existing profile
still works. A valid saved client name becomes the device name. Later starts keep the same identity;
inconsistent legacy state stops migration instead of replacing keys.

Create and verify an [encrypted backup](backup-and-restore.md) before upgrading. Restoring it
preserves peer identities and revocations. Keep the original appliance off while a restored copy
uses the same server identity.

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
