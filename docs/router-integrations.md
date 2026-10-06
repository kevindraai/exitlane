# Router integrations

ExitLane generates generic WireGuard client configurations. Import a router's own peer into UniFi,
MikroTik, ASUSWRT-Merlin, OpenWrt, pfSense or OPNsense and use that platform's policy-routing rules.
Router-specific exporters are planned; the core remains router-neutral.

## Give every consumer its own peer

In the WireGuard management page, create a named peer for each router, device or container that
connects directly to ExitLane. Use one profile per consumer; do not copy the router profile into
another device. Separate keys prevent endpoint flapping, attribute handshake/endpoint/traffic
correctly and let you revoke one consumer independently.

For example:

1. Keep `UniFi Gateway` as the router peer. Import its configuration into the router and select
   the clients or VLANs that should use the tunnel in the router's policy rules.
2. Add `Deluge - Synology` for a NAS container that connects directly. Import only this new
   configuration into that consumer.
3. Both consumers use the same ExitLane ingress interface and active provider. Changing the
   provider affects their shared egress; regenerating or revoking the NAS peer affects only it.

A router forwarding many LAN clients is one WireGuard consumer and needs one peer. Those LAN
clients do not each need an ExitLane peer unless they establish their own WireGuard tunnel.

After regeneration, replace only the selected consumer's configuration. After revocation, its old
configuration cannot authenticate. Migration from a valid v1 installation preserves the original
router configuration and identity. See [WireGuard device management](wireguard-configuration.md)
for lifecycle, status semantics and the authenticated API.
