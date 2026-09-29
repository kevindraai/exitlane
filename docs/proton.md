# Proton VPN profile import

ExitLane supports Proton VPN through WireGuard profiles generated in your Proton account. Download each `.conf` file from Proton VPN's **Downloads → WireGuard configuration** page, then import it in **VPN management → Proton VPN**. You can import several profiles and give each a local display name and optional two-letter country code. The profile selector uses the normal ExitLane provider controls. No Proton account password is entered into ExitLane.

ExitLane parses only the WireGuard address, private key, DNS address, peer public key, optional preshared key, endpoint, and bounded MTU/keepalive fields it needs. It rejects hooks, table directives, multiple peers, split routes, malformed keys, and oversized files. The original uploaded file is discarded after normalization. Imported keys and active generation state are encrypted using the appliance master key. A root-only WireGuard file exists while the tunnel is active and is removed on disconnect. The API and ordinary status views return only non-secret profile metadata. Disconnect before deleting an active profile.

Proton's current profiles may include IPv6 addresses and `::/0`. ExitLane validates these fields but keeps its existing IPv4 egress and IPv6 blocking contract. It does not advertise IPv6 VPN egress. The protected routing table, killswitch, readiness probes, switching, and startup recovery are the same ExitLane direct-provider lifecycle used by Mullvad and PIA.

Proton's desktop application, NetworkManager, gnome-keyring, and current Linux CLI are not dependencies of this integration. Proton [does not currently support the CLI on headless setups](https://protonvpn.com/blog/protonvpn-linux-app), which is why ExitLane uses imported profiles on a Debian appliance. A profile is local configuration, not an account sign-in session. A profile can expire or be revoked externally; reimport a newly generated profile when needed.

Synthetic profiles and a simulated WireGuard peer are used for automated qualification. Live Proton account and public VPN egress proof remain outstanding until an administrator provides safe QA profiles. No live Proton connection is claimed.

References: [Download Proton WireGuard profiles](https://protonvpn.com/support/wireguard-configurations) and [manual WireGuard on Linux](https://protonvpn.com/support/wireguard-linux).
