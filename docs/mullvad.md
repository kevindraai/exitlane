# Mullvad VPN provider

ExitLane integrates Mullvad as a direct WireGuard egress provider. It does not install, start or
control the Mullvad desktop app, CLI or `mullvad-daemon`. ExitLane owns the egress interface,
policy-routing table and forwarded-traffic killswitch; WireGuard ingress remains a separate
interface and responsibility.

The implementation follows Mullvad's official
[WireGuard configuration guidance](https://mullvad.net/en/help/wireguard-and-mullvad-vpn) and the
endpoint/field usage in Mullvad's official
[`wg-tools`](https://github.com/mullvad/wg-tools). Those HTTP endpoints are implementation details,
not a separately versioned public API contract, so schema validation and live qualification are
required before release.

## Authentication and device ownership

The WebUI accepts a 16-digit Mullvad account number over the authenticated same-origin API.
ExitLane generates one X25519/WireGuard keypair and persists a `pending` registration record before
the first remote device mutation. After a timeout it lists devices and reconciles only the exact
public key; it never guesses, creates a second key automatically, deletes another device, or
silently replaces a revoked device.

The account number, private key and bound device metadata are encrypted in SQLite with the
appliance master key. Access tokens exist only in process memory for a short bounded lifetime.
The active root-only WireGuard configuration is mode `0600`; responses, Activity metadata and logs
contain neither account number, token nor private key. Preserve `/etc/exitlane/secret.key` and the
database together in backup and recovery.

Ending the Mullvad session removes exactly ExitLane's recorded device remotely before deleting its
local encrypted state. If the remote result is uncertain, local state is retained for a safe retry.
An active connection must be disconnected first.

## Relay and tunnel model

Only active WireGuard relays with strictly validated identifiers, a public numeric IPv4 endpoint
and a valid 32-byte public key are eligible. The first release scope is IPv4-only:

- provider interface: `wg-mullvad`;
- provider policy table: `51820`;
- ExitLane route protocol: `196`;
- WireGuard UDP port: `51820`;
- MTU: `1380` by default (`1280` is troubleshooting-only);
- provider DNS address for live tests: `10.64.0.1`.

`Table = off` prevents `wg-quick` from changing the host default route. ExitLane adds policy rules
only for configured protected ingress interfaces. The host continues to use `main` for SSH, WebUI,
Mullvad API access and the relay underlay path. Table `51820` always has an ExitLane-owned
unreachable default before it receives the live `wg-mullvad` default, so tunnel loss cannot fall
through to plaintext egress.

Connect and relay-switch transactions save a generation and relay intent, arm the guard, replace
the interface, verify the exact ingress/table/interface route, then require both an active
dataplane probe and a handshake for exactly the configured peer. Only then is the generation
committed. A failed switch restores the previous generation when it can be proven; otherwise the
owned unreachable route remains fail closed.

At boot, `exitlane-provider-egress.service` restores the guarded table and ingress rules before
normal networking whenever encrypted state records an active or pending Mullvad generation. Every
systemd-managed `wg-quick` ingress directly requires this successful guard restoration. This
applies even when the optional nftables killswitch setting is off. Normal status polling observes
the exact peer without generating traffic and cannot release an interrupted transaction.

## DNS and leak protection

ExitLane does not replace the appliance's `/etc/resolv.conf` as proof of client DNS behavior. Live
acceptance sends DNS from the actual protected ingress namespace/client to `10.64.0.1` and proves
that the query traverses `wg-mullvad`. The generic nftables policy allows protected IPv4 only via
the reported provider interface and blocks IPv6 for this provider. No public DNS or physical-uplink
exception exists for forwarded clients.

## Legacy Mullvad app conflict

An active `mullvad-daemon` or an existing `table inet mullvad` is a conflicting network owner.
ExitLane reports `legacy_mullvad_runtime_conflict` and refuses activation. It never deletes or
flushes that table automatically.

Inspect before manual cleanup:

```console
sudo systemctl is-active mullvad-daemon.service
sudo nft list table inet mullvad
sudo ip -4 rule show
sudo ip -4 route show table 51820
sudo wg show wg-mullvad
```

If this host previously used the Mullvad app, disconnect it, disable its daemon and uninstall it
using Mullvad's documented procedure. Inspect the exact nftables table before removing any stale
provider-owned state. Never flush the complete nftables ruleset. Old ExitLane package-helper units
and drop-ins may be removed only after the app/package has been retired and the direct provider
reports no legacy conflict.

## Live acceptance

Run this on the disposable network runner/appliance with a test account:

1. Sign in and confirm exactly one new device with the recorded public key.
2. Perform at least three cold connects and verify route, exact-peer handshake and forwarded IPv4.
3. Switch to a different relay and verify generation commit or proven rollback.
4. Resolve through `10.64.0.1` from protected ingress; capture the physical uplink and prove zero
   plaintext forwarded IPv4, IPv6 and DNS packets.
5. Confirm SSH/WebUI/API management traffic continues over the host main route.
6. Kill the tunnel interface and confirm table `51820` remains unreachable for protected ingress.
7. Reconnect, reboot with an active generation, and confirm the boot guard is installed before
   forwarded traffic can flow.
8. Sign out and confirm only ExitLane's bound device is removed and no secret appears in logs,
   process arguments, API responses or Activity.

Unit and namespace simulations are necessary evidence but do not replace these real-account,
real-relay checks.
