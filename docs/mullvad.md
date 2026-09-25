# Mullvad VPN provider

ExitLane integrates Mullvad as a direct WireGuard egress provider. It does not install, start or
control the Mullvad desktop app, CLI or `mullvad-daemon`. ExitLane owns the egress interface,
policy-routing table and forwarded-traffic killswitch; WireGuard ingress remains a separate
interface and responsibility.

This guide describes the direct integration in **0.3.0-rc.2**. Use the supported
[Debian 13 `amd64` appliance](deployment.md); the qualified Proxmox configuration is a privileged
LXC. The integration currently provides IPv4 egress.

## Set up and connect

1. Keep local console access available and create a verified encrypted backup if the appliance
   already holds configuration. Use an active Mullvad account with an available device slot.
2. During the wizard, select Mullvad. On an existing appliance, open **VPN**, select **Mullvad VPN**
   and follow its sign-in action. Enter the 16-digit account number in the authenticated WebUI.
   ExitLane creates and owns one device for this appliance; no Mullvad app installation is needed.
3. Confirm that the provider reports **Signed in**. Provision ingress before starting the outbound
   connection; readiness verification requires that ingress interface to exist.
4. Set up the separate WireGuard ingress and import its client profile on the router. Choose the
   ingress name once; `wg-mullvad` is reserved and cannot be used for ingress. The router's policy
   determines which clients or VLANs enter ExitLane.
5. Select Mullvad as the active provider, choose a country or relay and connect. Wait for
   **Connected** before relying on it for client traffic. ExitLane verifies the configured peer
   and usable data path before accepting the connection.
6. Enable the ExitLane killswitch if those clients must stay blocked after a deliberate disconnect.
   Keep the management network outside the client routing policy.
7. From a routed client, verify internet access and the expected VPN exit. Test DNS through the
   tunnel, for example with `dig @10.64.0.1 example.com` and
   `dig +tcp @10.64.0.1 example.com`. Configure that client's or router's DNS policy accordingly;
   changing the appliance's resolver alone does not change client DNS.

Country and relay changes keep the router's ingress profile unchanged. Regenerating that ingress
profile is a separate action: it replaces the router's keypair and requires importing the new profile.

## Disconnect, protection and sign-out

| Situation | Routed client behavior |
| --- | --- |
| Mullvad connected | Protected IPv4 uses the Mullvad tunnel; protected IPv6 is blocked. |
| Connection pending, tunnel unexpectedly lost, or restored generation awaiting reconnect | Mandatory routing protection blocks unverified egress, even with the optional killswitch off. |
| Explicit disconnect, optional killswitch enabled | Client forwarding remains blocked until a usable active provider is available. |
| Explicit disconnect, optional killswitch disabled | Client traffic may use direct egress through the host's normal route. |

The optional killswitch setting and the mandatory Mullvad routing guard have different purposes.
Choose the optional killswitch according to the desired behavior when you deliberately stop the VPN.
Management access continues over the host's normal route.

Disconnect before ending the Mullvad session. Sign-out removes only ExitLane's registered device;
it also makes backups containing that device identity unusable for reconnection. To migrate using
a backup, keep the original appliance shut down and restore the existing identity on the replacement.
Do not sign out on the original or run both appliances with the same identity. See
[backup and restore](backup-and-restore.md#mullvad-identity-and-appliance-migration).

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
for protected ingress, interface-bound probes and the exact provider-assigned IPv4 source. The
host continues to use `main` for SSH, WebUI,
Mullvad API access and the relay underlay path. Table `51820` always has an ExitLane-owned
unreachable default before it receives the live `wg-mullvad` default, so tunnel loss cannot fall
through to plaintext egress.

The exact source rule also catches kernel-generated replies with no interface binding. It precedes
management routing and remains, with the unreachable default, until reboot even after disconnect
or sign-out. Previously used provider addresses are therefore reserved as sources for the current
boot; no account or key is retained in these rules. An address already assigned to another local
interface is rejected. The kernel local-table rule remains first.

Connect and relay-switch transactions save a generation and relay intent, arm the guard, replace
the interface, verify the exact ingress/table/interface route, then require both an active
dataplane probe and a handshake for exactly the configured peer. Only then is the generation
committed. A failed switch restores the previous generation when it can be proven; otherwise the
owned unreachable route remains fail closed.

At boot, `exitlane-provider-egress.service` restores the guarded table, ingress and source rules before
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

## Connection failures and recovery

If sign-in fails, check the account number, account availability and device slots in Mullvad's
account management. Retry an uncertain registration on the same appliance so ExitLane can reconcile
the existing public key. Do not remove unrelated Mullvad devices to make the error disappear.

An explicit relay request is attempted for that relay only. Country selection chooses an eligible
relay; availability is not guaranteed by its catalog entry. If readiness times out, ExitLane reports
`vpn_connect_timeout` and restores the previous proven generation where possible. Otherwise it
keeps protected forwarding blocked. Select another relay or retry after checking provider status;
ExitLane does not silently substitute a different country.

Choose the WireGuard ingress interface name during first setup. Once configured, changing its name
through the provisioning API is rejected: leaving an older ingress enabled could bypass the new
interface's routing policy. Regeneration using the existing name remains supported. `wg-mullvad`
is reserved for provider egress.

If activation reports `legacy_mullvad_runtime_conflict`, follow the legacy-conflict inspection
above. If it reports a routing resource conflict, inspect table `51820` and policy rules from the
local console; do not flush shared routing or firewall state. Keep client forwarding blocked until
ownership is understood. The Activity view and provider status expose safe error codes for diagnosis.

Backup restore holds forwarding for both the old and restored ingress while replacing data. It
explicitly reinstalls the mandatory provider routing guard before starting ingress and the
application, including when the optional killswitch was disabled in the backup. Reconnect after
restore to establish a new proven tunnel. A failed restore recovers the previous database, master
key and WireGuard files; a failed recovery keeps forwarding blocked for local operator recovery.

## Release limitations

- IPv6 through Mullvad is not supported; protected IPv6 is blocked.
- One commercial provider is active at a time. Signing in to both providers does not combine them.
- No automatic switch to another relay or country is promised after an unavailable relay.
- This integration does not expose the Mullvad app's full feature set, such as multihop or obfuscation.
- Direct exposure of the management API to the internet is unsupported.
- A restored appliance must reconnect explicitly. If the recorded device was revoked, it requires
  deliberate account/device recovery; restore never silently registers a replacement.
