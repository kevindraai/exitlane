# NordVPN provider

ExitLane manages the official NordVPN Linux client and its `nordvpnd` service. NordVPN provides
outbound NordLynx connectivity; the separate WireGuard ingress carries traffic from your router
to ExitLane. Changing the VPN country or provider does not require a new router profile.

Use the supported [Debian 13 `amd64` appliance](deployment.md). Native installation in the gateway
VM or supported privileged Proxmox LXC is required; the Docker development environment cannot
install or manage the NordVPN client.

## Install and sign in

1. Open the **VPN provider** step in the setup wizard and select **NordVPN**. On an appliance that
   has already completed setup, open **VPN → NordVPN**.
2. If NordVPN is not installed, choose **Install NordVPN**. This installs the official Linux client
   on the appliance and starts its service. Wait for installation and readiness checks to finish;
   installation alone does not sign you in or connect a tunnel.
3. Obtain an access token from your Nord Account as described below. Enter it in the masked token
   field in ExitLane and choose **Sign in**. Wait for the provider to report **Signed in**.
4. Complete the separate WireGuard ingress setup and import its client profile on your router.
   Configure the router's policy to send the intended clients or VLANs through that profile.
5. Select NordVPN as the active provider, choose a country or server, and connect. Wait for
   **Connected** before relying on the VPN for client traffic.
6. Enable the [ExitLane killswitch](killswitch.md) if those clients must stay offline when the VPN
   disconnects. From a routed client, check internet access, DNS and the public exit address.
   Confirm that SSH and the WebUI remain accessible from the management network.

NordVPN and Mullvad can both be configured, but only one commercial provider can be active at a
time. Selecting a provider for setup is separate from activating its outbound connection. If you
defer provider setup, routed clients can use direct internet egress; configure a provider later
under **VPN** when you want VPN protection.

## Get a NordVPN access token

Sign in to [Nord Account](https://my.nordaccount.com/), open **NordVPN**, then find **Advanced
settings → Get access token**. Complete email verification, choose **Generate new token** and
select the expiry you want. Copy the token while it is shown and enter it in ExitLane. Nord's
current steps and screenshots are in its official
[token login guide](https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-log-in-to-NordVPN-without-a-GUI-using-a-token).

The token is a secret. Use the access token for the Linux app; your account password and manual
OpenVPN service credentials are different credentials. Keep it out of screenshots, shell command
arguments, support messages and Activity exports. ExitLane supplies it through a masked local
provider prompt and does not store a reusable copy in its database. NordVPN manages the resulting
provider session. See [authentication](authentication.md#nordvpn-token-subprocess-boundary).

## Disconnect, sign out and replace a token

**Disconnect** stops the VPN tunnel while retaining the NordVPN sign-in session. With the optional
ExitLane killswitch enabled, protected forwarding stays blocked until a usable active tunnel is
available. With it disabled, a deliberate disconnect can allow direct egress.

**End current session** signs out of NordVPN and ends its active tunnel. ExitLane uses the normal
NordVPN logout action, which invalidates the token used for that session, including a non-expiring
token. Generate a new access token before signing in again. ExitLane does not use NordVPN's native
`--persist-token` option.

To replace a token, open **VPN → NordVPN**, choose **End current session** and confirm. Wait for
**Signed out**, then enter the new token and sign in. Reconnect afterwards. The client cannot
validate a replacement token while the current session remains signed in; ExitLane will not end
that session automatically merely because another token was entered.

## Gateway settings and DNS

ExitLane applies NordLynx, routing, LAN discovery and the NordVPN firewall for gateway operation.
It disables NordVPN's own killswitch, auto-connect and analytics. Use ExitLane's killswitch and
connection controls to manage forwarded clients; changing managed settings separately with the
NordVPN CLI can make the appliance's observed state differ from its required gateway settings.

Protected IPv4 uses the `nordlynx` interface. The ExitLane NordVPN integration does not report
protected IPv6 egress, so its killswitch blocks protected IPv6. Keep management access outside the
client routing policy. For protection and provider-switch behavior, see the
[killswitch guide](killswitch.md).

Configure DNS on the routed clients or their router and test it from those clients, including both
UDP and TCP DNS where applicable. A DNS query or public-IP check on the appliance itself does not
prove that client traffic uses the VPN. See [router integrations](router-integrations.md) and
[connection diagnostics](diagnostics.md).

## Installation and connection problems

| Symptom | Next step |
| --- | --- |
| NordVPN is not installed | Select NordVPN and use Install NordVPN. A working Mullvad configuration does not install NordVPN. |
| Installation failed or is still checking readiness | Read the installation status and use the offered retry action. Check appliance internet access and package-manager availability. |
| Provider is unavailable | Retry the status check and inspect the NordVPN service from the local console if it stays unavailable. |
| Token is invalid, expired or revoked | Generate a new Linux-app access token in Nord Account and sign in again. A token invalidated by logout cannot be reused. |
| Already signed in or replacement unsupported | End the current provider session deliberately before entering a different token. |
| Connect times out or status stays unknown | Keep client protection enabled, inspect Diagnostics and Activity, and retry after checking provider availability. |

These read-only commands help inspect the native installation from a trusted console:

```console
sudo systemctl status nordvpnd.service
sudo nordvpn status
sudo nordvpn settings
sudo journalctl -u exitlane-provider-install-nordvpn.service --no-pager -n 50
```

Review diagnostic output before sharing it. Do not flush shared firewall rules or change the
host's default route to bypass a failed connection check.

## Backup, restore and migration

ExitLane backups include its own configuration and ingress identity, but exclude NordVPN's
host-wide provider state and session. On a replacement appliance, install NordVPN and sign in
again deliberately, then reconnect and verify routed client traffic. Restoring an ExitLane backup
does not recreate a NordVPN session. Follow [backup and restore](backup-and-restore.md) and
[upgrade and recovery](upgrade-and-recovery.md) for the complete procedure.
