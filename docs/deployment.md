# Deployment

For lifecycle operations, use the root-only
[backup and restore](backup-and-restore.md) and
[upgrade and recovery](upgrade-and-recovery.md) procedures. A portable backup
must be encrypted and verified before an upgrade. Local pre-upgrade recovery
directories are plaintext, host-bound rollback material and must remain mode
`0700`.

## Local administrator recovery

The Debian installer installs `/usr/local/sbin/exitlane-cli` with root-owned executable
permissions and preserves Exitlane's database during upgrades. If the administrator password is
forgotten, open a terminal on the Exitlane host and run:

```bash
sudo exitlane-cli reset-password
```

Input is interactive and is not echoed. A successful reset revokes every browser session. Sign in
again with the new password and confirm the password-reset event in Activity.

For a reverse-proxy configuration lockout, inspect or reset the database-backed values locally:

```bash
sudo exitlane-cli network-status
sudo exitlane-cli reset-network-security
```

The reset requires explicit confirmation and revokes every browser session. Environment
overrides retain precedence and must be corrected in the service configuration.

Exitlane is currently designed as a single service on a dedicated Debian 13 `amd64` host or LXC.
That is the supported 0.3.0-rc.1 appliance baseline; other Debian releases and architectures are not
supported release targets. The installer creates an isolated Python environment, installs the
systemd unit, and prepares configuration, data, and log locations.

ExitLane must run natively in the gateway VM or LXC. NordVPN uses `nordvpn`/`nordvpnd`; Mullvad uses
ExitLane's own `wg-mullvad` interface and must not have an active Mullvad app daemon or firewall
table. The Docker image is for UI/API development and is not a supported VPN gateway. Do not expose
the Docker socket or mount broad host paths to bridge that boundary.

The systemd service gives provider tooling a private writable home under `/var/lib/exitlane` while
retaining `ProtectHome=true`. ExitLane does not mount host command or Docker control sockets.

## Prerequisites

The host needs systemd, outbound internet access, `/dev/net/tun`, and permission to create and
manage WireGuard interfaces. A Proxmox LXC must be configured accordingly; the currently tested
baseline is a privileged container. Unprivileged LXC is not a supported release target.
See [Proxmox LXC](proxmox-lxc.md).

Use the published release tag. The following command becomes available when `v0.3.0-rc.1` is
published; do not substitute an unreviewed development branch for an appliance deployment:

```bash
git clone --branch v0.3.0-rc.1 --depth 1 https://github.com/kevindraai/exitlane.git
cd exitlane
sudo ./installer/install-debian.sh
```

After installation, open `http://<host>:8787` from the trusted management network and complete the
wizard. The router imports the generated WireGuard client configuration and owns the policy that
selects which traffic uses Exitlane. See [Router integrations](router-integrations.md).

## First-run checklist

1. Create the local administrator and enable MFA after completing setup. Store recovery codes
   somewhere other than the appliance.
2. Choose NordVPN, Mullvad or direct egress. For Mullvad, follow the
   [account and device setup](mullvad.md#set-up-and-connect) instructions; the Mullvad app is not required.
3. Choose the WireGuard ingress name before provisioning. A configured interface cannot be renamed
   through the API; regeneration retains its name and replaces the client identity.
4. Import the generated profile on the router, then apply the router's routing policy to a test
   client first. Configure client DNS through the intended tunnel path.
5. Enable the ExitLane killswitch if clients must stay offline after an explicit VPN disconnect,
   then connect the selected provider. Direct-egress setups can continue without a VPN connection.
6. From that client, check internet access, DNS and the public exit address. Check that management
   access remains available from its trusted network, then create an encrypted backup.

Verify the application first:

```bash
sudo systemctl status exitlane
curl --fail http://127.0.0.1:8787/api/health
```

For a connected Mullvad appliance, also inspect `sudo wg show wg-mullvad` and
`sudo ip -4 route show table 51820`. On a NordVPN appliance, use `sudo nordvpn status`.
An absent Mullvad interface while disconnected is expected. A successful health response confirms
the management service; client traffic and DNS need their own checks.

## Security and operations

Do not expose port 8787 directly to the public internet. Limit the management interface at the
network boundary and protect local configuration, state, and logs. Configure HTTPS using the
[reverse-proxy guide](deployment/reverse-proxy.md); forwarding headers are ignored unless their
direct peer is explicitly trusted.

The installer creates `/etc/exitlane/secret.key` with mode `0600` and preserves it during an
upgrade. Preserve the database and key together. If the key is lost, restore that pair from a
verified backup. For an MFA lockout, local `sudo exitlane-cli disable-mfa` is available; it does not
recover encrypted Mullvad credentials or the provider's WireGuard identity if the key is lost.

ExitLane provides root-only encrypted appliance backup and strictly validated restore commands.
Create and verify a portable backup before upgrading, retain the installer's protected local
recovery snapshot until post-upgrade validation is complete, and test changes on a separate LXC
before applying them to a live gateway. See the
[backup and restore](backup-and-restore.md) and
[upgrade and recovery](upgrade-and-recovery.md) guides.
