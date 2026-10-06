# Deployment

For Docker, start with the [Docker deployment Quick Start](docker-deployment.md#quick-start).
The commands below describe native Debian; the Docker guide covers its separate lifecycle.

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
That is the native appliance target for 1.0.0; other Debian releases and architectures are not
supported release targets. The installer creates an isolated Python environment, installs the
systemd unit, and prepares configuration, data, and log locations.

The supported deployment method remains native Debian in the gateway VM or privileged LXC.
NordVPN uses `nordvpn`/`nordvpnd`; Mullvad, PIA and imported Proton profiles use ExitLane-owned
direct WireGuard interfaces. Mullvad must not have an active app daemon or provider firewall table.

The appliance Docker v1 contract is rootful Linux Docker Engine >=28, Compose v2 and amd64.
It supports Mullvad, PIA and imported Proton WireGuard, with permanent provider-or-block
protection. NordVPN remains native-only. Follow the [operator Quick Start](docker-deployment.md)
for the versioned image, explicit LAN bindings, minimum privileges and durable state.
Verify stable publication and exact final-image acceptance in the [v1 release receipts](release-notes/1.0.0.md#release-and-image-receipts).
The original development Compose surface is not this appliance path.

The systemd service gives provider tooling a private writable home under `/var/lib/exitlane` while
retaining `ProtectHome=true`. ExitLane does not mount host command or Docker control sockets.

## Prerequisites

The host needs systemd, outbound internet access, `/dev/net/tun`, and permission to create and
manage WireGuard interfaces. A Proxmox LXC must be configured accordingly; the currently tested
baseline is a privileged container. Unprivileged LXC is not a supported release target.
See [Proxmox LXC](proxmox-lxc.md).
On the PVE host, the ordinary installation route is:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/kevindraai/exitlane/main/installer/proxmox.sh)"
```

It creates a new privileged Debian 13 LXC with default or advanced settings and one plan
confirmation, then reuses the same Debian installer at the resolved published tag.
See the linked guide for release selection, trust and inspect-first operation.

Use the published release tag. The following command becomes available when `v1.0.0` is
published; do not substitute an unreviewed development branch for an appliance deployment:

```bash
git clone --branch v1.0.0 --depth 1 https://github.com/kevindraai/exitlane.git
cd exitlane
sudo ./installer/install-debian.sh
```

After installation, open `http://<host>:8787` from the trusted management network and complete the
wizard. The router imports the generated WireGuard client configuration and owns the policy that
selects which traffic uses Exitlane. See [Router integrations](router-integrations.md).

Exact stable native installation, upgrades from qualified rc.4/v1 RC and recovery must have
source-bound receipts in the [stable release notes](release-notes/1.0.0.md). Prior receipts
remain historical evidence rather than being relabelled as final-source results.

## First-run checklist

1. Create the local administrator and enable MFA after completing setup. Store recovery codes
   somewhere other than the appliance.
2. Choose no provider for native direct egress, or configure any combination of NordVPN, Mullvad,
   PIA and imported Proton profiles. Follow the [NordVPN client/token guide](nordvpn.md#install-and-sign-in),
   [Mullvad account/device guide](mullvad.md#set-up-and-connect), [PIA guide](pia.md), or
   [Proton profile-import guide](proton.md). Select exactly one provider for active egress.
   PIA and Proton are implemented with synthetic/native-kernel qualification; live provider proof
   remains outstanding for both.
3. Choose the WireGuard ingress name before provisioning. A configured interface cannot be renamed
   through the API. The wizard creates the first named peer; later devices share that interface.
   A device can be renamed independently, and regeneration replaces only its client identity.
4. Import the first peer's profile on the router, then apply the router's routing policy to a test
   client first. Configure client DNS through the intended tunnel path. Add a separate named peer
   for every other consumer that connects directly; never share one profile across devices.
5. Enable the ExitLane killswitch if clients must stay offline after an explicit VPN disconnect,
   then connect the selected provider. Direct-egress setups can continue without a VPN connection.
6. From each intended consumer, check internet access, DNS and the public exit address. Confirm
   separate handshake/endpoint/traffic attribution in WireGuard management. Check that management
   access remains available from its trusted network, then create and verify an encrypted backup.

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
