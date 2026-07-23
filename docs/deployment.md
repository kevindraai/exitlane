# Deployment

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

Exitlane is currently designed as a single service on a dedicated Debian 12 or 13 host or LXC.
The supported installer creates an isolated Python environment, installs the systemd unit, and
prepares configuration, data, and log locations.

ExitLane must run natively in the same VM or LXC as the NordVPN CLI and `nordvpnd`. The Docker
image is for UI/API development and is not a supported VPN gateway: a container cannot see or
control the host's NordVPN installation. Do not expose the Docker socket or mount broad host
paths to bridge that boundary.

The systemd service gives the NordVPN CLI a private writable home under `/var/lib/exitlane` while
retaining `ProtectHome=true`. The CLI communicates with the local daemon through its normal
runtime interface; ExitLane does not mount host command or Docker control sockets.

## Prerequisites

The host needs systemd, outbound internet access, `/dev/net/tun`, and permission to create and
manage WireGuard interfaces. A Proxmox LXC must be configured accordingly; the currently tested
baseline is a privileged container. See [Proxmox LXC](proxmox-lxc.md).

Run the installer from a repository checkout:

```bash
sudo ./installer/install-debian.sh
```

After installation, open `http://<host>:8787` from the trusted management network and complete the
wizard. The router imports the generated WireGuard client configuration and owns the policy that
selects which traffic uses Exitlane. See [Router integrations](router-integrations.md).

Verify on the appliance that ExitLane and the interactive CLI use the same runtime:

```bash
sudo systemctl status exitlane
sudo nordvpn status
curl --fail http://127.0.0.1:8787/api/health
```

## Security and operations

Do not expose port 8787 directly to the public internet. Limit the management interface at the
network boundary and protect local configuration, state, and logs. Configure HTTPS using the
[reverse-proxy guide](deployment/reverse-proxy.md); forwarding headers are ignored unless their
direct peer is explicitly trusted.

The installer creates `/etc/exitlane/secret.key` with mode `0600` and never replaces it during an
upgrade. Preserve the database and key together. Losing the key never bypasses MFA: run
`sudo exitlane-cli disable-mfa` locally and enroll again.

The current release has no built-in update, rollback, backup, or restore workflow. Preserve the
appliance's configuration and data directories using an operator-managed backup process, and test
changes on a separate LXC before applying them to a live gateway.
