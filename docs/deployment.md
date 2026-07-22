# Deployment

Exitlane is currently designed as a single service on a dedicated Debian 12 or 13 host or LXC.
The supported installer creates an isolated Python environment, installs the systemd unit, and
prepares configuration, data, and log locations.

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

## Security and operations

Do not expose port 8787 directly to the public internet. Limit the management interface at the
network boundary and protect local configuration, state, and logs. HTTPS can be terminated by a
trusted reverse proxy; secure session cookies must be enabled for an HTTPS-only deployment.

The current release has no built-in update, rollback, backup, or restore workflow. Preserve the
appliance's configuration and data directories using an operator-managed backup process, and test
changes on a separate LXC before applying them to a live gateway.
