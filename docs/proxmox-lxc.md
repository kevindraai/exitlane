# Proxmox LXC

The qualified container baseline for ExitLane 0.3.0-rc.2 is **Debian 13, `amd64`, privileged LXC**.
Unprivileged containers, other Debian releases and other architectures are not supported release
targets. ExitLane runs natively inside the container and needs systemd, WireGuard, nftables and
permission to administer its network namespace.

## Create the container

Release qualification uses 2 vCPUs, 2 GiB RAM and a 16 GiB disk. These are a reference configuration,
not a guaranteed throughput target. Allow additional storage for encrypted backups and local
installer recovery snapshots.

Create a privileged container from a Debian 13 `amd64` template. Give it a reachable address on
the trusted management network, working DNS and outbound internet access. Keep the Proxmox console
available during initial setup and network recovery.

On the Proxmox host, add these entries to `/etc/pve/lxc/<CTID>.conf` while the container is stopped:

```ini
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

Start the container and verify inside it:

```bash
cat /etc/os-release
dpkg --print-architecture
test -c /dev/net/tun
systemctl --version
```

The OS must report Debian 13 and the architecture must be `amd64`. The installer also checks that
it can create a WireGuard interface. A failed capability check must be resolved in the container
configuration before continuing; installing another VPN application does not supply those privileges.

## Install and connect

Follow the [deployment guide](deployment.md) for the tagged installation command and first-run
checks. Permit the selected WireGuard ingress UDP port from the router to the container; the
default is `51820`. Limit TCP port `8787` to the trusted management network or an explicitly trusted
reverse proxy. Preserve access to Proxmox independently of the ExitLane data path.

For Mullvad, use the [direct WireGuard provider guide](mullvad.md). Do not run the Mullvad app daemon
alongside ExitLane's direct integration. NordVPN uses its own managed Linux client.

## Backup and migration

Keep an encrypted [appliance backup](backup-and-restore.md) outside the container. A Proxmox snapshot
is useful for host recovery but does not replace verification of ExitLane's database, master key,
provider identity and client configuration.

Never start a clone and its original gateway simultaneously with the same restored Mullvad or
WireGuard identity. Shut down the original before migration and validate the restored appliance
before redirecting client traffic. Deleting the original Mullvad device by signing out also revokes
the identity held in its backups.
