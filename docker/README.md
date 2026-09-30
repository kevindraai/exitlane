# Docker runtime

The image in this directory is intended for UI and API development only. It is **not a supported
VPN gateway deployment**. The [Docker appliance feasibility assessment](../docs/docker-appliance-feasibility.md)
records the capability matrix and the missing network, lifecycle and recovery proof.

The Compose example binds management TCP only to host loopback, publishes no WireGuard UDP port,
drops all Linux capabilities and gives the container no host device. Use a trusted local browser
or an explicitly configured development reverse proxy. Its named `/data` volume holds both the
development database and master key; protect or delete that volume deliberately. Removing the
container does not remove the volume. This development setup cannot route protected client traffic.

Do not mount the Docker socket, broad host directories, or arbitrary host-command interfaces to
work around this boundary. ExitLane's supported deployment is native systemd execution on the
same dedicated Debian VM or LXC where the NordVPN client and daemon run. Use:

```bash
sudo ./installer/install-debian.sh
```

The native service and an interactive `nordvpn status` command then communicate with the same
local `nordvpnd` instance.
