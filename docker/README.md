# Docker runtime

The image in this directory is intended for UI and API development only. It is not a supported
VPN gateway deployment: the image does not contain the NordVPN CLI and cannot control a NordVPN
daemon running on the Docker host.

Do not mount the Docker socket, broad host directories, or arbitrary host-command interfaces to
work around this boundary. ExitLane's supported deployment is native systemd execution on the
same dedicated Debian VM or LXC where the NordVPN client and daemon run. Use:

```bash
sudo ./installer/install-debian.sh
```

The native service and an interactive `nordvpn status` command then communicate with the same
local `nordvpnd` instance.
