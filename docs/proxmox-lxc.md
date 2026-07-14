# Proxmox LXC

Tested baseline: Debian 12, privileged LXC and `/dev/net/tun`. Add to `/etc/pve/lxc/<CTID>.conf`:

```ini
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```
