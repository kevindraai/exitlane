# Proxmox LXC

Supported 0.2.0 baseline: Debian 13 on `amd64`, privileged LXC and `/dev/net/tun`. Other Debian
releases and architectures are not supported release targets. Add to
`/etc/pve/lxc/<CTID>.conf`:

```ini
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```
