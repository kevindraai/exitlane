# ExitLane killswitch

The ExitLane killswitch is a system-level, provider-independent protection for
forwarded client traffic. It is distinct from any provider-client killswitch.

Mullvad's built-in connection kill switch remains owned by the Mullvad client while connecting or
connected. Mullvad **Lockdown Mode** is separate and is explicitly kept off by ExitLane's gateway
baseline, because it would also block host traffic after an intentional disconnect. ExitLane does
not advertise provider-killswitch management for Mullvad; its appliance killswitch remains the
policy layer for forwarded WireGuard/LAN traffic.

Mullvad's separate `mullvad-early-boot-blocking.service` is also not the ExitLane appliance
killswitch. An ExitLane-owned systemd condition prevents that upstream unit from applying firewall
state even if a package install or upgrade enables it again. A disconnected provider is accepted
only when no provider-owned `table inet mullvad` remains.

When enabled, ExitLane owns only `table inet exitlane_killswitch`. Its forward
hook protects WireGuard ingress and explicitly configured routed LAN/VLAN
interfaces. Host input and output are not hooked, so the web interface, SSH,
local recovery and provider reconnect traffic remain available. Established
return traffic and configured local CIDRs are allowed.

With a usable tunnel, protected IPv4 traffic is released only to the provider
interface and is masqueraded there. IPv6 is released only when the provider
reports protected IPv6 egress; otherwise it remains blocked without changing
host-wide IPv6 settings.

When the tunnel is unavailable, all other protected forwarding is dropped.
UDP and TCP port 53 are explicitly dropped before the final guard, so there is
no public DNS exception. Local DNS is possible only through an explicitly
allowlisted local CIDR. Provider DNS and connection setup use host output and
are not blocked.

Provider network facts include the observed, validated interface and truthful IP-family support.
Mullvad remains IPv4-only in the current ExitLane contract. Multiple connected provider tunnels or
an inactive connected provider are ambiguous egress and therefore produce a fail-closed provider
conflict instead of silently choosing an interface.

Boot restoration is performed by `exitlane-killswitch.service` before
`network-pre.target`; configured systems start closed and are released only
after verified provider facts. Recovery is available locally:

```console
sudo exitlane-cli killswitch-status
sudo exitlane-cli disable-killswitch
```

Disable requires typing `DISABLE EXITLANE KILLSWITCH`, removes only ExitLane's
table, synchronizes the setting and revokes existing web sessions.

Run the isolated nftables/reboot test on a disposable host or LXC:

```console
sudo ./scripts/test_killswitch_netns.sh
```
