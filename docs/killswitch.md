# ExitLane killswitch

The ExitLane killswitch is a system-level, provider-independent protection for
forwarded client traffic. It is distinct from any provider-client killswitch.

Direct Mullvad egress has no provider-app killswitch. ExitLane owns both the provider policy table's
unreachable fallback and the optional nftables killswitch. An active legacy Mullvad daemon or
`table inet mullvad` is a hard conflict, not a second protection layer.

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

During a connected-provider handoff, ExitLane persists a separate transition flag and temporarily
installs the closed form of the same `exitlane_killswitch` table even when the operator killswitch
setting is off. This protects forwarded WireGuard/LAN clients while leaving host input, output,
SSH, HTTP, management routing and provider control traffic available. Normal reconcile and web
killswitch mutations cannot release this state. It is cleared only after the target has connected
and its egress and management postconditions are proven, or after rollback has proven the source
provider restored. If the process or host restarts mid-transition, boot restoration re-arms the
closed rules. The runtime monitor can only reconcile the closed form; it never releases a
transaction guard. A subsequent explicit retry or disconnect may claim an inherited recovery
guard, while an active provider-switch transaction retains sole ownership. This mechanism does not
alter, bypass or add DNS exceptions to provider-owned firewall policy.

Boot restoration is performed by `exitlane-killswitch.service` and
`exitlane-provider-egress.service` before `network-pre.target`; configured, interrupted-transition
or previously active direct-provider systems start closed and are released
only after verified provider facts. Recovery is available locally:

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
