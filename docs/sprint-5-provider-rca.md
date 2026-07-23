# Sprint 5 provider root-cause analysis

## Scope

This analysis compares the Sprint 5 candidate LXC with CT110, a clean Debian
13 reference LXC. CT110 received only the official NordVPN repository package
and the unmodified candidate installer before provider tests began.

## Findings

NordVPN 5.2 creates `/run/nordvpn/nordvpnd.sock` as `root:nordvpn` with mode
`0660`; its parent directory is `root:nordvpn` with mode `0750`. The package
adds the installing desktop/login user to `nordvpn`. Root can access the socket
without supplementary group membership. On the clean reference, `nordvpn
status`, `nordvpn account`, token login, and connect all worked as root while
root had only its primary group. ExitLane therefore must not add root to the
`nordvpn` group or configure `SupplementaryGroups=nordvpn`.

The daemon runs as root with primary group `nordvpn`. The CLI connects to the
Unix socket above. ExitLane runs provider subprocesses as root with
`HOME=/var/lib/exitlane`, a fixed `PATH`, and no dependency on a session D-Bus
or `XDG_RUNTIME_DIR`. The same token login succeeded both as the regular test
user and with the exact minimal ExitLane root environment.

Debian 13 no longer creates the legacy `/var/run/utmp`; it uses `wtmpdb`.
NordVPN 5.2 hardcodes `/var/run/utmp` in its `NorduserProcessMonitor` and logs
the following after every boot:

```text
Error when starting norduser monitor: creating file watcher:
adding file to watcher: no such file or directory
```

This is reproducible on both candidate and clean reference LXCs and is
independent of ExitLane. Creating an empty compatibility file would only hide
the error: Debian 13 would still not update that legacy file. ExitLane does not
apply that workaround. The daemon's credential-aware gRPC middleware starts a
per-user `norduserd` for an invoking CLI client, and root provider operations
remain functional despite the failed background session monitor.

The initially observed token-login timeout was reproduced once on the clean
reference while the ExitLane killswitch was disabled. During that attempt
there was no DNS or port 443 traffic and no login RPC in `nordvpnd`; nftables
did not change. The same API route later completed in about one second without
code, group, permission, or environment changes. Direct user and exact
ExitLane-root invocations also succeeded. The evidence places the transient
stall in NordVPN's local CLI/gRPC runtime, before its control plane. It does not
support a firewall, token, group, or environment cause. ExitLane reports such
an unconfirmed condition as `unknown`/`timeout` and does not infer
authentication from a network interface.

## Firewall and management

With the ExitLane killswitch disabled, the first `nordvpn connect` made SSH
unreachable. The console showed a healthy connected NordLynx/UDP tunnel. After
disconnect, SSH returned and only the baseline `table inet filter` remained.
Official settings showed `LAN Discovery: disabled`.

After applying ExitLane's existing provider-defaults flow, official settings
showed `LAN Discovery: enabled`. A subsequent connect completed without losing
SSH. NordVPN then installed its own `table inet nordvpn`, including private
IPv4 LAN ranges in `allowlist_subnets`. This table is provider-owned and
separate from `table inet exitlane_killswitch`.

The same defaults enable NordVPN auto-connect. With ExitLane configured, the
early boot service first installs the fail-closed client-forwarding table.
NordVPN can then reconnect using host traffic, after which the backend monitor
atomically releases protected IPv4 forwarding. NordVPN's provider Kill Switch
remains explicitly disabled; auto-connect and the ExitLane system killswitch
are separate concepts.

The ExitLane table protects forwarded client traffic only. It does not add a
general host-output drop, so provider DNS, authentication, and tunnel setup do
not require an ExitLane firewall bypass. Captures confirmed DNS and QUIC/443
control-plane traffic during successful login. No nftables delta occurred
during login.

## Provider facts

Authentication comes only from `nordvpn account`; connected state, protocol,
server, and technology come only from `nordvpn status`. NordVPN 5.2 has no JSON
status option and does not print the kernel interface name. The NordVPN adapter
therefore translates the official connected technology `NORDLYNX` to the
provider-specific `nordlynx` interface contract. The generic killswitch never
contains that name. If technology is absent or unknown, the adapter supplies
no interface and the killswitch remains fail closed.

## `resolv.conf`

NordVPN 5.2 marks `/etc/resolv.conf` immutable while connected.

During a graceful shutdown or service stop this flag is removed by the
official NordVPN daemon. This was reproduced on CT110: `nordvpn connect` set
the flag and both `nordvpn disconnect` and a normal `systemctl stop nordvpnd`
removed it.

An unexpected host crash or forced container termination may interrupt that
cleanup. In that situation Proxmox can fail to regenerate its managed
`resolv.conf` during the next LXC start.

This is provider/runtime behaviour and is not caused by ExitLane. ExitLane
intentionally does not modify inode flags or install Proxmox-side recovery
hooks.

Recovery consists of clearing the immutable flag from the offline container
filesystem before restarting the container.
