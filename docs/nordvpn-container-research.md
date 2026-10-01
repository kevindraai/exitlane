# NordVPN container research decision

Research date: 2026-10-01. Work item: [#98](https://github.com/kevindraai/exitlane/issues/98).
ExitLane baseline: `d9e6e85fe2acb028bb85b570ee5197db8a753ca6`.

## Decision: NOT SUITABLE

The current stock official NordVPN Linux client **5.4.0** cannot connect under ExitLane's
existing qualified Docker contract. Its mandatory IPv6 sysctl write fails against Docker's
read-only `/proc/sys`, even when the desired value was supplied at container creation.
There is no supported client setting transferring that operation to ExitLane. Keep native
NordVPN support unchanged and container NordVPN explicitly unavailable. Do not start an
implementation program or claim provider parity through a modified kernel view, command
shim, patched client or broader privileges.

This is a decision about the current supported client and qualified runtime, not a claim
that every custom kernel or OCI configuration makes NordVPN impossible. Reopen this track
only after a material upstream change provides a supported externally owned IPv6 mode or
otherwise removes the incompatibility. Repeating the same architecture without that change
does not advance qualification. The Docker v1 direct providers remain Mullvad, PIA and
imported Proton WireGuard profiles; Docker remains experimental/unsupported overall.

## Current first-party authority

- [Official release 5.4.0](https://github.com/NordSecurity/nordvpn-linux/releases/tag/5.4.0),
  published 2026-09-07, immutable source commit
  `c81971da41c318883129deec1a148d1577687ce1`.
- Nord's signed stable amd64 APT index currently also supplies 5.4.0. The
  [package](https://repo.nordvpn.com/deb/nordvpn/debian/pool/main/n/nordvpn/nordvpn_5.4.0_amd64.deb)
  is 44,698,830 bytes, SHA-256
  `57669d407215f34cd80b56d0b953dcd0ab8dcd3413ed18c646f666e0582e013a`.
  Its digest/size match the index, whose digest/size match the verified
  [InRelease](https://repo.nordvpn.com/deb/nordvpn/debian/dists/stable/InRelease).
  The signature was checked against Nord's HTTPS-delivered
  [key](https://repo.nordvpn.com/gpg/nordvpn_public.asc), fingerprint
  `BC5480EFEC5C081CE5BCFBE26B219E535C964CA1`. No independent fingerprint root or
  reproducible source-to-binary equivalence is claimed. Extracted init/service/socket files
  match the pinned source; bundled binary components were not audited exhaustively.
- Nord's [official Docker recipe](https://support.nordvpn.com/hc/en-us/articles/20465811527057-How-to-build-the-NordVPN-Docker-image)
  uses Ubuntu 24.04, APT installation, init.d plus a sleep and shell, and adds NET_ADMIN
  **to Docker's default capabilities**. It does not establish drop-ALL/NET_ADMIN-only,
  read-only-root, supervisor, forwarding or ExitLane fail-closed compatibility. Its
  `disable_ipv6=0` example enables IPv6 despite contrary prose; it is not protection proof.
  The release's own
  [container entrypoint](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/ci/docker/nordvpn/entrypoint.sh)
  also installs temporary INPUT/OUTPUT iptables drops and enables Nord's killswitch.
  Copying that recipe would introduce a second firewall owner.

## Decisive IPv6 incompatibility

The pinned [`start` path](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/networker/networker.go#L296-L301)
calls `ipv6Blocker.Block()` unconditionally before VPN start and propagates errors.
The [`restart` path](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/networker/networker.go#L468-L473)
does the same after restarting the tunnel and configuring DNS. This is independent of
the firewall/routing switches. [`Ipv6.Block`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/ipv6/ipv6.go#L22-L49)
uses `net.ipv6.conf.all.disable_ipv6=1`; stop/failure paths can restore the previous value.
The [`setter`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/kernel/sysctl_setter.go#L33-L62)
explicitly writes even when the current value is already 1, invoking
[`sysctl -w`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/kernel/kernel.go#L14-L18).

A bounded, network-none probe used the refreshed ExitLane image
`sha256:91ccff4f957b58f0af5a33f0fd19638c43c70320a654b85cbad9ceba11ca2b79`,
read-only root, drop ALL/add NET_ADMIN, no-new-privileges and a creation-time
`net.ipv6.conf.all.disable_ipv6=1`. The process read `1`, effective capabilities
`0000000000001000`, then attempting to write the same value returned **EROFS (errno 30)**.
This proves the required filesystem operation fails under the retained default protections;
it is not an end-to-end execution of NordVPN or proof about every kernel/engine version.
The local engine was 26.1.5; ExitLane's qualified host minimum remains Engine 28. The
read-only sysctl contract, rather than this older engine alone, is the incompatibility.

Alternatives were explicitly challenged:

- Creation-time sysctls do not avoid the client's repeated write.
- Privileged execution, SYS_ADMIN remounts, host networking/PID, Docker socket, host daemon
  and broad host mounts violate the work order. Disabling default system-path protection
  to expose writable kernel controls abandons the qualified minimal contract.
- An **additional** OCI masked directory can hide the IPv6 sysctl tree while preserving
  other default masks/read-only paths. It need not broaden privileges or weaken isolation:
  [OCI supports masking](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
  and [Moby exposes MaskedPaths](https://github.com/moby/moby/blob/v28.5.2/api/types/container/hostconfig.go).
  However the stock client then interprets hidden state as “IPv6 module is not enabled”;
  this is a compatibility workaround, not a supported external-owner configuration.
  Masking `conf/all` also hides ExitLane's current startup forwarding check. Merely masking
  a file is not evidence that the client's existence/value checks will bypass it.
  No masking bypass was executed or qualified. Reject capability hiding under the explicit
  instruction not to hack around incompatibility merely to claim parity.
- A custom no-IPv6 kernel is outside the supported general Docker-host contract; client
  forks, fake-success sysctl wrappers and binary patches are not the supported client model.

## Ownership assessment

This table records the proposed boundaries and their disposition; it does **not** describe
an implemented or qualified NordVPN container adapter.

| Concern | ExitLane | NordVPN client | Docker host | Disposition |
| --- | --- | --- | --- | --- |
| Protected ingress | Sole owner of ingress and admission | None | Published-port transport | Retain existing boundary |
| Provider tunnel | Orchestrates selection and validates usability | Creates/owns `nordlynx` | Transport only | Potential delegation; not qualified |
| Forwarding/firewall | Sole owner of protected policy and permanent guard | Must have firewall and killswitch off | Bridge/NAT only | Client has real firewall no-op mode |
| Policy routing | Sole owner of protected route/rule transaction | Routing off, no managed default/policy rules | Host bridge routing | Client has real routing no-op mode |
| Protected DNS | Owns UDP/TCP capture and provider-bound routing | Must not change protected policy | None | Requires separate proof; not implemented |
| Control-plane DNS | Requires stable namespace resolver | Normally writes/restores resolver | Supplies container resolver | Explicit non-owner-writable resolver potentially prevents Nord writes; unqualified |
| IPv6 protection | Owns guard and validates actual kernel state | Mandatory write/restore of namespace IPv6 sysctl | Creation-time namespace setup | **Unresolved incompatibility under qualified contract** |
| Killswitch | Sole protected-ingress owner | Off; internal events must remain firewall no-ops | None | Never rely on Nord killswitch |
| Provider authentication | Brokers masked local prompt | Owns token/session/provider keys | None | Requires explicit sensitive-state contract |
| Process supervision | PID 1 lifecycle and guarded restart | Foreground daemon plus optional user child | Container lifecycle | Source supports foreground; minimal-cap behavior unproven |
| Host firewall | None | None | Docker/operator only | No host access allowed |

Firewall/routing are **not inherently irreducible competing owners**. With killswitch and
Meshnet off, supported settings disable the
[`firewall wrapper`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/daemon/firewall/firewall.go#L40-L112)
and [`routing agents`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/daemon/rpc_set_routing.go).
Native ExitLane deliberately enables Nord firewall/routing for its different gateway model;
changing those shared native defaults is not an acceptable container adaptation.

DNS also requires precise treatment. `set dns off` clears custom servers and returns to
Nord's defaults, rather than disabling all DNS ownership. Without host resolver services,
Nord falls back to
[`resolv.conf`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/daemon/dns/dns_resolvconf_file.go#L24-L105).
It honors a non-owner-writable/immutable file. Its
[`FileWritable`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/internal/filesystem.go#L345-L355)
checks mode 0200, **not mount writability**: an ordinary 0644 file on a read-only bind
still takes the write/error path. A deliberately managed 0444 resolver could bound this
owner, but was not implemented or tested, and DNS restoration/fallback must remain outside
protected traffic. DNS is additional qualification work, not the decisive impossibility.

## Processes, privileges and state

The packaged service runs `/usr/sbin/nordvpnd` directly. Its
[`manual socket listener`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/cmd/daemon/main.go#L715-L760)
works without systemd socket activation; foreground supervision is source-supported.
Init.d backgrounds the process, so it should not be used as the supervisor's real child.
The daemon handles INT/TERM/HUP/USR1, disconnects and stops child services on shutdown;
that is not an independent fail-closed guarantee or a proven bounded shutdown deadline.

NET_ADMIN and the existing explicit `/dev/net/tun` device would remain the candidate ceiling;
the official example retaining default capabilities does not prove that ceiling sufficient.
The source can choose native TUN or fall back to BoringTun. The non-snap RPC middleware
attempts `norduserd` with changed groups, which can fail without SETGID; the middleware logs
that error and continues. Do not infer an essential VPN failure from this optional path or
add capabilities speculatively. No current daemon/library capability trace was executed.

The [`default paths`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/internal/constants.go#L118-L161)
would require explicit ownership and seeding:

| Path | Required treatment if upstream later becomes suitable |
| --- | --- |
| `/var/lib/nordvpn/data/settings.dat` | Root-only 0600 plaintext `.DAT` + JSON containing token, NordLynx key, OpenVPN credentials and settings; sensitive durable provider state |
| `data/install.dat`, `install_static.dat`, `recent_connections.dat` | Legacy migration material, persistent identity and connection history; deliberate persistence policy |
| `data/moose.db` and SQLite sidecars | Event state can be created even with analytics off; complete write trace required |
| `data/{servers,countries,version,insights}.dat`, `/var/lib/nordvpn/conf/` | Seeded provider catalog and remote configuration/cache; attributable executable does not freeze remote config |
| `/var/lib/nordvpn/backup/resolv.conf` | Namespace-local resolver backup; prevent stale restore across recreation |
| `/run/nordvpn/` | Ephemeral socket/PID, privately recreated; never restore stale sockets |
| CLI/user `$HOME/.config/nordvpn`, `$HOME/.cache/nordvpn` | Bounded private writable paths, including CLI logs; redact secrets |
| `/etc/resolv.conf`, `/etc/hosts` | Explicit resolver boundary; Meshnet off; no broad writable system mount |

PREFIX_DATA/COMMON/STATIC affect multiple paths, including socket/log paths, and are not
independent arbitrary-directory remaps. Config writes are ordinary writes, not ExitLane's
crash-consistent state journal. A future design must define quiesced encrypted backup and
restore/re-auth behavior; current native backups intentionally exclude host-wide Nord state.

## Authentication, reconnect and failure behavior

The [official token flow](https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-log-in-to-NordVPN-without-a-GUI-using-a-token)
and pinned source support masked interactive token input. Keep ExitLane's PTY secret boundary;
never place tokens in command arguments, logs, image layers or attached evidence. The client
persists the entered token and tunnel credentials in its own state. Disconnect is separate
from logout; ordinary logout invalidates the token, and restoring old state cannot undo
remote revocation. A local year-9999 token marker does not prove server-side non-expiry.

Autoconnect off disables boot autoconnect, not all background actions. The
[`network-change listener`](https://github.com/NordSecurity/nordvpn-linux/blob/c81971da41c318883129deec1a148d1577687ce1/networker/vpn.go#L70-L173)
can reapply DNS, restart the tunnel and invoke internal killswitch operations. A future
adapter would need generation-bound observation and transaction handling for these events.
Provider status alone must never grant forwarding. Source-provider rollback must revalidate
the old tunnel; failed rollback, process death, stale proof and namespace restart remain
blocked by ExitLane's independent permanent guard. Management continuity is a separate gate.

If upstream resolves the incompatibility, qualification must first cover account-free
synthetic/unit/lifecycle cases: startup without configuration; auth-state transitions;
connect/disconnect/reconnect; both switch directions; failed connect/daemon/client death;
rollback success/failure; restart/recreation/persistence; resolver ownership; IPv4 and IPv6
guards; and management continuity. Packet evidence must verify protected ingress never
uses plaintext container egress, including transient background reconnects and UDP/TCP DNS.
Only bounded testing with the owner's authorized account can establish live-provider proof;
CI must not require credentials and availability remains off until all relevant proof exists.

## Evidence and review boundaries

Research used official documents, immutable source and non-executing package extraction.
No Nord daemon/client was started, no provider account used, and no host firewall/sysctl
changed. The isolated Docker probe used only its own private namespace. No image was
published and no publication workflow dispatched. Download verification establishes integrity
against the official HTTPS/signing-key model, not an independent authenticity root.

The package verification, full process/state research and sysctl receipt are retained under
`/tmp/exitlane-nordvpn-research/` for this execution. Primary immutable source links above
provide durable reviewable evidence; no secrets are included. Architecture review must use
this exact decision artifact, and the documentation PR must receive immutable-head review
before merge. #97/#90 remain open at the separate publication/support boundary; unfixed
Debian HIGH advisories do not change this architectural decision or freeze other engineering.
