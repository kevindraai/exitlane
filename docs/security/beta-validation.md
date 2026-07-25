# Beta candidate validation record

Candidate validation date: 2026-07-25 UTC. Target scope was exclusively
`172.16.130.81` (`test-exitlane`, Debian 13). The previously configured
`exitlane-test` SSH alias resolved to `172.16.130.129` and was not touched.
The correct existing alias was `exitlane-reference`. The deployment helper now
defaults to that alias and verifies the exact target IP before copying files.

## Completed evidence

- Installed exact alpha baseline
  `11bc3bf4ab4314d9812e67fdfff0c609ca783751` on the initially clean LXC.
- Alpha health returned `0.2.0-alpha.1`; database, master key, and WireGuard
  files were root-owned with mode `0600`.
- Created representative Dutch/Amsterdam/dark/dashboard settings, a local
  administrator, TOTP MFA, ten one-time recovery codes, one session, trusted
  proxy data, and WireGuard server/client configuration. No real provider token
  was stored.
- Upgraded alpha to beta with a root-only pre-upgrade recovery snapshot.
  Version `0.2.0-beta.1`, schema 1, settings, MFA, recovery codes, session,
  master key, and WireGuard configuration survived.
- Re-ran the beta installer successfully and idempotently.
- Created, inspected, and verified an encrypted four-component `.elb` backup.
- Changed persisted data, restored the backup, observed the previous data,
  retained MFA/WireGuard, revoked all sessions, and received healthy beta HTTP
  status before the restore command returned.
- Wrong passphrase and modified ciphertext both failed with the same safe
  `authentication_failed` code while active data and health remained intact.

## Findings produced by appliance testing

| Severity | Finding | Resolution / regression | Status |
| --- | --- | --- | --- |
| High | PEP 440 alpha `0.2.0a1` was misclassified as newer than the human beta string by `dpkg` | Compare installed PEP 440 version with explicit target `0.2.0b1`; installer regression | Resolved |
| High | Restore returned before HTTP health was established | Bounded local health wait; unhealthy restore triggers data rollback; regression simulates failed health | Resolved |
| High | Explicit installer `fail()` bypassed the `ERR` trap and rollback | `fail()` now invokes rollback directly; regression verifies the callback | Resolved |
| High | Rollback copied the recovery staging directory itself onto `/`, applying its `0700` mode to top-level directories | Restore only saved child entries into existing top-level directories; a filesystem regression verifies destination modes | Resolved and corrected rollback passed on appliance |
| Medium | Repository deploy alias pointed at `.129`, not the authorized `.81` target | Default to `exitlane-reference` and fail closed unless remote IP is exactly `.81` | Resolved |

## Recovery and completed follow-up

The rollback finding changed `/`, `/etc`, and `/opt` to mode `0700`. ExitLane
remained reachable and healthy. An authorized administrator restored `/`, after
which `/etc` and `/opt` were also identified and restored to their standard
`0755` modes. `/dev` remained `0755` and `/dev/null` remained `0666`.

The exact injected service-start failure was then repeated with the corrected
candidate. Automatic rollback restored code, SQLite, systemd unit, MFA state and
service health; SQLite integrity was `ok`; and `/`, `/etc`, `/opt`, `/var`,
`/home`, and `/dev` all remained `0755` while `/dev/null` remained `0666`.

A new encrypted backup was subsequently created and verified. `/etc/exitlane`
and `/opt/exitlane` were moved to a root-only quarantine, the beta was installed
as a clean appliance with zero users, and the backup was restored. Language,
timezone, MFA, ten unused recovery codes and WireGuard returned; sessions
remained revoked; SQLite integrity and HTTP health passed; and secret/database/
WireGuard files were `0600`. The temporary passphrase, backups and quarantine
were deleted after validation.

The NordVPN 5.2.0 package was installed through the fixed systemd helper.
Appliance testing found that the NordVPN CLI requires a writable HOME even for
`status`; `ProtectHome=true` correctly made `/root` read-only. The helper now
uses its existing root-only runtime directory as HOME while retaining all
sandbox properties. The exact installed unit then completed with result
`success`; `nordvpnd` and ExitLane remained active and NordVPN reported the safe
unauthenticated state `Disconnected`.

The real killswitch was enabled and reconciled without a tunnel. It reported
`enabled_waiting_for_tunnel`, effective fail-closed state, and an installed
firewall table while ExitLane health and host management remained available.
Disable removed only the ExitLane table; a temporary unrelated nftables
sentinel remained and was then cleaned up.

A bounded unauthenticated web matrix confirmed protected docs/OpenAPI/settings/
events/WireGuard routes, safe path and method variants, CSP and other security
headers, `no-store`, ignored untrusted forwarded headers, and HTTP 413 for an
approximately 1.1 MB request body. The public session-status endpoint also
returns 200 under an arbitrary Host header but exposes only generic
authentication/setup state; this matches the documented direct-access model.

An eleven-case, authentically encrypted malicious restore corpus exercised
traversal, absolute and nested paths, symlinks, duplicate entries, missing
manifest, unexpected files, checksum mismatch, future schema, invalid SQLite,
and excessive compression ratio. Every case failed with its expected safe error
before service mutation. The service activation timestamp, database, master key,
and WireGuard configurations remained unchanged; SQLite integrity and HTTP
health passed; no restore staging directory remained. The encrypted corpus,
passphrase, and generator were then deleted.

A temporary 48-byte-url-safe administrator password was generated and used
entirely inside a root process on the LXC. The existing TOTP secret was decrypted
only in that process to complete MFA; no recovery code was consumed. Secure
challenge/session cookies remained in memory and were sent only to the fixed
`172.16.130.81:8787` target with the configured trusted public Origin.

The bounded scan ran 5 public GETs, 14 authenticated GETs, 13 HEADs, 13 OPTIONS
and 42 read-only injection/header/path probes. Mutating credential, settings,
setup, provider, killswitch, WireGuard and notification routes were hard
excluded. It observed no HTTP 5xx or finding. The original password verifier was
restored, all temporary sessions and challenges were deleted, MFA and all ten
unused recovery codes remained, and service health passed. The root-only
credential, cookies, scanner and sanitized summary were removed. No ZAP context,
request archive or response artifact was created, and Activity metadata
contained no password, token or cookie fields.

A disposable NordVPN token was supplied as a root-owned `0600` regular file.
ExitLane read it through a no-follow, close-on-exec descriptor and submitted it
only to the CLI's private, echo-disabled terminal prompt. A concurrent scan of
process arguments and environments found no token. Login, provider defaults,
connection, disconnect/reconnect, token metadata/renewal, logout with token
retention, and a fresh login all passed. NordVPN's regular state files were
root-owned, inaccessible to other users, and limited to the intended daemon
group where applicable.

With the NordLynx tunnel present, two independent IPv4 observers and explicit
DNS queries over both UDP and TCP all observed the tunnel egress. The LXC had no
IPv6 address or route and the IPv6 observer was unreachable. The same matrix
passed from a temporary routed network namespace protected by ExitLane's real
nftables rules. After a deliberate disconnect, IPv4, IPv6, DNS/UDP, and DNS/TCP
were all blocked fail-closed. Reconnection restored the protected tunnel and
the complete matrix passed again.

Stopping `nordvpnd` produced the expected provider-unavailable state and engaged
the same four-way fail-closed behavior. ExitLane health, SSH management, and an
unrelated nftables sentinel survived disconnect, daemon loss, and recovery.
Restarting the daemon restored the tunnel and `enabled_protected` state.

Before cleanup, an exact-value in-memory scan found no disposable token in
process arguments/environments, ExitLane Activity/SQLite, system or provider
journals, CLI logs, the deployment candidate, `/tmp`, or test artifacts. Final
cleanup disconnected and logged out of NordVPN, disabled the ExitLane
killswitch, removed its test namespace and sentinel, deleted the token file,
candidate tree, and two test-only upgrade snapshots, and reset the temporary
routed-ingress setting. Post-cleanup checks confirmed those objects absent,
NordVPN signed out and disconnected, HTTP health 200, and SSH preserved.

Pull request #34 remains draft until all four required GitHub Actions workflows
are green on the final branch SHA.

The final local regression run passed 324 backend tests and 124 frontend test
definitions. Ruff check and format, Bandit, pip-audit, Python compilation,
JavaScript syntax, JSON and translation validation, Bash syntax, ShellCheck,
`git diff --check`, and wheel/sdist builds also passed. Package inspection found
no private-key material, databases, backups, provider credentials, sessions, or
unexpected generated files.
