# Mullvad launch qualification — 2026-09-25

This is pre-merge candidate evidence, not a published-release qualification. It supplements
[the initial live validation](mullvad-live-validation-2026-09-25.md). The work order authorizes
investigation, fixes, isolated tests, commits and pushes to PR #62; merge and publication remain
separate actions.

## Source and test surfaces

- Direct-integration baseline: `3c2ba61284097e4160655a83d307a25a0a1b6ecc`.
- Guard/restore/ingress corrections: `fbce67e`.
- Installer mode preservation and CI audit corrections: `6088bc57fdc2973d9bbbd908a2aeb49b6bf1e819`.
- Earlier tested runtime archive SHA-256:
  `066b50078f83b0752f8f01c45703540fb9279245b2e9e074e80061eddfee44ed`.
  This contains the `fbce67e` runtime. The corrected installer tested separately has SHA-256
  `ec16b4eb7d5d68f2ff8a494dd51fc7ce21590c596e4513f62f74fd5fbc870dc6`.
- Final runtime: `3782a461f810a42d2a4d5c4094efad144018710a`, following source guard commit `5422095`.
  Final source archive SHA-256: `40506c9593ac5bbb7cba87b5ccaf1b742108ca3bca030963e1ace71f1123419e`.
  The normal installer completed successfully on VM128.
- Native Debian 13 amd64 LXC, provisioned through the authorized runner: VM128 for real-account
  network qualification; VM100 for published-release upgrade/rollback; VM129 for synthetic cold
  recovery. These are disposable test installations, not production.
- Source transfers use temporary SSH keys removed in a `finally` block. The explicitly authorized
  cross-host recovery trial additionally transfers a secret-bearing backup bundle through a private
  runner directory to the designated recovery appliance, then removes the temporary copies. No credentials, configurations,
  raw pcaps or database contents are included in repository evidence.

## Findings resolved

| Finding | Correction and evidence |
| --- | --- |
| Root execution hid CI fixtures writing to `/etc/exitlane` | Isolate WireGuard paths in the three affected fixtures; reproduce and pass as UID 65534 with a deliberately unwritable default data path. |
| Custom ingress used the wrong settings key | Read canonical `wireguard_interface`, retaining legacy fallback; regressions cover actual custom ingress rules and invalid configuration. |
| Renaming ingress left the previous tunnel outside later provider protection | Reject configured-interface renames before mutation, serialize initial provisioning with provider operations, and retain same-name regeneration. |
| Ingress could claim the provider interface | Reserve `wg-mullvad`; independent provider preflight rejects identical ingress and egress before any command. |
| Restore could expose traffic before its mandatory route guard | Hold the union of old/restored ingress in an nftables forwarding guard; explicitly restore routing/firewall policy before ingress/application start, including optional killswitch-off backups. |
| Failed restore omitted WireGuard files and could alter key permissions | Recover database, master key and every ingress configuration together; retain mode 0600 and fail closed when recovery fails. |
| Installer recovery recursively narrowed original file modes | Keep copied modes under root-owned 0700 recovery directories; live corruption/rollback proves exact contents and modes. |
| CI audit queried unpublished ExitLane and repeatedly received PyPI 503 | Skip the sole editable application distribution; continue auditing every installed external runtime/development dependency. Local audit reports no known vulnerabilities. |
| Source-directory upgrades could retain vulnerable AnyIO despite the updated lock | Declare `anyio>=4.14.2,<5` in runtime metadata. The exact installer command retained 4.10.0 with old metadata and upgraded to 4.15.1 with corrected metadata; `pip check` passed and all 64 locked package versions remained unchanged. |

## Additional packet finding and source protection

A stricter repeated capture reproduced four physical-uplink TCP resets during restore/reconnect:
160 bytes, zero application payload, source equal to the provider-assigned IPv4 address and
destination Mullvad DNS. Directional captures and an independent host OUTPUT counter confirmed
they were locally generated; the forwarded-traffic counter was correctly zero. Consequently,
the earlier zero-packet sample alone was insufficient for a GO decision.

The correction adds an exact provider `/32` source selector before management routing and retains
it with the unreachable default until reboot, including across disconnect/sign-out/restore.
Ownership review additionally required both IPv4 and IPv6 table checks before cleanup, including
exact deletion candidates with extra selectors. The final code passed 82 focused regressions and
independent review returned **Approve** on `3782a46`. Namespace tests exercise a real source-bound
UDP socket without `SO_BINDTODEVICE`, a competing management-priority rule, kernel local-table
precedence, late sends after interface deletion and the unaffected management source.
Source-only teardown protection avoids temporarily diverting another provider's ingress.

## Live network and restore qualification

The root-only [live harness](../../scripts/qa_mullvad_live.py) uses a real WireGuard client namespace,
continuous IPv4/IPv6 and DNS UDP/TCP probes, a physical-uplink packet capture and a post-filter
forward counter. It exercises explicit relay switching, an injected unavailable relay, tunnel
removal, disconnect, real backup restore and failed-restore rollback. Capture validity, positive
client traffic and the existence of the counter are required assertions.

The first complete corrected-runtime run observed 896 client packets and zero physical plaintext
packets, with a zero-packet/zero-byte post-filter uplink counter. The initial development run is
excluded: it incorrectly started traffic before the optional killswitch had been enabled. The final
harness additionally requires successful capture decoding and positive IPv6 evidence.

The decisive run on `3782a46` passed with **1,217 client packets**, including **293 IPv6 packets**,
**zero physical plaintext packets**, and independent forward and host-OUTPUT counters both
**0 packets / 0 bytes**. Both capture processes and all five readers/counter queries exited zero.
The harness waits for capture headers before starting traffic and checks exact source-rule order,
the unreachable fallback and real source-bound UDP sends after restore, tunnel deletion and
disconnect. Installed CLI/provider/routing/lifecycle files matched the source archive. Harness
SHA-256: `406ace9d71fb5216f859204f9610d674477c43de7f6983383ea7b6c3a761d8c4`
(the harness at `decb9af`). Subsequent CodeQL review removed its unnecessary plaintext passphrase
file: the checked-in harness keeps that generated value only in memory and places its encrypted
backup under the existing temporary directory. The tested restore operations already used the
in-memory value. Runtime and packet assertions are unchanged; the live run is attributed to its
actual harness revision rather than claimed as a rerun of this cleanup change.

- Relays `nl-ams-wg-004`, `nl-ams-wg-005`, `de-ber-wg-001` and `au-adl-wg-301` connected in roughly
  1.5–3.7 seconds. The previously observed naturally unavailable relay was not reproduced.
- DNS through `10.64.0.1` passed over both UDP and TCP, and the client passed the separate lossless
  five-packet dataplane gate.
- Dropping only the selected German relay's WireGuard underlay produced `vpn_connect_timeout`
  after about 44 seconds. The exact previous proven generation was restored. No product retry
  change was warranted by this evidence; explicit relay identity is preserved and another relay
  can be selected after a failure.
- Deleting `wg-mullvad` while the optional killswitch was disabled left protected route lookup
  unreachable; reconnect succeeded.
- Backups recording an active Mullvad generation and optional killswitch disabled were restored
  onto both disconnected and active target states. The provider identity and master key were
  preserved, old sessions returned 401, and client routing remained blocked before reconnect.
- Injecting a failed post-restore health check recovered the previous settings, master key and
  WireGuard files, removed the temporary guard after healthy recovery and preserved the remote
  device set. Reconnect succeeded without device registration.
- External API/WebUI sampling showed only the expected service-stop windows during restore.
  Initial repeated anonymous SSH-banner probes triggered OpenSSH's documented local anti-abuse
  penalty (confirmed in sshd journal); those drops are excluded as network-availability evidence.

To repeat on the dedicated test appliance, first configure `qa-router` at `10.99.99.2` through
WireGuard ingress on UDP 51820, authenticate the Mullvad test account and supply a root-only
administrator JSON file. Install the test-only prerequisites (`tcpdump`, `dnsutils`, `iproute2`,
`wireguard-tools`, `nftables`, `iputils-ping`, Python); the cross-host HTTPS extension also uses
`curl`. The harness refuses missing commands/readiness script before mutation. Run from the
reviewed checkout using its installed Python environment:

```sh
/opt/exitlane/venv/bin/python scripts/qa_mullvad_live.py --confirm-disposable \
  --admin-file /root/exitlane-qa-admin.json
```

The harness creates a root-only encrypted temporary backup for the recovery scenarios, keeps its
passphrase only in memory, and removes the backup, namespace, temporary key and capture table.
Successful captures are removed; failed captures
are retained locally in a unique root-only directory for diagnosis. Test credentials/backups must be
removed and the registered device reconciled when the qualification is finished.

## Upgrade and security evidence

- Upgrade source was published tag `v0.2.0`, peeled commit
  `c5f0d8614eb1bdbf0f55c3714ff39d6144aea2b3`. Its package still reports `0.2.0rc1`; no version claim
  was inferred from the tag name. The old release needed its missing `/var/lib/exitlane` directory
  created before startup; the candidate already fixes that clean-install defect.
- Upgrade preserves users/settings, keys, addresses, peers, defaults, unit overrides, version and
  timezone. Legacy Nord-bound WireGuard forwarding lines are deliberately migrated to the current
  provider-neutral rules; their semantics and all unchanged lines were checked explicitly.
- Idempotent reinstall matched 15 critical files and 97 installed code files exactly.
- Injected late-upgrade corruption exited with the intentional status 77, then rollback restored
  all checked bytes and modes. Database integrity, administrator login, health and the original
  active WireGuard identity passed.
- On VM128, 16 lifecycle tests passed as an unprivileged user. An additional eight malicious archive
  cases were rejected: traversal, absolute path, symlink, hardlink, FIFO, directory, duplicate entry
  and excessive compression. Active data/service state was preserved.
- Bounded loopback web validation completed 54 requests at 10:35:57 UTC: public/authenticated and
  unauthenticated protected GETs, HEAD/OPTIONS, path/query and proxy/CORS probes. No HTTP 5xx,
  credential reflection or missing security-header finding. Protected routes returned 401;
  traversal returned 404 and malformed input 422. Scanner sessions were removed.
- Three installed units passed `systemd-analyze verify`; required directories and secret files were
  root 0700/0600. The documented systemd exposure score remains 7.7 because the appliance needs root
  network administration; this is an accepted architecture limitation, not a passing score.
- Three actual test secrets compared in memory did not occur in the last 300 service-journal lines.
  TLS/HSTS/Secure-cookie behavior and browser execution were not rerun on this HTTP-only appliance;
  corresponding backend regressions and passive CI remain separate evidence.

## Cold recovery and deterministic gates

The VM100 upgrade/rollback and VM129 cold-recovery runs used the earlier `fbce67e` runtime
archive and corrected `6088bc5` installer identified above. The subsequent source guard is covered
by final-runtime VM128 restore, teardown and active-boot tests; these earlier cold-recovery results
are not presented as a rerun of `3782a46`.

VM129 was given a custom `wg-office` ingress and generated test administrator/MFA/session state,
plus synthetic encrypted provider state with an active generation. No valid external provider
account was used. Its local encrypted backup survived removal of the original database, master
key and WireGuard files. A fresh installation generated a different master key and a different
`wg-before` ingress before restore.

Restore recovered the original database/key/WireGuard and encrypted provider state; revoked old
sessions, MFA challenges and pending enrollments; and accepted the original administrator's MFA.
It removed/disabled `wg-before`, enabled `wg-office`, armed unreachable IPv4/IPv6 defaults and bound
the policy rules to the custom restored interface. Protected route lookup failed and management
health passed. Cold boot repeated those assertions and confirmed the guard unit became active
before the restored ingress unit. VM100 and VM129 were stopped and retained with root-only test
evidence.

The initial real-account backup transfer was rejected by automatic approval review because the
prior authorization did not specifically cover exporting that secret-bearing bundle. No transfer
occurred at that time. The user subsequently granted explicit permission for the temporary SSH
transfer, root/test-user-only access and cleanup. The following additional trial closes that gap.

## Authorized real-account recovery onto another appliance

Both source VM128 and recovery VM129 ran the approved `3782a46` runtime. VM129 was reinstalled
and cold-booted: its master key differed from the earlier installation, users/sessions/provider
secrets were all zero, and only loopback and the management interface remained. Seven critical
modules matched the approved source in both the service tree and installed package. Historical
synthetic recovery evidence was preserved separately.

A fresh test registration on VM128 produced an active-generation encrypted backup with the optional
killswitch disabled. The backup, generated recovery passphrase, temporary administrator details
and comparison metadata were transferred through the runner using SSH with host keys obtained
from the authorized provisioner. Directories were mode 0700 and files 0600. Bundle hashes matched;
the runner temporary directory and exact temporary SSH keys were removed automatically.

Before target restore, VM128 was disconnected with forwarding protected, its local provider state,
configuration, backup bundle and temporary administrator file were removed, and the VM was stopped.
Its remote device set was unchanged, leaving the copied identity available to VM129 alone.

Restore on VM129 recovered exactly the source master key, provider account/key/device identity and
WireGuard files. The previous session returned HTTP 401. Source/ingress rules and IPv4/IPv6
unreachable defaults were verified before reconnect. Administrator login and reconnect succeeded
without changing the remote device set. Management health at the target's own `172.16.135.129`
address returned HTTP 200 from the runner.

The initial packet-test attempt stopped before traffic because the clean target lacked `tcpdump`.
Its exact temporary namespace/link/table were removed, test tools were installed, and the harness
now checks required tools and the readiness script before authentication or mutation. An empty-PATH
regression exited with the expected prerequisite error. The subsequent live run uses the memory-only
backup passphrase behavior and an additional HTTPS check from the real WireGuard client.

The complete cross-host live run passed: **1,249 client packets**, including **301 IPv6 packets**,
**zero physical plaintext packets**, and forward/host-OUTPUT counters both **0 packets / 0 bytes**.
Both capture processes and all five capture/counter readers exited zero. Four relays, DNS UDP/TCP,
HTTPS with a confirmed Mullvad exit, forced relay timeout with exact-generation rollback, both
restore states, injected failed-health rollback and optional-killswitch-off tunnel deletion passed.
The temporary HTTPS harness SHA-256 is
`7013dcdea193ffea2e1a1fbee7a64dcb8c78371da133e461ca4f45a9b2eb17f6`; it uses the checked-in
harness plus the reviewed namespace HTTPS check. Local result log:
`/root/exitlane-crosshost-live-final.jsonl` on VM129.

The restored appliance also passed active-generation reboot: exact source and ingress guards
preceded ingress startup (monotonic timestamps `7446597930419` and `7446598473513`), management
returned HTTP 200 from the runner and reconnect succeeded. Final sign-out removed only the shared
test device (**3 → 2** remote devices, other IDs unchanged), while source protection remained.
The target bundle, backup, passphrase, temporary administrator file and SSH keys were removed;
restore staging/snapshots and QA namespaces were absent. Generated transfer secrets were absent
from the last 300 service-journal lines. Both source VM128 and recovery VM129 were stopped and
retained. The original runner credential file was not changed.

This proves recovery and client dataplane on the new appliance. The namespace client explicitly
selects that appliance; external router endpoint/DNS changes after moving management addresses
remain an operator action and are not automatically validated by this test.

CI on final runtime `3782a46` passed all required jobs: **627 backend tests**, **180 frontend tests**, shell checks,
CodeQL (both languages), dependency review, dependency audit, secret scanning, passive ZAP and
package build. [CI run](https://github.com/kevindraai/exitlane/actions/runs/36128140619),
[supply-chain run](https://github.com/kevindraai/exitlane/actions/runs/36128140585),
[CodeQL run](https://github.com/kevindraai/exitlane/actions/runs/36128140641),
[passive ZAP run](https://github.com/kevindraai/exitlane/actions/runs/36128140671).

Local Ruff/format, Bandit, installer syntax/ShellCheck and workflow-policy checks also passed.
Wheel and sdist were rebuilt using the declared build backend; their 101/137 entries contained
no keys, environments, databases, backups, logs, caches or recovery directories. SHA-256:

- Wheel: `55e2ca871769e168ecdb26506fa78a31cdbf3087565e6fc564400c29673cff8d`.
- Sdist: `9679e7ab3066bc169366e79ffee2a06b64b023d8dd4335285eb2025216ca3e95`.

## Final runtime qualification

The real-account transition capture and all CI checks passed on the reviewed runtime `3782a46`.
The same runtime produced the package hashes above; later evidence/harness-only changes do not
alter runtime or package inputs.

Active-generation reboot on the final runtime restored the exact source rule after the kernel
local-table rule, the unreachable route and protected ingress before reconnect. Guard and ingress
activation timestamps were respectively `7437830953769` and `7437831551472` microseconds on the
host monotonic clock. Management health returned HTTP 200 from the runner; reconnect succeeded.

Final sign-out removed exactly the owned device: remote count **3 → 2**, with the remaining device
IDs unchanged. Local provider secret state/configuration was removed while source protection
remained verified. The root-only QA backup/passphrase, generated administrator credential file and
three task-created upgrade snapshots were deleted. Temporary SSH authorization count was zero.
VM128 was stopped and retained, matching VM100/VM129; redacted local test logs and forensic
observations remain available. The original runner credential file was not modified.

## Promotion boundary

Independent code/security review of `3782a461f810a42d2a4d5c4094efad144018710a` returned **Approve**
after all identified implementation findings were closed. The final PR head adds only this evidence
and the validated harness; its check receipt is available under [PR #62 checks](https://github.com/kevindraai/exitlane/pull/62/checks).
Release still requires an approved merge, consistent new version metadata and final-main qualification under [the release checklist](../release-checklist.md).
No tag, merge or publication is included in this work order.

Candidate decision: **GO for merge review**. No code/security blocker remains on the qualified
runtime. Publication remains **NO-GO pending the separate release gates**; this evidence
does not authorize a merge, tag or deployment.
