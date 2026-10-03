# Remaining release evidence — 2026-10-03

The reachable qualification work is complete within the recorded limits. No release, tag or image
was published. Commercial interoperability is blocked by unavailable authenticated provider/profile
material; the ordinary public rc.4 launcher gate requires separately authorized publication.
[#87](https://github.com/kevindraai/exitlane/issues/87) therefore remains open.

## Source and prior lifecycle evidence

Published rc.3 baseline: `5d97db3375cc8361e27c98b11bcc8ccf6c69a875`.
Reviewed native candidate: `941f7368368e1fbe2723f099c7f443d7435626d0`, runtime `0.3.0-rc.4`.
The completed fresh install, actual upgrade, idempotence, injected rollback, encrypted restore and
second-guest disaster recovery are retained in the
[PR #126 lifecycle receipt](https://github.com/kevindraai/exitlane/issues/87#issuecomment-5970830970).
Those receipts are reused explicitly; this work adds the previously missing active-provider,
upgrade-packet, current OS assurance and fresh launcher-helper evidence.

[PR #127](https://github.com/kevindraai/exitlane/pull/127) repairs only the provisioning helper,
its focused tests and documentation. The backend, frontend, ordinary Debian installer, systemd
units and provider/routing implementation are byte-identical to candidate `941f736`.
Successful helper source: `5659aeb65d96674bd7d623ccf35bd4b0866e59a2`, helper SHA-256
`12c724a24398b95051ab166364bdefbee8e79b3b59bd16c5783cd6808629beac`.
Final approval, merged-main identity and fresh hosted runs belong in the external issue/PR receipt,
so this source does not attempt to contain its own commit hash.

## Active provider and packets during the ordinary upgrade

An isolated privileged Debian 13 guest ran the genuine installed Proton-profile integration with
locally generated WireGuard keys and an owned synthetic endpoint. No commercial account or
external VPN endpoint was involved. The actual provider import/connect/status path selected an
active generation; the ordinary latency measurement populated one real ICMP-measured cache row.
The installed rc.3 baseline and rc.4 candidate inventories were verified against their exact sources.
The unmodified candidate `installer/install-debian.sh` performed the real upgrade.

The exact installer window lasted **8.421 seconds**. Each of ten numbered IPv4/IPv6 data UDP,
TCP SYN, ICMP and DNS UDP/TCP SYN streams had **80 observations at ingress inside that window**.
Each IPv4 stream had 80 provider-tunnel observations; IPv6 had zero, consistent with blocked
IPv6 egress. Maximum observed ingress gap was 0.217 seconds; first/last window-edge gaps were
below 0.072 seconds. The wider capture phase had 87 observations per stream and is not confused
with the exact installer window.

The actual kernel path used two WireGuard hops: protected client ingress and provider egress.
Baseline and post-upgrade real ICMP and UDP/TCP DNS round trips passed. Continuous TCP streams
were SYN attempts, not complete TCP DNS sessions. All 40 phase/stream counts and sequence IDs
reconciled. Real management-interface and synthetic-underlay positive controls, including all ten
marked IP protocol controls, validated observer/parser readiness. Physical original or quoted
plaintext markers, capture drops and unexplained errors were **zero**. An ordinary post-upgrade
provider disconnect exercised fail-closed IPv4/IPv6/DNS: 29 ingress observations per stream,
zero provider or physical plaintext observations.

Encrypted profile identity, active generation, cache values and relevant settings were preserved.
Master-secret and ingress/default file hashes were unchanged; no reconnection was required.
Exact topology cleanup and restored sysctl state passed. Separate runner sampling recorded
145 successful SSH TCP connections and 135 HTTP 200 health responses; ten HTTP failures occurred
during the intentional service restart. This is sampled TCP reachability, not uninterrupted HTTP
or authenticated SSH continuity. Real authenticated SSH is separately evidenced on the fresh
launcher guest below.

Private harness SHA-256:
`f12634bc099bcbd4e0c7a61333f68c97d092033fc5bd8d211a8d4fae09de257c`, independently approved
before execution and again against final captured evidence. Earlier failed attempts remain failed:
one DNS fixture copied EDNS request bytes into its reply; a later observer aborted when the
ordinary provider disconnect removed its interface. The repaired observer retires only a proven
removed/down/replaced provider interface and retains successful packet statistics. Uplink/ingress
loss, unexplained errors, drops or inadequate coverage still invalidate the result. No product
provider/routing change or weakened evidence threshold was introduced.

The existing reference runtime was inspected without reading credentials: no provider secret rows,
Nord signed out and disconnected. Thus live commercial provider interoperability cannot be completed
with available authorized runtime material. This synthetic result does not close that claim.

## Native OS advisory disposition

The [complete public-safe coverage index](native-os-advisories-2026-10-03.json) binds the actual final
Debian 13.7 inventory and scan. It retains **786** raw binary-package/advisory records:
8 CRITICAL, 184 HIGH, 269 MEDIUM, 311 LOW and 14 UNKNOWN. All **192 HIGH/CRITICAL records across
66 CVEs** match the independently reviewed prior CVE/binary-package index; unmatched count is zero.
No scanner fixed-version field exists at any severity. The preceding qualified inventory had
796 records (8/185/273/316/14): the exact ten removals are eight libpcap and two tcpdump QA-tool
records. Retained identities, severities and versions are unchanged; there are no new findings.
DNS qualification tooling adds no raw advisory finding. Neither inventory is described as clean.

Actual supported APT update/upgrade logs are retained. The prior final native maintenance transaction
upgraded 49 packages with no removals/new installs/not-upgraded packages; current fresh guests also
consumed supported updates. Zero prior supported-maintenance HIGH/CRITICAL records survive.
Current Python is 3.13.5-2+deb13u5, OpenSSL 3.5.7, Expat 2.8.3-1~deb13u1 and glibc 2.41-12+deb13u4.
No unsupported-suite substitution, scanner exclusion, severity downgrade or advisory waiver was used.
The actual installed venv has 30 audited third-party distributions, zero advisories and zero skips.

| Source family | Bounded disposition and retained risk |
| --- | --- |
| acl, ncurses, perl, systemd, util-linux | Supported-unfixed baseline/host findings retain the reviewed component and feature prerequisites; no new first-party mandatory patch was demonstrated. Operator maintenance owns supported updates. |
| Python 3.13 | Inspected backup uses bounded regular bytes from validated seekable tar, without extract/extractall or streaming filters. No first-party HTML/XML parser surface was established. Host tools and uninspected third-party consumers retain risk. |
| curl | Ordinary new-process explicit HTTPS lacks the reviewed STARTTLS/Negotiate/proxy-handle-reuse/schemeless SFTP prerequisites. Other operator/libcurl consumers remain outside that distinction. |
| OpenSSH | Hostile-server client rekey remains an operator/client surface. Current default and management Match observations give GSSAPI=no, DisableForwarding=no and PermitTunnel=no for the configuration-dependent server distinctions. Other Match branches are unqualified. |
| LMDB, libxml2, Expat | ExitLane uses SQLite; no first-party hostile LMDB/XML parser path was demonstrated. Expat is genuinely loaded; trusted-local D-Bus configuration is a separate observed surface. |
| gnupg2, vim, wget, setuptools, OS urllib3 | Reviewed operator/document/build/network prerequisites and bootstrap residuals remain explicit in the coverage index. Final venv audit does not cover OS tools or seed pip. |
| glibc | Prior short-search/environment trigger distinction remains bounded; CVE-2026-8674 stays OPEN as an availability residual. No universal libc exclusion is claimed. |

The initial upgraded guest still had D-Bus mapping deleted old Expat bytes. That evidence was retained;
a normal maintenance reboot resolved it. On the actual final guest, D-Bus and the ExitLane MainPID
mapped current Expat with exact device/inode correspondence, no deleted marker and no mapping errors.
Default and actual-source management SSH policy observations completed. Standard D-Bus configuration
objects were root-owned and nonwritable; the observed daemon used system mode without custom config.
This covers standard/custom roots and linked-object metadata, not arbitrary recursive XML includes,
static/transitive linkage, delayed plugins or proprietary provider dependencies.

All 12 actual installed-client loopback TLS controls passed on Python 3.13.5/OpenSSL 3.5.7:
Mullvad, PIA public and PIA pinned accepted valid certificates, and rejected unknown CA, wrong
hostname and expiration before sending HTTP. Client source hashes match candidate `941f736`.
This does not prove commercial accounts, public endpoint operation or pip bootstrap TLS.

Before/after ordinary upgrade observations bind the Debian ensurepip seed
`pip-25.1.1-py3-none-any.whl`, SHA-256
`20568e5d750393b2a331d6b261886cbe5d62aca3f54d49a39815b7474d34cd9c`, vendored urllib3 1.26.20.
Selected index/trusted-host/proxy/TLS overrides were empty; standard global/root/venv pip config
files and supplementary XDG/default overrides were absent. The installer used its ordinary trusted
package-origin policy. Malicious-peer/index-page exploitation and future origins are not certified;
trusted-origin bootstrap availability residuals remain owned and distinct from the clean final audit.
Fourteen UNKNOWN findings retain their raw status and bounded Python SNI/LZMA/Perl POD/telnet/groff
dispositions. MEDIUM/LOW findings are retained, not individually exploit-adjudicated. No additional
mandatory application-source fix was established by the reviewed bounded disposition.

## Public launcher qualification and repairs

The ordinary moving-main public one-liner ran as root in a real terminal on a disposable nested
Proxmox VE 9.2 host. Actual GitHub metadata resolved published rc.3, verified the tagged helper and
created a new Debian 13 LXC. The old published helper failed: explicit IPv6 manual configuration
was merged by ifupdown2 into DHCPv6 startup, blocking networking and management startup.
This public attempt remains **FAILED**; the existing release/tag was not changed.

Fresh candidate-helper trials exposed and isolated three defects, repaired in PR #127:

1. Omit the management IPv6 method; the intended IPv4 DHCP/static configuration remains.
2. Enable PVE nesting required by the existing systemd mount isolation, preserving service hardening.
   The trusted privileged appliance's additional proc/sys exposure is documented.
3. Restart SSH after syntax/effective-policy validation so a socket-activated Debian template keeps
   its manager-supplied listener. Do not remove the key-only access policy or service isolation.

The exact repaired helper created a fourth fresh guest and completed with exit **0**, using the
actual published rc.3 application payload. Observed proof includes IPv4 DHCP/default route,
inherited private DNS and `_apt` access, TUN, nesting/service isolation, installed tag/package/source,
root-only logs/configuration and key-only SSH policy. A real configured-key SSH login returned health
`0.3.0-rc.3`; first-run UI/state was initial/unconfigured. Reboot preserved networking, service,
health, TUN and real SSH access. The ordinary exact `5659aeb` candidate installer then upgraded that
guest to `0.3.0-rc.4`; another reboot, real SSH and health passed. Candidate installed-client TLS
controls also passed (its independently reported OpenSSL 3.5.6 stack is not substituted for the
fully maintained native guest's 3.5.7 receipt).

All 97 focused helper/launcher tests and applicable formatting/lint checks passed. Independent
code review approved the three repairs and observed fresh-guest evidence. Earlier partial guests
and their failed terminal/service receipts were preserved until private archival, then cleaned up.
This is **pre-publication candidate-helper acceptance with rc.3 payload plus candidate upgrade**.
It does not complete ordinary public rc.4 tag resolution/same-tag fresh install. That remaining
#87 acceptance is unreachable without the separately prohibited release publication.

## Evidence retention, cleanup and boundaries

Root-only private archives retain source/guest bindings, failed and successful terminal receipts,
APT/package/scanner/audit inputs, captures, preservation comparisons and recovery evidence.
Public documents contain counts/hashes and limits, never private keys, credentials, cookies or backups.

| Retained archive | SHA-256 |
| --- | --- |
| Initial DNS-fixture failed native attempt | `b88c0b39fe4cac5288a9206d74d7ae8eeec93b65e3f59348ed6b37df22cd9fb5` |
| Failed observer/full-upgrade attempt and maintenance restart proof | `7bf56c7a6837890cc6a900eee5fdce3f6cfa36486bb9d3c901d13f70ac758352` |
| Successful final native upgrade/dataplane/assurance | `2d84ae7abca375c339ffa87c783d904cf63ba2de789b381a066718cab046b220` |
| Public/candidate helper attempts and fresh guest evidence | `c4a1ce236980f63557286e0c60ec5265661a47a52a0a98e66f305d1382d6e99c` |

All newly allocated native guests and four nested launcher test guests are destroyed after verified
archival; generated SSH key and namespace/WireGuard resources are removed. The previously retained
disposable PVE QA host remains available, stopped, specifically for the later ordinary public-tag
acceptance; it is not fresh guest proof. Existing reference/production guests remain untouched.

Docker publication remains blocked, Nord gateway remains reviewed NO-GO, and commercial credentials
remain out of scope. No rc.3/rc.4/other release or image publication was performed or authorized here.
