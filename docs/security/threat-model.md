# Exitlane threat model

Current contract: stable v1 native/container appliance. The dated 2026-09-30 Daybreak
Blue-assisted review remains historical internal evidence; this document is not a new assessment.
Exact-source and image qualification receipts are linked by the
[published v1.0.0 release](https://github.com/kevindraai/exitlane/releases/tag/v1.0.0).
A trusted management network is a deployment assumption, not a substitute for application security.

## System and trust boundaries

The browser loads same-origin static HTML/JavaScript and sends credentials and a HttpOnly session cookie to FastAPI. FastAPI validates authentication, setup state, CSRF source and request models before reading SQLite or invoking explicit-argv subprocesses. SQLite and generated WireGuard files cross the application/filesystem boundary. NordVPN CLI/daemon, the Mullvad HTTPS API, `wg`, `ip`, `systemctl` and `wg-quick` cross into privileged host or provider-controlled components. systemd starts Exitlane as root because the native appliance directly configures networking and WireGuard; Linux, the NordVPN daemon, Mullvad's remote control plane, and the router are separate trust domains. The router consumes a downloaded private client configuration.

Before setup, health/session plus the allowlisted wizard operations are public on the management network. Completion closes that bootstrap boundary; all API routes except health, login and session then require a valid session. `/`, static assets and passive partials remain public; docs/OpenAPI require authentication.

## Assets, actors and entry points

Assets are the administrator verifier and salts, session digests, provider credentials in request memory, encrypted persisted Mullvad account/device/private-key state, PIA renewal credentials/generations and imported Proton profile keys, the shared appliance master key, WireGuard private keys/configurations, SQLite configuration/events, active-provider selection, network routing and tunnel state, root privileges, Actions token and release artifacts. Entry points are HTTP routes, cookies and headers, provider output, SQLite state, environment/default files, downloaded client configurations, installer/package inputs, Actions and operator proxy configuration.

Plausible attackers include an unauthorised management-LAN user, compromised browser/extension, stolen-cookie holder, setup-route attacker, cross-site CSRF origin, command-injection input, malicious provider output, limited local Linux user, compromised dependency/Action, misconfigured reverse-proxy operator, manipulated backup/update/restore artifact and a reader mining errors or Activity/logs for secrets.

## Highest-risk abuse cases and disposition

| Threat / attack path | Impact | Existing mitigation | Baseline measure | Residual risk / verification |
| --- | --- | --- | --- | --- |
| Bootstrap route reused after setup | Appliance takeover or privileged network changes | Explicit setup allowlist and persisted completion | Route-boundary regressions, trailing/encoded-path checks | LAN attacker can race an unfinished setup; finish setup promptly and firewall it |
| Stolen session cookie replay | Full administrator authority | Random token, digest-only storage, HttpOnly/SameSite/Secure, idle/absolute expiry and revocation | Active-session management and no-store responses | A stolen live cookie remains usable until revoked or expired |
| Stolen password | Administrator access attempt | Optional TOTP MFA, bounded challenge and one-time recovery codes | Replay counter and rate-limit regressions | TOTP is phishable and recovery codes must remain offline |
| Cross-site mutating request | Configuration/network changes | SameSite=Lax and Origin/Referer comparison | Strict source parsing and regression matrix | Headerless non-browser clients remain intentionally allowed; protect network/API clients |
| Command/path injection | Root command execution or key disclosure | Pydantic patterns, explicit argv, `shell=False`, fixed command names; privileged network values and restored command directives use strict allowlists | Bandit, hostile-input regressions and fixed download/client paths | `wg-quick` remains a privileged interpreter; restored non-command field semantics are not exhaustively re-derived |
| Timezone system mutation | Root command injection, path traversal or application/system divergence | IANA membership validation, fixed absolute `timedatectl` argv, post-change verification, persistence rollback and startup reconciliation | Valid/invalid input, apply failure, storage rollback and mismatch regressions | A broken host `timedated` service can leave reconciliation pending; Settings and Activity expose the stable failure state |
| Managed Speedtest install or measurement abuse | Unauthorized proprietary install, package-manager conflict, bandwidth use, or information disclosure | Authenticated same-origin endpoints; four visible confirmations; fixed systemd helper; shared package lock; digest, package-owner and path verification; bounded commands; allowlisted status/error fields; one in-process measurement at a time | Installation, redaction, reload, confirmation, ownership, and single-flight regressions | Ookla terms and suitable commercial permission remain operator responsibilities; a compromised signed artifact or root host defeats this boundary |
| Provider credential disclosure | Reusable NordVPN token or Mullvad account/token/private key exposed through argv, output, logs, events, files, or responses | Nord private PTY; Mullvad fixed HTTPS origin, memory-only token and AES-GCM state bound to the appliance key; root-only generated config; masked/cleared browser fields; safe codes and metadata | Ciphertext, sentinel log/event/API and configuration-permission tests | A compromised browser during submission or root host can observe a live credential; real account use requires separate authorized validation |
| Concurrent or external provider tunnels | Ambiguous routing, egress leak, or stale firewall policy | One persisted active provider; global mutation claim; disconnect-and-verify before switch; inactive connect denial; all-provider observation; fail-closed conflict facts | Switch/connect races, disconnect rollback, inactive connect, and external double-connection tests | A root operator can bypass ExitLane and must resolve a reported native-client conflict locally |
| Direct-provider routing fails open | Missing interface or reboot lets protected clients fall through to the host default route | Ingress-selected dedicated table; owned unreachable default armed before mutation and restored before networking; exact route/peer/dataplane commit; nftables forwarding guard | Unit, namespace, interruption/reboot and uplink-capture acceptance | Kernel/iproute behavior and real relay/DNS behavior require disposable-appliance qualification |
| Restored or renamed ingress escapes the provider guard | Plaintext forwarded traffic or stale keys after recovery | Canonical ingress setting, immutable configured interface name, reserved egress identity; temporary old/new ingress forwarding guard and explicit provider guard restoration before service activation; complete DB/key/WireGuard rollback | Unprivileged regressions, live disconnected/active restore and injected-health-failure captures | Restore pauses client traffic; failed recovery retains the guard for local operator recovery |
| Kernel-generated replies retain the provider source after teardown | Provider-source metadata escapes the physical uplink despite zero forwarded packets | Exact provider IPv4 source rule before management routing; unreachable fallback and retired source rules retained until reboot | Source-bound socket, rule ordering, tunnel-loss and strict live OUTPUT/capture regressions | Only the assigned /32 is reserved; host management sources remain outside provider routing |
| Mullvad API/schema drift or ambiguous device mutation | Wrong relay/key, duplicate device or unrecoverable local/remote state | Fixed TLS origin and paths; bounded strict schemas; pending intent before POST; public-key reconciliation; exact-device deletion; revoked devices are not recreated | Parser, timeout/retry, device ownership and live test-account scenarios | Endpoints used by official wg-tools are implementation details rather than a separately versioned third-party contract |
| Malicious provider/subprocess output | Secret leak, UI injection, parser confusion or local probe redirection | Bounded typed provider responses, stable parser errors, public-unicast latency targets and frontend `textContent` | Deep/oversized/malformed synthetic responses, safe error codes, bounded Activity metadata, CSP | Transport inactivity timeouts are not a universal total response deadline; some setup diagnostics remain visible to an authorised/setup operator |
| Malicious local documentation content or link | Browser script execution or unsafe navigation | Fixed authenticated catalog, bounded UTF-8 files, typed Markdown projection, HTTPS/local-link allowlist and DOM construction with `textContent` | Backend and frontend negative documentation tests plus CSP | A repository writer can still publish misleading prose; normal source review remains required |
| Local Linux file read/write | Credential/key/database theft | 0700 directories, 0600 key files, umask 0077 | systemd filesystem sandbox and permission tests | Root or equivalent host control defeats these controls |
| Compromised dependency or Action | Build/runtime compromise | Narrow dependencies | CodeQL, Bandit, pip-audit, dependency review, Gitleaks, SHA-pinned Actions, Dependabot | The development uv.lock is versioned; the appliance installer resolves pyproject dependency ranges with pip, including explicit security floors, so appliance dependency resolution is not fully reproducible |
| Malicious backup/update/release | Persistent compromise | Authenticated encrypted backup format, bounded decompression including tar metadata, strict restore staging, key/schema/application compatibility, staged MFA/provider ciphertext authentication through ordinary stored SQLite columns, pre-mutation privileged-config validation, lifecycle lock and root-only recovery snapshot | Hostile archive/config corpus, parser-normalisation cases, rollback tests, release checklist and package review | Authentication proves possession of the backup passphrase, not trusted provenance; no signed update channel exists |
| Proxy/Internet misconfiguration | Client-IP/CSRF/cookie downgrade | Forwarded headers accepted only from configured IP/CIDR peers | Right-to-left chain parsing, reliable HTTPS status and conditional HSTS | Incorrectly broad operator trust remains dangerous |
| Logs/errors/Activity mined | Secret disclosure | allowlisted metadata and generic auth/storage errors | sentinel scans, size/control-character bounds, scanner checks | system journal contains third-party process messages outside application control |

STRIDE was used as a checklist: spoofing (sessions/setup), tampering (settings/files/releases), repudiation (Activity), information disclosure (errors/logs/downloads), denial of service (request sizes/subprocess timeouts) and elevation of privilege (root commands/systemd).

Database-only theft does not expose the encrypted TOTP secret or usable recovery codes without the
separate masterkey. Mullvad account, device and private-key state uses AES-GCM with that same
appliance master key; database-only theft does not reveal those encrypted values. Theft of both
permits offline verification/decryption. Local root compromise
defeats the application key, CLI and filesystem boundaries.

## WireGuard peer lifecycle boundary

One ingress interface accepts multiple named consumer identities. Every active peer has its own
keypair and exact tunnel `/32`; all peers use the existing shared subnet routing and killswitch
policy. This adds no per-device provider selector or independent firewall policy.

The durable peer ID selects resources. Bounded names/descriptions reject control characters and
unsafe path components, and names never select configuration paths. SQLite holds public metadata;
client private keys remain in root-only configuration files. Authenticated list/status responses
map kernel public keys to device names without exposing private material. Reveal/download/QR use
explicit private no-store endpoints. Activity records only allowlisted peer IDs and names.

Create/edit/regenerate/revoke/delete share a mutation lock and transactional configuration/runtime
rollback. Regeneration removes the selected old public key; revocation removes the peer from the
live server, prevents ordinary configuration download and retains metadata. Deletion requires
revocation. Other peers and the shared server key remain unchanged. A revoked IP remains reserved
until deletion. Legacy migration validates existing state and preserves both server/client keys;
it never repairs ambiguity by creating a replacement identity.

Restore must validate the server, per-peer configurations and metadata as one state unit and must
retain revocation. Filesystem, runtime or database errors must not silently commit divergent
truths. Relevant regression evidence includes concurrent mutation, malformed persisted state,
rollback, private-response redaction, legacy key preservation, encrypted backup/restore and a
real two-peer namespace dataplane with provider-loss blocking. Root compromise still defeats the
local boundary; copied client configurations remain credentials wherever the operator stores them.

## Operational assumptions and boundaries

Exitlane is single-administrator, single-appliance software on a firewalled management VLAN.
MFA, one-time recovery codes, active-session management, encrypted backup, verified local restore,
and an appliance upgrade/recovery path are present. Root service execution, headerless non-browser
writes, public static shell assets and memory-only login throttling remain explicit operating risks.
Public Internet exposure, untrusted shared hosting and permanent active-scan targets are
unsupported. See `security-assurance-matrix.md` for test traceability and the published v1 release
for final appliance qualification receipts.

The [2026-10-06 Daybreak Blue-assisted assessment](daybreak-blue-assessment-2026-10-06.md)
challenged the multi-device ingress transition and root-run evidence collector. The initial
peer-adoption consistency and collector output-confinement findings were fixed and
deterministically retested in PRs #143 and #144. Its assessed-source outcome remains
historical; final release and appliance qualification require separate evidence.

The [2026-09-30 Daybreak Blue-assisted assessment](daybreak-blue-assessment-2026-09-30.md)
challenged these boundaries as an internal defensive exercise. It found and remediated two
High-impact issues with substantial prerequisites plus bounded availability and parser findings.
Sensitive High-impact reproduction detail is retained in private draft advisories. This work is
not an independent penetration test.

## Proxmox installer access boundary

The public launcher verifies the selected published helper and negotiates its UI capability
without provisioning mutation. New helpers separate optional Linux console-root credentials from
ExitLane web onboarding and from SSH authentication. Passwords are masked and confirmed, transferred
through stdin, and omitted from argv, environment, canonical plans, host logs and failure output.
Public keys are structurally validated; private material and option-prefixed authorized-key entries
are rejected rather than removing restrictions. SSH key-only policy is the default when SSH is
requested; password SSH requires explicit advanced selection. Skipping all guest credentials keeps
PVE-managed access as the recovery path, with an explicit operator acknowledgement.

Installer logging is root-only and streams subprocess output with bounded diagnostic tails.
Credential-configuration subprocess output is suppressed even on failure. A root-equivalent PVE
operator can inspect live memory or change guest configuration; this boundary does not defend
against the operator who owns the provisioning host. The helper still creates new guests only,
requires one canonical confirmation, rechecks frozen resources and never destroys partial guests.

The new UI/access/logging path is only available after inclusion in a published helper tag;
the public moving bootstrap preserves compatible behavior for older published helpers.

## Docker deployment boundary

The development Docker Compose surface remains a WebUI/API development environment. Its private
container namespace has no qualified WireGuard ingress, fail-closed forwarding, DNS protection,
startup guard or restore path. Docker owns its host bridge/NAT firewall state; ExitLane must not
modify those host tables. The [issue #76 feasibility matrix](../docker-appliance-feasibility.md)
records the missing container-capability and packet-level proof. The development Compose
example binds management only to host loopback and publishes no VPN ingress.

Runtime capabilities are selected by trusted process configuration, never by a browser request.
The explicit composition boundary implements native systemd and container adapters;
unknown runtime selections fail before database or key initialization. The authenticated capability endpoint and public onboarding
projection contain availability facts, not host paths or secrets. UI hiding is convenience:
API and CLI checks deny unavailable operations before state writes, privileged commands or Activity
acceptance. Native command allowlists, provider authorization and restore validation remain in
force. Container support follows the bounded [v1 operator contract](../docker-deployment.md).

The D2 synthetic lifecycle installs a permanent container-owned forwarding restriction and shared
unreachable provider routes before ingress, verifies actual rule semantics, and never executes native
configuration hooks. Its worker supervisor keeps protection through failures and exits on uncertain
interface ownership rather than adopting or deleting another interface. The test harness uses only
NET_ADMIN/TUN in isolated namespaces; Docker owns all host bridge/firewall setup. D2's isolated
slice did not enable full composition; the historical D5 stage subsequently supplied the candidate
application image. The supported v1 appliance uses the separate versioned operator path.

The D3 direct-provider adapter adds a shared candidate epoch and a separate commit
gate: a handshake alone does not open forwarding. Exact route, peer, interface,
lossless dataplane and UDP/TCP DNS proof must precede committed encrypted state.
Revocation preserves ingress/source unreachable routes and the permanent namespace
guard. Registered provider IPv4 sources are also filtered in OUTPUT after destination
translation, independently of destination port, so local resolver translation cannot
turn protected source traffic into management-uplink DNS. Historical sources remain
blocked after interface deletion or disconnect; the bounded inventory fails closed
instead of evicting an address. Startup accepts only an exact owned policy shape and
revokes its previous forwarding/probe permissions before use.

Separate synthetic packet observers must prove both usable provider transport and
zero plaintext fallback on the normal uplink; observer failure, packet drops or missing
positive controls invalidate that evidence. D3's lightweight checks do not themselves qualify
daemon/host restart, persistent restore or appliance images; separate D4–D6 evidence covers those
boundaries. The original development image retains its existing restrictions.

D4 adds a private DB/key/manifest volume contract and a supervisor-owned mutation
lease. Its root-only local control socket is not a Docker socket or host-control
interface. Loss of a writer guards networking and reaps only the known owned
worker before another writer can be admitted. Restore shares native archive and
cryptographic validation; old/restored ingress identities remain behind an exact
owned temporary drop policy throughout journalled publication and rollback.
Corrupt journals, incompatible schemas and failed rollback remain blocked with
recovery state retained. Root-equivalent container processes already share this
trust boundary; the manifest key digest does not authenticate externally supplied
state. See [container recovery](../docker-container-recovery.md).

The appliance image supplies full container composition, separate from the
development image. The parent owns ingress and mutation
authority; the worker owns live direct-provider generations and proofs. A one-use
inherited socket grants initialization while the parent holds the startup lease.
No startup credential travels through argv, environment values or persistent files.
Subordinate ingress operations are revoked on lease loss, drained before the final
guard/quiesce, and cannot release protection after revocation. Unsupported native
service, package, host-power and upgrade operations remain unavailable in API/CLI.

The appliance uses a read-only root, one private state volume, bounded private tmpfs,
NET_ADMIN alone, TUN and explicit namespace sysctls. Management defaults to loopback;
LAN exposure requires operator selection. Proxy trust is tied to the actual peer,
not a supplied forwarded chain. Image content, actual authentication/proxy requests,
encrypted ingress, namespace recreation and restore have dedicated qualification
gates. Historical D6 synthetic whole-host packet/restart qualification passed on the retained
exact surface. D7 supplies manual exact-release scanning, provenance/SBOM and digest verification
behind Product Owner approval in the protected publication environment. The published v1.0.0 release
records official image identities and exact-image qualification receipts.

The historical refreshed candidate scan retained 44 HIGH package findings across 8 distinct CVEs,
zero CRITICAL, zero secret findings and zero Python vulnerabilities; reported Debian Trixie
advisories remained unfixed. Exact rebuilt-image scans remain required. The [v1 security decision policy](../../SECURITY.md#v1-release-vulnerability-decisions)
retains all findings: secrets, actionable fixes and concrete security regressions block; exact
reviewed Debian findings without a supported fix receive residual platform-risk dispositions. See [the candidate contract](../docker-appliance-candidate.md) and
[rc.4 release record](../release-notes/0.3.0-rc.4.md).

### System power actions

An authenticated administrator can request three fixed host lifecycle actions.
The browser never supplies a command string: the backend maps an allowlisted
action identifier to an absolute `systemctl` argv and invokes it with
`shell=False`. Existing same-origin, CSRF, host, and session controls protect the
POST endpoints, and accepted or failed launches are written to the Activity
audit log. The service already runs as root for network gateway management, so
this feature installs no broader sudoers rule or generic privileged helper.

## Disposable native qualification tools

The source-only native qualification scripts require an explicitly authorized disposable
root-controlled guest; they are not product routes, installed recovery commands or a
provisioning service. Execution binds hostname, machine ID, exact clean source, harness
hashes and private single-use stage receipts. The default action is plan-only. Synthetic
credentials, cookies, key material, backups and child logs stay in root-private run state
and must not become public CI artifacts. The loopback API client disables inherited
proxies and redirects; the runner uses a clean child environment and the unmodified
installer's own rollback path. A root operator can forge these local receipts, so they
are auditable observations within that trust boundary, not cryptographic attestation.

Fixture results cannot establish real guest lifecycle or protected packet behavior.
A separate disaster target must be authorized, initially clean and distinct from the
source; the source must be isolated before activating duplicate restored ingress.
The tool cannot infer that external isolation or expand the operator's authorization.
