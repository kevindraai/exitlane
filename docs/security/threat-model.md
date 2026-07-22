# Exitlane threat model

Status: alpha baseline, reviewed 2026-07-22. A trusted management network is a deployment assumption, not a substitute for application security.

## System and trust boundaries

The browser loads same-origin static HTML/JavaScript and sends credentials and a HttpOnly session cookie to FastAPI. FastAPI validates authentication, setup state, CSRF source and request models before reading SQLite or invoking explicit-argv subprocesses. SQLite and generated WireGuard files cross the application/filesystem boundary. NordVPN CLI, `wg`, `ip`, `systemctl` and `wg-quick` cross into privileged host and provider-controlled components. systemd starts Exitlane as root because the current alpha directly configures networking and WireGuard; Linux, the NordVPN daemon and router are separate trust domains. The router consumes a downloaded private client configuration.

Before setup, health/session plus the allowlisted wizard operations are public on the management network. Completion closes that bootstrap boundary; all API routes except health, login and session then require a valid session. `/`, static assets and passive partials remain public; docs/OpenAPI require authentication.

## Assets, actors and entry points

Assets are the administrator verifier and salts, session digests, NordVPN token while in request memory, WireGuard private keys/configurations, SQLite configuration/events, network routing and tunnel state, root privileges, Actions token and release artifacts. Entry points are HTTP routes, cookies and headers, provider output, SQLite state, environment/default files, downloaded client configurations, installer/package inputs, Actions and operator proxy configuration.

Plausible attackers include an unauthorised management-LAN user, compromised browser/extension, stolen-cookie holder, setup-route attacker, cross-site CSRF origin, command-injection input, malicious provider output, limited local Linux user, compromised dependency/Action, misconfigured reverse-proxy operator, manipulated backup/update/restore artifact and a reader mining errors or Activity/logs for secrets.

## Highest-risk abuse cases and disposition

| Threat / attack path | Impact | Existing mitigation | Baseline measure | Residual risk / verification |
| --- | --- | --- | --- | --- |
| Bootstrap route reused after setup | Appliance takeover or privileged network changes | Explicit setup allowlist and persisted completion | Route-boundary regressions, trailing/encoded-path checks | LAN attacker can race an unfinished setup; finish setup promptly and firewall it |
| Stolen session cookie replay | Full administrator authority | Random token, digest-only storage, HttpOnly/SameSite, expiry/revocation | Uniform cookie attributes, no-store responses, CSP; Secure configurable | No MFA and no binding; terminate sessions/change password and require HTTPS |
| Cross-site mutating request | Configuration/network changes | SameSite=Lax and Origin/Referer comparison | Strict source parsing and regression matrix | Headerless non-browser clients remain intentionally allowed; protect network/API clients |
| Command/path injection | Root command execution or key disclosure | Pydantic patterns, explicit argv, `shell=False`, fixed command names | Bandit and negative tests; fixed download/client paths | `wg-quick` interprets generated config directives; all interpolated fields remain allowlisted |
| Malicious provider/subprocess output | Secret leak, UI injection or parser confusion | Parsers and frontend `textContent` in dynamic paths | Safe error codes, bounded Activity metadata, CSP | Some setup diagnostic/provider output remains visible to an authorised/setup operator; deferred sanitisation review |
| Local Linux file read/write | Credential/key/database theft | 0700 directories, 0600 key files, umask 0077 | systemd filesystem sandbox and permission tests | Root or equivalent host control defeats these controls |
| Compromised dependency or Action | Build/runtime compromise | Narrow dependencies | CodeQL, Bandit, pip-audit, dependency review, Gitleaks, SHA-pinned Actions, Dependabot | Python ranges are not a lockfile; reproducible constraints are deferred |
| Malicious backup/update/release | Persistent compromise | Manual operator workflow | release checklist, package-content and checksum review | No signed update channel exists in alpha |
| Proxy/Internet misconfiguration | CSRF/cookie downgrade and remote attack surface | Direct Host-based same-origin policy | hardening guide; HSTS/Secure opt-in only with HTTPS | Forwarded headers are not trusted; Internet exposure is unsupported |
| Logs/errors/Activity mined | Secret disclosure | allowlisted metadata and generic auth/storage errors | size/control-character bounds, scanner checks | system journal contains third-party process messages outside application control |

STRIDE was used as a checklist: spoofing (sessions/setup), tampering (settings/files/releases), repudiation (Activity), information disclosure (errors/logs/downloads), denial of service (request sizes/subprocess timeouts) and elevation of privilege (root commands/systemd).

## Accepted alpha assumptions

Exitlane is single-administrator, single-appliance software on a firewalled management VLAN. Root service execution, headerless non-browser writes, public static shell assets, memory-only/no login throttling, dependency ranges without a lock and no MFA are accepted or deferred alpha risks. Public Internet exposure, untrusted shared hosting and permanent active-scan targets are unsupported.
