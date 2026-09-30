# Security testing

The candidate traceability source is the
[security assurance matrix](security-assurance-matrix.md). It distinguishes
automated regression evidence, synthetic provider evidence, native appliance
evidence, the Daybreak Blue-assisted internal defensive assessment, accepted
residual risk, and work reserved for a future independent external review. None
of the checks in this repository are an independent penetration test.

Lifecycle security checks include authenticated-encryption tampering, wrong
passphrases, root-only enforcement, malicious archive paths, schema
and application compatibility, compressed and expanded archive budgets including
metadata, raw privileged-configuration bytes, lifecycle concurrency, session revocation, installer syntax,
ShellCheck, downgrade rejection, recovery snapshot creation, and rollback
contracts. Prior Debian 13 appliance evidence covers the bounded malicious-archive corpus and
failed-service rollback. Requalification for a release candidate must use an explicitly disposable
guest; Track D did not repeat these destructive cases on the shared native test-LXC.

Integrated-documentation checks cover the authenticated route boundary, fixed source catalog,
file-size limit, path confinement, raw-HTML non-interpretation, unsafe URL schemes, remote image
suppression and the absence of browser HTML parsing sinks. Browser QA must also confirm that CSP
and existing security headers remain unchanged on the help routes.

Every PR runs backend/frontend regressions, Ruff, Bandit, pip-audit, secret scanning, dependency review, CodeQL and a passive ZAP baseline. Scheduled runs repeat CodeQL, dependency/secret audits and ZAP. Release/manual work adds disposable-target authenticated/active scanning, package inspection, test-LXC validation and systemd review.

## Daybreak Blue-assisted internal defensive assessment

The 2026-09-30 Track D assessment followed a private attack-hypothesis ledger rather than using
the existing scanner list as its conclusion. It challenged state transitions and trust boundaries
for setup/auth/session/MFA, CSRF and proxies, DOM rendering, subprocesses, provider parsers,
routing/killswitch, management locking, lifecycle operations, PVE, Docker, static assets,
availability and secret handling. The [sanitised report](daybreak-blue-assessment-2026-09-30.md)
records scope, evidence and residual limits.

Dynamic validation remained defensive and bounded:

- direct ASGI cases covered missing or understated length, fragmented and empty chunks,
  disconnect behavior, exact-limit replay and security headers;
- synthetic provider/profile corpora covered deep, oversized, malformed and command-like input;
- encrypted archive/config fixtures covered metadata expansion, corrupt compression, compatibility,
  parser separators and pre-mutation rejection;
- isolated namespaces challenged provider egress and management routing without using provider
  infrastructure as a target;
- exact PR heads were deployed to the Debian 13 test-LXC for service, health, TUN and changed-flow
  checks, with a real loopback chunked-body test and read-only current-config validation.

Critical and High findings block candidate status. Sensitive unpatched detail belongs in the
private security-advisory route described by `SECURITY.md`; public issues and PRs use sanitised
descriptions. Each accepted finding requires a focused regression where useful, independent diff
review, exact-head required checks, relevant native/synthetic retest, remediation challenge,
merge and post-merge main reconciliation.

The assessment deliberately did not perform offensive exploit development, container/host escape
research, real provider security testing, PVE mutation or destructive experiments on the shared
native LXC. A future independent external penetration test remains a separate assurance layer.

Local commands are the normal project checks plus `bandit -c backend/pyproject.toml -r backend/exitlane`, `pip-audit` in the installed backend environment, `gitleaks git .`, workflow SHA/permission inspection and the passive ZAP container command from its workflow. Findings are classified as fixed, accepted, deferred or false positive with severity, owner and evidence. Critical/high findings block publication and potentially exploitable details use private disclosure.

Reviewed static dispositions: Bandit B104 is accepted because management-LAN reachability is the
documented appliance default and can be narrowed with `EXITLANE_HOST`; B608 is a false positive
because the dynamic SQL fragments are fixed internal column comparisons and all values are bound.

## ZAP baseline dispositions

The reliable 2026-07-22 dummy-instance scan produced no failures. Targeted rules record: 10049
accepted (`no-store` is deliberate), 10109 and 10111 false positive/informational (expected SPA
and login form), 10202 accepted (SameSite plus strict Origin/Referer is the documented CSRF
boundary), and rule 2 accepted (private WireGuard/loopback addresses are expected appliance
defaults). Rule 90004 was fixed by adding COEP, COOP and CORP headers. Form fallback was also fixed
to use POST, eliminating scanner-generated credential-like query strings. No broad warning
suppression is used.
