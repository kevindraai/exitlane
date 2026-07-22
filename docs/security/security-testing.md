# Security testing

Every PR runs backend/frontend regressions, Ruff, Bandit, pip-audit, secret scanning, dependency review, CodeQL and a passive ZAP baseline. Scheduled runs repeat CodeQL, dependency/secret audits and ZAP. Release/manual work adds disposable-target authenticated/active scanning, package inspection, test-LXC validation and systemd review.

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
