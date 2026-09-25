# Release security checklist

Per-release template: record the exact source SHA, commands and results in the release PR
or attached qualification report. Historical scan results do not complete a new release gate.

- [ ] CI and security regression tests green; CodeQL reviewed
- [ ] Bandit, pip-audit, dependency review and Gitleaks green
- [ ] ZAP passive baseline reviewed; authenticated scan run on the authorized LXC
- [ ] bounded read-only active scan run on the explicitly authorized target
- [ ] threat-model and ASVS deltas reviewed
- [ ] systemd-analyze output and remaining root privileges reviewed
- [ ] filesystem/database/config/key permissions checked
- [ ] wheel/sdist contents inspected; checksums published
- [ ] test-LXC installer, service, login, provider, VPN/WireGuard, Activity and Settings validated
- [ ] scan logs/reports/artifacts contain no credentials, cookies or keys
- [ ] GitHub security-settings checklist reviewed
- [ ] changelog contains a security section
- [ ] each open finding records severity, owner, status and rationale
