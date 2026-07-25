# Release security checklist

- [ ] CI and security regression tests green; CodeQL reviewed
- [ ] Bandit, pip-audit, dependency review and Gitleaks green
- [x] ZAP passive baseline reviewed; authenticated scan run on the authorized LXC
- [x] bounded read-only active scan run on the explicitly authorized target
- [ ] threat-model and ASVS deltas reviewed
- [ ] systemd-analyze output and remaining root privileges reviewed
- [ ] filesystem/database/config/key permissions checked
- [ ] wheel/sdist contents inspected; checksums published
- [ ] test-LXC installer, service, login, provider, VPN/WireGuard, Activity and Settings validated
- [x] scan logs/reports/artifacts contain no credentials, cookies or keys
- [ ] GitHub security-settings checklist reviewed
- [ ] changelog contains a security section
- [ ] each open finding records severity, owner, status and rationale
