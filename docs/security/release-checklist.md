# Release security checklist

- [ ] CI and security regression tests green; CodeQL reviewed
- [ ] Bandit, pip-audit, dependency review and Gitleaks green
- [ ] ZAP passive baseline reviewed; authenticated scan run on disposable target
- [ ] active scan run when risk warrants it, never on a permanent appliance
- [ ] threat-model and ASVS deltas reviewed
- [ ] systemd-analyze output and remaining root privileges reviewed
- [ ] filesystem/database/config/key permissions checked
- [ ] wheel/sdist contents inspected; checksums published
- [ ] test-LXC installer, service, login, provider, VPN/WireGuard, Activity and Settings validated
- [ ] logs/reports/artifacts contain no real credentials, cookies, keys or private addresses
- [ ] GitHub security-settings checklist reviewed
- [ ] changelog contains a security section
- [ ] each open finding records severity, owner, status and rationale
