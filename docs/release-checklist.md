# Beta release checklist

This checklist is evidence-driven. An unchecked appliance item is a release
blocker and the pull request must remain draft.

## Branch and version

- [x] Work is on `release/beta`, based on origin/main
  `11bc3bf4ab4314d9812e67fdfff0c609ca783751`.
- [x] No direct main commit, merge, reset, rebase, force-push, tag, or release.
- [x] Runtime and installer version are `0.2.0-beta.1`; Python package version is
  the PEP 440 equivalent `0.2.0b1`.
- [ ] Final branch SHA and unchanged remote main are recorded in PR #34.

## Automated validation

- [x] Backend tests, frontend tests, Ruff check/format, Bandit, pip-audit,
  compileall, JavaScript syntax, JSON, i18n, Bash syntax, ShellCheck, namespace
  killswitch test, wheel/sdist build, and `git diff --check`.
- [ ] Gitleaks, CodeQL, dependency review, ZAP baseline, and all GitHub checks
  pass on the final branch.
- [ ] Final package content and generated artifact checks contain no secrets,
  sessions, private keys, backups, or unexpected files.
- [ ] No open critical/high finding; every medium is fixed or explicitly accepted.

## Appliance lifecycle

- [ ] Clean Debian 13 beta install and wizard.
- [ ] Exact alpha baseline clean install and representative configuration.
- [ ] Alpha-to-beta upgrade and automatic protected pre-upgrade snapshot.
- [ ] Settings, MFA, recovery codes, sessions, Activity, reverse proxy, trusted
  proxies, WireGuard, NordVPN, token renewal, and killswitch preserved.
- [ ] Candidate installer is idempotent when run a second time.
- [ ] Injected upgrade failure restores code, database, configuration, units,
  version state, permissions, and a healthy service without secret leakage.
- [ ] Encrypted backup create, inspect, verify, restore, and old-session rejection.
- [ ] Disaster restore onto a clean beta appliance.
- [ ] Malicious restore corpus leaves active data and service intact and cleans
  staging plaintext.
- [ ] IPv4, IPv6, DNS UDP/TCP, fail-closed tunnel loss, recovery, and preservation
  of non-ExitLane nftables tables.

## Web and operational security

- [ ] Bounded passive and active scan target only `172.16.130.81`.
- [ ] Unauthenticated and authenticated crawl; docs/OpenAPI authorization.
- [ ] Login/MFA enumeration, replay, concurrency, rate limiting, expiry, rotation,
  revocation, password change, and local recovery.
- [ ] Setup/access route variants, CSRF origin/content-type matrix, trusted-proxy
  chain/IP/CIDR edges, Host/public-URL mismatch, cookie flags, cache headers, CSP,
  and HTTPS-context HSTS.
- [ ] Provider hostile-output/input-validation corpus and bounded availability
  checks.
- [ ] Filesystem owners/modes, systemd state/hardening, logs, diagnostics, and
  health checks.

## Documentation and handoff

- [x] Backup/restore, upgrade/recovery, threat model, assurance matrix, ASVS,
  hardening, changelog, roadmap, security policy, and beta limitations updated
  in English.
- [ ] Deployment and LXC evidence reflect the final candidate exactly.
- [ ] PR #34 contains commands, test counts, findings, residual risks, appliance
  evidence, original/final SHAs, and all branch-protection confirmations.
- [ ] Maintainer manually marks the PR ready and merges it; Codex does not merge.
