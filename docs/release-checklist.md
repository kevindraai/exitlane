# Beta release checklist

This checklist is evidence-driven. An unchecked appliance item is a release
blocker and the pull request must remain draft.

## Branch and version

- [x] Work is on `release/beta`, based on origin/main
  `11bc3bf4ab4314d9812e67fdfff0c609ca783751`.
- [x] No direct main commit, merge, reset, rebase, force-push, tag, or release.
- [x] Runtime and installer version are `0.2.0-beta.2`; Python package version is
  the PEP 440 equivalent `0.2.0b2`.
- [ ] Final branch SHA and unchanged remote main are recorded in PR #34.

## Automated validation

- [x] Backend tests, frontend tests, Ruff check/format, Bandit, pip-audit,
  compileall, JavaScript syntax, JSON, i18n, Bash syntax, ShellCheck, namespace
  killswitch test, wheel/sdist build, and `git diff --check`.
- [ ] Gitleaks, CodeQL, dependency review, ZAP baseline, and all GitHub checks
  pass on the final branch.
- [x] Final package content and generated artifact checks contain no secrets,
  sessions, private keys, backups, or unexpected files.
- [x] No open critical/high finding; every medium is fixed or explicitly accepted.

## Appliance lifecycle

- [x] Clean Debian 13 beta install (provider-authenticated wizard remains open).
- [x] Exact alpha baseline clean install and representative configuration.
- [x] Alpha-to-beta upgrade and automatic protected pre-upgrade snapshot.
- [x] Settings, MFA, recovery codes, sessions, Activity, reverse proxy, trusted
  proxies, WireGuard, NordVPN, token renewal, and killswitch preserved.
- [x] Candidate installer is idempotent when run a second time.
- [x] Injected upgrade failure restores code, database, configuration, units,
  version state, permissions, and a healthy service without secret leakage.
- [x] Encrypted backup create, inspect, verify, restore, and old-session rejection.
- [x] Disaster restore onto a clean beta appliance.
- [x] Malicious restore corpus leaves active data and service intact and cleans
  staging plaintext.
- [x] IPv4, IPv6, DNS UDP/TCP and tunnel-present leak tests; fail-closed
  tunnel-unavailable state, recovery, and preservation
  of non-ExitLane nftables tables.

## Web and operational security

- [x] Bounded read-only active scan targeted only `172.16.130.81`; passive CI
  scan passed on the earlier candidate.
- [x] Authenticated crawl; unauthenticated route matrix and docs/OpenAPI
  authorization passed.
- [ ] Login/MFA enumeration, replay, concurrency, rate limiting, expiry, rotation,
  revocation, password change, and local recovery.
- [ ] Setup/access route variants, CSRF origin/content-type matrix, trusted-proxy
  chain/IP/CIDR edges, Host/public-URL mismatch, cookie flags, cache headers, CSP,
  and HTTPS-context HSTS.
- [x] Provider hostile-output/input-validation corpus and bounded availability
  checks.
- [x] Filesystem owners/modes, systemd state/hardening, logs, diagnostics, and
  health checks.

## Documentation and handoff

- [x] Backup/restore, upgrade/recovery, threat model, assurance matrix, ASVS,
  hardening, changelog, roadmap, security policy, and beta limitations updated
  in English.
- [x] Deployment and LXC evidence reflect the final candidate exactly.
- [ ] PR #34 contains commands, test counts, findings, residual risks, appliance
  evidence, original/final SHAs, and all branch-protection confirmations.
- [ ] Maintainer manually marks the PR ready and merges it; Codex does not merge.
