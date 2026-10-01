# Beta release checklist

This checklist is evidence-driven. An incomplete required pre-publication gate blocks tagging
and publishing the release. The narrowly defined rc.4 public-launcher stage below
is the only explicitly authorized post-publication gate. Evidence may be recorded in the release task, a
release pull request, or linked GitHub evidence.

Do not claim that a check is complete unless its evidence is included or linked.
Screenshots are optional when equivalent machine-verifiable appliance evidence
is available, such as command output, test logs, redacted journal output, API
responses, or a recorded verification checklist.

## Release identity and source

- [ ] The final implementation pull request is approved and merged, not merely
  closed. Record an independent pre-merge `APPROVE` on the exact final pull-request head.
- [ ] Local `main` is clean and exactly matches the current `origin/main`.
- [ ] The exact final `origin/main` release SHA is recorded as runtime release
  evidence: `<release-sha>`.
- [ ] The recorded release SHA contains every intended release change.
- [ ] Runtime, installer, package, changelog, and tag versions are mutually
  consistent.
- [ ] The intended tag and GitHub release do not already exist.
- [ ] The release is prepared from the exact recorded `origin/main` commit, not
  from a feature or release branch.
- [ ] No direct commit, reset, rebase, force-push, tag overwrite, or tag move is
  used to prepare the release.

A dedicated release branch is not required. If documentation or metadata must
change before release, update it through a normal pull request, merge it, and
repeat every final-main gate against the new `origin/main` commit. Codex must
not merge a release pull request unless explicitly instructed.

## Automated validation

- [ ] Backend tests, frontend tests, Ruff check and formatting check, Bandit,
  pip-audit, compile or configured type checks, JavaScript syntax, JSON and i18n
  validation, Bash syntax, ShellCheck, namespace and killswitch tests,
  wheel/sdist builds, package-content validation, and `git diff --check` pass
  from a clean checkout of the recorded release SHA.
- [ ] Gitleaks, CodeQL, dependency review, ZAP baseline, packaging,
  supply-chain checks, and every other applicable required GitHub check pass on the final
  `main` commit. Dependency review is PR-only: record its exact approved PR-head result
  separately, plus fresh final-main dependency auditing; never label a skipped job as a pass.
- [ ] Built package metadata reports the expected PEP 440 version.
- [ ] Final package contents and generated artifacts contain no secrets,
  sessions, private keys, backups, logs, databases, or unexpected files.
- [ ] No blocking critical or high finding affects the application packages or supported native
  release. Classify findings by affected artifact and native/shared applicability. Docker-only
  base/OS findings remain blockers for the separate image publication, with complete evidence
  retained and no waiver. Any shared/native applicable HIGH/CRITICAL still blocks the application
  release. Review medium findings with linked disposition; do not suppress scanner evidence.
- [ ] Commands, counts, results, and links for final validation are recorded as
  release evidence.

## Appliance lifecycle

- [ ] Clean installation on every supported Debian release succeeds.
- [ ] Upgrade from the supported previous release succeeds and creates the
  documented protected pre-upgrade snapshot.
- [ ] Settings, MFA, recovery codes, sessions, Activity, reverse proxy, trusted
  proxies, WireGuard, provider authentication, token renewal, and killswitch
  state are preserved as documented.
- [ ] Re-running the installer is idempotent.
- [ ] An injected upgrade failure restores code, database, configuration,
  units, version state, permissions, and a healthy service without leaking
  secrets.
- [ ] Encrypted backup creation, inspection, verification, restore, and
  old-session rejection succeed.
- [ ] Disaster restore onto a clean appliance succeeds.
- [ ] The malicious restore corpus leaves active data and service state intact
  and cleans staging plaintext.
- [ ] IPv4, IPv6, DNS UDP/TCP, and tunnel-present leak tests pass, including
  fail-closed tunnel-unavailable behavior, recovery, and preservation of
  non-ExitLane nftables tables.
- [ ] Release-specific appliance behavior is verified and linked on the exact merged-main SHA.
  Verify preservation of database, secret key, users, sessions, MFA, recovery codes, WireGuard,
  settings and contractually retained provider/cache state. Existing provider, killswitch,
  lifecycle, rollback and system-action evidence remains required unless the release record cites
  an explicit checklist allowance for unchanged code.
- [ ] Appliance evidence is included or linked; unchecked appliance
  verification remains a release blocker.

## Web and operational security

- [ ] A bounded read-only active scan targets only the designated test
  appliance, and the passive CI scan passes on the final candidate.
- [ ] Authenticated crawling and the unauthenticated route matrix pass, including
  authorization for documentation and OpenAPI routes.
- [ ] Login and MFA enumeration, replay, concurrency, rate limiting, expiry,
  rotation, revocation, password change, and local recovery are verified.
- [ ] Setup and access route variants, the CSRF origin/content-type matrix,
  trusted-proxy chain/IP/CIDR edges, Host/public-URL mismatch, cookie flags,
  cache headers, CSP, and HTTPS-context HSTS are verified.
- [ ] Provider hostile-output and input-validation tests pass, including bounded
  availability behavior and confirmation that secrets and raw provider output
  are not exposed.
- [ ] Filesystem owners and modes, systemd state and hardening, logs,
  diagnostics, and health checks are verified.

## Documentation and handoff

- [ ] Backup and restore, upgrade and recovery, threat model, assurance matrix,
  ASVS, hardening, changelog, roadmap, security policy, and beta limitations
  are current and written in English.
- [ ] Deployment and appliance evidence reflect the exact recorded release SHA.
- [ ] Release evidence records the implementation PR, original and final SHAs,
  commands, test counts, findings, residual risks, appliance results, and
  branch-protection confirmations.
- [ ] Every checked item has included or linked evidence; the release
  description does not claim completion based only on unchecked or unlinked
  assertions.
- [ ] A maintainer or explicitly authorized release agent has performed the merge only after the
  independent pre-merge approval and every required gate passed on the final pull-request head.

## Tag and release-candidate publication

- [ ] Every preceding pre-publication gate is complete before creating a tag.
- [ ] An annotated version tag is created at the recorded release SHA and pushed
  without force.
- [ ] The GitHub release targets that exact tag and SHA, uses reviewed English
  release notes and follows the current release channel policy. For rc.4, the Product Owner
  explicitly requires consistency with rc.3: `prerelease=false`, `make_latest=true`. The rc tag,
  runtime/package versions and prose still identify a release candidate; these GitHub channel
  flags do not assert stable maturity.
- [ ] Attached artifacts, when required by the established workflow, are built
  from the recorded release SHA and published with verified SHA-256 checksums.
- [ ] The published tag resolves to the recorded SHA, release notes render
  correctly, downloadable artifacts match their checksums, and no unrelated
  branch or repository file was modified.

## rc.4 public Proxmox stage (explicit Product Owner sequencing exception)

All normal final-main, native lifecycle, security, package and candidate gates must pass before
tagging. The moving public launcher cannot resolve rc.4 until the actual GitHub release exists.
The work order therefore authorizes a two-stage sequence, solely for this public-resolution gate:

- [ ] Before publication, qualify exact candidate helper/install behavior on a designated fresh
  disposable native Debian 13 amd64 privileged LXC and qualify rc.3 → rc.4 upgrade.
- [ ] Immediately after publication, run the ordinary public main one-liner on the authorized PVE
  host. Prove resolution of the actual rc.4 release, exact helper integrity, new-container creation
  and same-tag installation, networking, access/log controls, service/UI/API and stop/start.
- [ ] Preserve the guest and secret-free receipts; CT100 and CT123 are excluded from fresh-create
  proof. Do not auto-destroy guests. Record the final SHA and artifact digests outside that source
  commit, in the release body and qualification receipt.
- [ ] Mark the release fully qualified only after this second stage passes. A public-path failure
  is an rc.4 defect: retain evidence, diagnose and use a bounded reviewed follow-up release. Never
  move the rc.4 tag or claim #87 completed without proof.

No Docker publication, support declaration, container aliases or production rollout is authorized.
