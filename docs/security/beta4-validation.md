# Beta.4 candidate validation record

Candidate validation date: 2026-08-24 UTC. The source branch was
`feat/beta4-ux-documentation-polish`, based on
`6b31e78ccdf52c38542e41ab46f57f592c039974`. The qualified implementation commit is
`d4e277231ccdd97fe8db7a65d7be2ccf8ba79b12` in draft pull request
[#56](https://github.com/kevindraai/exitlane/pull/56). The final pull-request head is recorded in
the PR and release handoff and must be replaced by the merged `origin/main` SHA before release
publication.

## Local automated evidence

- Backend: 387 tests passed. The only warning is the existing Starlette/httpx test-client
  deprecation.
- Frontend: 157 Node test definitions passed.
- Ruff check and format, Bandit, pip-audit, Python compilation, JavaScript syntax, JSON and EN/NL
  translation validation, Bash syntax, ShellCheck, `uv lock --check`, `git diff --check`, and the
  disposable namespace/killswitch test passed.
- Wheel and sdist built as `0.2.0b4`. Package inspection confirmed the documentation module and
  assets and found no databases, keys, encrypted backups, environment files, sessions or recovery
  codes.
- All 19 third-party Action references across four workflows remain pinned to full commit SHAs.
  Gitleaks was not available locally, so the hosted Gitleaks job remains its authoritative scan.

## Hosted pull-request evidence

All four pull-request workflows completed successfully on implementation commit
`d4e277231ccdd97fe8db7a65d7be2ccf8ba79b12`:

- [CI run 32774947061](https://github.com/kevindraai/exitlane/actions/runs/32774947061):
  Shell scripts, Python backend, Frontend and Package build passed. The hosted suites reported
  387 backend tests and 157 frontend test definitions passed.
- [CodeQL run 32774947103](https://github.com/kevindraai/exitlane/actions/runs/32774947103):
  Python and JavaScript/TypeScript `security-extended` analyses passed; GitHub reported no new
  alerts in code changed by the pull request.
- [Supply-chain run 32774947011](https://github.com/kevindraai/exitlane/actions/runs/32774947011):
  dependency review, Gitleaks and pip-audit passed. Gitleaks reported no leaks and pip-audit
  reported no known dependency vulnerabilities, excluding only the local unpublished ExitLane
  package itself.
- [ZAP run 32774947014](https://github.com/kevindraai/exitlane/actions/runs/32774947014):
  the isolated passive baseline passed with 0 new or in-progress failures, 0 warnings, 0
  informational findings, 5 configured ignores and 62 passing rules.

The active GitHub repository ruleset `Protect main` (ruleset `19550158`) applies to `main`, rejects
deletion and non-fast-forward updates, and requires a pull request with resolved review threads.
It does not currently declare the four workflow checks as required status checks; that repository
configuration remains a maintainer release gate even though the actual pull-request runs passed.

## Appliance upgrade and recovery

The designated `exitlane-reference` target resolved to `test-exitlane`, Debian 13, at exactly
`172.16.130.81`. The service was healthy on `0.2.0-beta.3` before the upgrade.

The normal deployment helper upgraded beta.3 to beta.4 and created a root-only pre-upgrade recovery
snapshot. Before/after SHA-256 comparisons proved that the master key, the existing administrator,
all 15 settings, schema state, VPN latency cache, and both WireGuard configuration files remained
unchanged. The database changed only because the expected application-start Activity event was
added. The installed service returned a healthy `0.2.0-beta.4` response, and the documentation API
returned `401` without a session. CSP, `nosniff`, frame denial, referrer policy and `no-store`
headers remained present.

Re-running the beta.4 installer succeeded and produced another recovery snapshot. An injected
`ExecStart=/bin/false` change was then applied only to the disposable deployment staging tree. The
installer failed with exit status 1 after copying, automatically restored the previous candidate,
and retained its recovery snapshot. Code, database tables other than the expected Activity history,
master key, WireGuard files and configuration fingerprints matched their pre-test values. SQLite
integrity was `ok`; the service returned healthy beta.4 after a bounded readiness poll; `/`, `/etc`,
`/opt`, `/var`, `/home` and `/dev` remained mode `0755`, and `/dev/null` remained `0666`. The staging
unit was restored immediately after the test.

The outstanding non-empty authentication-state gap was closed in a second upgrade from the
published beta.3 source SHA `6b31e78ccdf52c38542e41ab46f57f592c039974` to implementation commit
`d4e277231ccdd97fe8db7a65d7be2ccf8ba79b12`. Four lifecycle- and authentication-critical source
file hashes on the restored appliance matched the beta.3 tag before the run. A temporary root-local
QA administrator was then enrolled in TOTP MFA, received ten unused recovery codes and held one
live authenticated session. The password, TOTP setup key, recovery codes and session token existed
only in the appliance process memory and were never printed or written to an artifact.

The normal beta.4 installer exited 0 and created root-only recovery snapshot
`pre-upgrade.pm44t3yK`. Before the preserved session was reused, SHA-256 comparisons proved that the
application master key, complete QA user record, encrypted TOTP blob, complete recovery-code digest
set and complete live-session row were unchanged. After upgrade the encrypted TOTP secret decrypted
and produced a valid code, all ten recovery codes remained unused, and the same pre-upgrade session
successfully authenticated `GET /api/auth/security`, which reported MFA enabled and ten codes
remaining. SQLite integrity was `ok` and health reported `0.2.0-beta.4`. The QA user, its events,
session and recovery-code rows and the candidate staging directory were then removed; post-cleanup
checks found no QA row or orphan session/recovery-code row, and the service remained active and
healthy. Four candidate source hashes on the appliance matched the local implementation worktree.

## Browser evidence

Headless Chromium exercised the installed candidate at 1440×1000, 900×900 and 390×844 in dark,
light and system appearance. The checks covered login and local recovery disclosure, Dashboard,
VPN, WireGuard, Activity, Diagnostics, Settings and Help, all eight required contextual help links,
the six-category/13-document index, an integrated guide, EN/NL switching, visible focus treatment,
horizontal overflow, the killswitch confirmation, Diagnostics progressive disclosure and the
Speedtest run confirmation. The Speedtest confirmation retained all four legal/bandwidth controls;
it was cancelled without starting a measurement. No browser exception or failed network request
was observed. Screenshots were inspected for clipping, alignment, readable muted text, dialog width
and responsive stacking.

The documentation projection was additionally inspected after browser QA found wrapped Markdown
list lines too fragmented. The final candidate keeps wrapped bullets together, retains numbered
recovery steps 1–5 across code blocks, and constructs no script elements.

## Remaining release gates

- Chromium covered the Safari-sensitive responsive contracts, but a real Safari/WebKit engine was
  not available for this run. This is an explicit residual QA limitation; no compatibility defect
  was observed in the available runtime.
- Independent review must approve the final actual pull-request head after this evidence update.
- The active `main` ruleset does not yet require CI, CodeQL, supply-chain and ZAP status checks.
- A clean install on every supported Debian release and final merged-`main` SHA validation remain
  release blockers unless separately linked evidence closes them. No merge, tag or release was
  performed.

## Governance deviation and publication decision

Pull request #56 was merged before the required independent review occurred. The later review
result was `Approve with follow-up`, not a pre-merge `APPROVE`. The final PR head
`c3e118a9bd60a99af957f15958e0387e87a7450c` and squash-merged `main`
`832851e65c90e4c5c4beb8936cc4c66b23bf123b` share exact tree
`3e92c0c53fcfad55cefdeee7b623b1f19ccc0b8b`, and the hosted final-main gates were green. Those
facts prove content equivalence and final validation, but they do not compensate for the missing
pre-merge approval. Beta.4 was therefore deliberately not tagged or published. Beta.5 restores
the assurance chain through a new branch, required hosted checks, clean-install evidence and an
independent `APPROVE` on the exact final PR head before merge.
