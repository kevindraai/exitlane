# Beta.4 candidate validation record

Candidate validation date: 2026-08-24 UTC. The source branch was
`feat/beta4-ux-documentation-polish`, based on
`6b31e78ccdf52c38542e41ab46f57f592c039974`. The final local commit is recorded in the handoff and
must be replaced by the merged `origin/main` SHA before release publication.

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
  Gitleaks was not available locally; Gitleaks, CodeQL, dependency review, ZAP and the other hosted
  checks remain mandatory on the implementation pull request.

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

- The appliance contained one administrator but had MFA disabled, no recovery codes and no active
  sessions at the beta.3 baseline. Their empty/disabled states were preserved, but this run cannot
  claim preservation of an active MFA enrollment or a live pre-upgrade session.
- Chromium covered the Safari-sensitive responsive contracts, but a real Safari/WebKit engine was
  not available for this run.
- Hosted security/CI workflows, the implementation pull request, independent GitHub approval, a
  clean install on every supported Debian release and final merged-`main` SHA validation remain
  release blockers. No merge, tag or release was performed.
