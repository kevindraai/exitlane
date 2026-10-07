# Daybreak Blue-assisted defensive assessment — 2026-10-06

## Status and provenance

This Daybreak Blue-assisted internal defensive assessment examined source commit
`f640a180932852ed89299789f2e70e5117e7da9b` (tree
`cc5870504279ec65e9b5e9add9dd2d45d5ff0137`) from
2026-10-06 14:21:38–14:56:59 UTC. The assessed `main` matched `origin/main`, and its
tracked worktree was clean. The review used the bounded Daybreak Blue validation profile.
It was not an independent penetration test or an assessment of a later release candidate.

The assessed source had **0 Critical, 0 High, 1 Medium and 1 Low** findings. Its review
outcome was **Changes requested** because the Medium finding blocked the patch release.
The two findings were subsequently fixed in separate, reviewed PRs #143 and #144.
The original severities and assessment outcome remain unchanged; release qualification of
the final v1.0.1 source, packages and appliances is a separate gate.
Both findings are closed after deterministic retests, including checks after the later
collector repair. There is no open release blocker from these Daybreak findings.

## Scope and method

The review reconstructed the browser/API, setup, authentication/session/MFA, CSRF/proxy,
SQLite, root-owned configuration, multi-device WireGuard ingress, provider egress,
management routing, nftables, native and Docker runtime, backup/restore, upgrade,
Proxmox helper, integrated Help, screenshot and release-workflow boundaries. The native
security evidence collector was included as a new root-run evidence surface. The
2026-09-30 assessment supplied dated hypotheses only.

Source and state-machine review was paired with fault injection, synthetic API/parser
fixtures, complete backend and frontend regressions, and disposable Linux network
namespaces. No provider infrastructure, public or production target was tested.
The final same-source challenge considered partial transitions, cross-device effects,
failed observations, secret/evidence boundaries and documentation claims; it retained
the two findings below and found no additional confirmed issue.

## Sanitized findings and disposition

| ID | Severity | Assessed-source finding | Later disposition |
| --- | --- | --- | --- |
| EL-DB-2026-10-06-01 | Medium | A failed initial WireGuard peer adoption step could leave runtime, files, settings and peer database state inconsistent and prevent retry. | PR [#143](https://github.com/kevindraai/exitlane/pull/143) made initial setup recoverable across the native and container paths. Deterministic rollback, retry, crash-state and native appliance checks passed on the reviewed fix; the corrected original recheck also passed after merge. |
| EL-DB-2026-10-06-02 | Low | A locally replaceable output-path ancestor could redirect final writes by the root-run native evidence collector. | PR [#144](https://github.com/kevindraai/exitlane/pull/144) pinned and confined output writes. Directory-swap and collector regression checks passed on the reviewed fix; the original deterministic recheck passed after merge. |

Neither finding requires discretionary Daybreak reassessment: both have deterministic
retests. During remediation, two fixture errors in the original private recheck were
corrected transparently: a retry with an intentionally persistent fault needed to
assert the expected application error, and a synthetic provision stub needed to create
private files with production-equivalent `0600` permissions. The fault injection and
security invariants were retained. Product regressions separately exercised a successful
retry after removing the fault.

## Evidence and its limits

On the assessed source, the complete backend suite passed **2,776** tests and the
frontend suite passed **42 test files**. Focused high-risk groups passed **466** tests;
focused runtime/container groups passed **636**. Ruff, Bandit, ShellCheck, JavaScript
syntax, Python compilation, translation and workflow-policy checks passed. Owned
namespace checks covered multiple peers, provider loss and recovery, management
routing, DNS/IPv4/IPv6 protection and synthetic PIA/Proton lifecycles. Both bounded
reproduction probes demonstrated their findings on the assessed source.

The separate remediation heads passed their own backend regressions (**2,829** for
PR #143 and **2,846** for PR #144), focused security tests and exact-head required
checks. PR #143 also passed real disposable native fault, rollback, retry, service
health and authenticated peer-list checks. These are fix receipts, not a claim that
the original assessment had no findings or that all v1.0.1 release gates have passed.

Later real-appliance qualification exposed native collector input and coverage gaps,
repaired separately in PR [#146](https://github.com/kevindraai/exitlane/pull/146). Its
reviewed source produced a complete, hash-verified collection without hiding native
or Python advisory records. This was post-assessment qualification work, not a new
Daybreak assessment; collection completeness does not settle vulnerability applicability.

The assessment host's Docker Engine 26.1.5 was below the supported Engine 28 minimum,
so no supported Docker appliance run is claimed for that assessment. Live commercial
provider interoperability, a public Proxmox installation, production behavior and
destructive lifecycle recovery were outside its dynamic scope. Gitleaks and Trivy
were unavailable locally, and the online Python advisory query could not complete;
current dependency and image scan decisions require fresh release evidence. Synthetic
screenshots are presentation assets and do not establish runtime or security behavior.

Root or hypervisor control still defeats local application controls. Provider
availability and schemas are external dependencies; PIA/Proton live commercial
interoperability remains unqualified. An independent external penetration test has
not been performed. The exact v1.0.1 release decision must reconcile final-source
scans, native and Docker qualification, and the applicable release checklist.
