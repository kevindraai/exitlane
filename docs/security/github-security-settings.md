# GitHub security settings

Repository settings rechecked on 2026-09-25 for 0.3.0-rc.1 preparation.
Final source-specific CI and findings are recorded separately in release qualification.

- [x] Dependency Graph enabled
- [x] repository variable
      `EXITLANE_DEPENDENCY_REVIEW_ENABLED=true` configured
- [ ] Dependabot security updates enabled (no automatic merge)
- [x] secret scanning and push protection enabled
- [x] private vulnerability reporting enabled
- [x] CodeQL/code scanning enabled; release findings must be triaged before publication
- [x] active `Protect main` ruleset requires the exact CI, CodeQL, supply-chain and ZAP job
      contexts, strict up-to-date checks, a pull request, resolved review threads and squash merge
- [x] default Actions token is read-only; workflow writes are explicitly scoped
- [x] Actions policy allows GitHub-owned actions and the explicitly selected
      `gitleaks/gitleaks-action@*` pattern, with `sha_pinning_required=true`
- [x] fork pull requests receive no repository secrets and first-time contributors require
      workflow approval
- [x] security advisories and private reporting are available for unpatched coordination

The 2026-10-01 D7 workflow revision removes the remaining Gitleaks Action and runs its
version/checksum-pinned CLI with redacted history scanning instead. All repository
workflow Actions are now GitHub-owned. The existing repository selected-action
setting still includes the historical Gitleaks pattern; no workflow uses it, and
`scripts/check_workflow_security.py` now rejects it along with every other third-party
owner. That defense-in-depth CI gate also rejects duplicate YAML mappings and checks
the required `push: main` triggers. The repository-level `sha_pinning_required`
control remains enabled. Tightening the unused repository setting is an administrative
follow-up, not permission to reintroduce the Action.

First image publication uses the `ghcr-production` Environment. The release validator
requires its existing Product Owner-only reviewer rule, disabled administrator bypass
and protected-branch restriction before the publish job can be scheduled. The
environment is not configured or approved by the D7 implementation PR. Missing
protection fails closed; typed confirmation alone does not authorize publication.

`EXITLANE_DEPENDENCY_REVIEW_ENABLED` remains an explicit capability gate, not an opt-out. Dependency
Graph is enabled and the variable is exactly `true`, so pull requests execute dependency review;
mandatory `pip-audit` remains an additional control.

| Finding | Severity | Source | Status | Reason | Compensating control | Closure condition |
| --- | --- | --- | --- | --- | --- | --- |
| Dependabot security updates disabled | informational / configuration | GitHub repository | open | Retained informational configuration risk; not a mandatory release gate | dependency review, pip-audit and manual alert triage | enable Dependabot security updates without automatic merge |
