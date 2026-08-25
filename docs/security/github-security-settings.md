# GitHub security settings

Verified repository state for the beta.5 release-assurance correction:

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

GitHub's selected-action pattern identifies the only non-GitHub Action currently needed. The
separate repository-level `sha_pinning_required` control prevents that pattern from authorizing a
tag or mutable branch reference. `scripts/check_workflow_security.py` remains a defense-in-depth
CI gate and checks all repository workflow references plus the CodeQL `push: main` trigger.

`EXITLANE_DEPENDENCY_REVIEW_ENABLED` remains an explicit capability gate, not an opt-out. Dependency
Graph is enabled and the variable is exactly `true`, so pull requests execute dependency review;
mandatory `pip-audit` remains an additional control.

| Finding | Severity | Source | Status | Reason | Compensating control | Closure condition |
| --- | --- | --- | --- | --- | --- | --- |
| Dependabot security updates disabled | informational / configuration | GitHub repository | open | Not required by the beta.5 release-governance work order | dependency review, pip-audit and manual alert triage | enable Dependabot security updates without automatic merge |
