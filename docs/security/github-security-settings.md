# GitHub security settings

Repository settings are not changed by this branch. A maintainer must verify:

- [ ] Dependency Graph enabled
- [ ] after enabling Dependency Graph, repository variable
      `EXITLANE_DEPENDENCY_REVIEW_ENABLED=true` configured
- [ ] Dependabot alerts and security updates enabled (no automatic merge)
- [ ] secret scanning and push protection enabled
- [ ] private vulnerability reporting enabled
- [ ] CodeQL/code scanning enabled and results triaged
- [ ] `main` protected; CI, CodeQL, supply-chain and ZAP checks required
- [ ] default Actions token is read-only; workflow writes are explicitly scoped
- [ ] Actions restricted to GitHub/approved SHA-pinned actions
- [ ] fork pull requests receive no secrets and require approval for workflows
- [ ] security advisories used for unpatched vulnerability coordination

`EXITLANE_DEPENDENCY_REVIEW_ENABLED` is a temporary capability gate, not a permanent opt-out.
Until GitHub Dependency Graph is enabled, the dependency-review action is unavailable and its job
is skipped; mandatory `pip-audit` remains the compensating control. Close the informational
configuration finding by enabling Dependency Graph and setting the variable exactly to `true`.

| Finding | Severity | Source | Status | Reason | Compensating control | Closure condition |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub dependency review unavailable | informational / configuration | GitHub Actions | deferred | GitHub Dependency Graph must be enabled manually | mandatory pip-audit | enable Dependency Graph and set `EXITLANE_DEPENDENCY_REVIEW_ENABLED=true` |
