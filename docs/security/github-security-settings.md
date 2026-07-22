# GitHub security settings

Repository settings are not changed by this branch. A maintainer must verify:

- [ ] Dependabot alerts and security updates enabled (no automatic merge)
- [ ] secret scanning and push protection enabled
- [ ] private vulnerability reporting enabled
- [ ] CodeQL/code scanning enabled and results triaged
- [ ] `main` protected; CI, CodeQL, supply-chain and ZAP checks required
- [ ] default Actions token is read-only; workflow writes are explicitly scoped
- [ ] Actions restricted to GitHub/approved SHA-pinned actions
- [ ] fork pull requests receive no secrets and require approval for workflows
- [ ] security advisories used for unpatched vulnerability coordination
