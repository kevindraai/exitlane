# Beta.5 release validation record

Validation date: 2026-08-24 UTC. Release character: `Release assurance and installation
hardening`.

## Source identity

- Base and initial `origin/main`: `832851e65c90e4c5c4beb8936cc4c66b23bf123b`
- Base tree: `3e92c0c53fcfad55cefdeee7b623b1f19ccc0b8b`
- Branch: `feat/beta5-release-governance-hardening`
- Final PR head/tree: pending final candidate commit
- Pull request: pending
- Merged-main SHA/tree and squash merge: pending pre-merge qualification
- Annotated tag and GitHub prerelease: prohibited until every final-main gate passes

The base is the unchanged beta.4 squash merge from pull request #56. No beta.4 tag exists and none
will be created.

## Repository governance

Active ruleset `Protect main` (`19550158`) applies to `refs/heads/main`, has no bypass actor,
rejects deletion and non-fast-forward updates, requires a pull request with resolved threads,
allows only squash merge and requires strict up-to-date status checks.

Required contexts use the exact observed GitHub check names and app integrations:

- GitHub Actions (`15368`): `Shell scripts`, `Python backend`, `Frontend`, `Package build`,
  `analyze (javascript-typescript)`, `analyze (python)`, `dependency-review`, `secrets`,
  `python-audit`, `baseline`
- GitHub Advanced Security (`57789`): `CodeQL`

Actions policy is enabled with `allowed_actions=selected` and `sha_pinning_required=true`.
GitHub-owned actions are allowed; verified Marketplace actions are not generally allowed; the only
external pattern is `gitleaks/gitleaks-action@*`. Policy-level SHA enforcement makes a mutable tag
or branch reference invalid even for that selected pattern. Default workflow token permission is
read-only and workflows scope their required writes explicitly.

## CodeQL and workflow regression

`security-codeql.yml` runs for pull requests to `main`, pushes to `main`, the weekly schedule and
manual dispatch. `scripts/check_workflow_security.py` checks the main-push trigger and rejects every
Action reference that is not pinned to a full 40-character commit SHA. CI executes this check.

## Beta.4 deviation

PR #56 received only a post-merge `Approve with follow-up`. Its final head and squash merge had
identical tree content and hosted final-main gates passed, but that does not reconstruct the missing
pre-merge approval. Beta.4 was intentionally not published. Beta.5 requires a fresh independent
`APPROVE` on the exact final PR head before merge.

## Candidate qualification

- Local automated suites: 387 backend tests and 157 frontend test definitions passed. Ruff check
  and format (52 files), Bandit, pip-audit, Python/JavaScript/Bash syntax, JSON, EN/NL i18n,
  ShellCheck, `uv lock --check`, `git diff --check` and the disposable namespace/killswitch test
  passed. The only backend warning is the existing Starlette/httpx test-client deprecation.
- Package metadata/content inspection: wheel and sdist built as `0.2.0b5`; the wheel contained 95
  expected entries and no database, SQLite file, encrypted backup, environment file, master key or
  recovery-code path.
- Workflow Action references: all 19 references are full 40-character SHAs; CodeQL main-push
  regression check passed
- Hosted PR runs and exact head SHA: pending
- Independent pre-merge review: pending; `APPROVE` is mandatory
- Debian 12 clean install: pending
- Debian 13 clean install: pending

### Clean-install finding and correction

A supplemental, explicitly non-authoritative Docker diagnostic reproduced a clean-install failure
on minimal Debian 12 and Debian 13 roots: neither environment guaranteed `procps`, so `sysctl` and
its configuration directory were absent when IPv4 forwarding was configured. Docker remains an
unsupported appliance runtime and is not counted as release evidence, but the missing declared
system prerequisite was a valid installer defect. The candidate now installs `procps`, creates the
fixed `sysctl.d` parent and has a regression assertion for both contracts. The complete local gate
set passed again after this change. Real supported Debian 12 and Debian 13 clean-install evidence
remains mandatory.

## Final-main qualification

- Exact merged-main local suites: pending
- Automatic final-main CI, CodeQL, supply-chain and ZAP run IDs: pending
- Transactional appliance validation and preserved-state evidence: pending
- Rollback/failure injection: mandatory on the final appliance because beta.5 now changes the
  installer prerequisite path; beta.4 evidence is background only and is not represented as a new
  beta.5 run
- Residual browser limitation: real Safari/WebKit remains unavailable; no known compatibility defect

Any pending required item is a hard release blocker. The final immutable commit, tag object and
release URL are recorded in the annotated tag, GitHub prerelease and release handoff after
qualification because a commit cannot contain its own resulting SHA.
