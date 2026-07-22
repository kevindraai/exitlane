# Contributing

Thank you for helping improve Exitlane. Keep changes focused and preserve the provider- and
router-neutral boundaries of the core.

## Branching model

Create a feature or fix branch from an up-to-date `main`. Use a short descriptive prefix, such as
`feat/`, `fix/`, `docs/`, or `chore/`. Open a pull request when the branch is ready for review.
Do not commit or push changes directly to `main`.

Keep each pull request limited to one coherent change. Documentation-only work should not include
runtime changes.

## Commit style

Write imperative, present-tense commit subjects that describe the outcome. Conventional Commit
prefixes are encouraged, for example `feat: add provider status` or `docs: update deployment`.
Avoid mixing formatting, refactoring, and functional changes in one commit.

Never commit credentials, access tokens, private keys, generated WireGuard configurations, or
real public IP addresses.

Security-sensitive changes must add relevant negative and authorization tests and update the
threat-model or ASVS delta when a boundary changes. Never use real cookies, sessions, passwords,
provider credentials, or appliance data in fixtures, logs, or artifacts. Report suspected
unpatched vulnerabilities privately according to `SECURITY.md`, not in a public issue.

## Tests and CI

Run checks relevant to the change before opening a pull request. The main local commands are:

```bash
cd backend
python -m pip install -e '.[dev]'
ruff check .
pytest -v
```

```bash
node --experimental-default-type=module --test frontend_tests/*.test.js
python3 scripts/check_i18n.py
```

GitHub Actions also checks Bash syntax and ShellCheck, compiles Python sources, validates
JavaScript syntax and JSON, runs backend and frontend tests, checks translations, and builds the
Python package. All required CI jobs must pass before merge.

Security CI additionally runs Bandit, pip-audit, Gitleaks, dependency review, CodeQL and a passive
ZAP baseline. See [security testing](docs/security/security-testing.md).

## Test-LXC deployment

Every runtime change must be deployed to the dedicated test LXC before merge. Deploy the exact
working tree under review:

```bash
./scripts/deploy_worktree_to_test.sh
```

Confirm the service starts, the health endpoint responds, authentication works, and the changed
user flow behaves as expected. Summarize the tests performed in the pull request.

For more context, see the [development guide](docs/development.md).
