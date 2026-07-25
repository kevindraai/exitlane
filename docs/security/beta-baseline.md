# Beta baseline validation

ExitLane's accepted alpha baseline for the beta iteration is
`11bc3bf4ab4314d9812e67fdfff0c609ca783751` (`origin/main`, fetched on
2026-07-25 UTC). The `release/beta` branch was created directly from that commit.
The local `main` reference was deliberately not reset or merged when it was found
to lag behind `origin/main`.

## Results before functional changes

| Area | Command | Result |
| --- | --- | --- |
| Backend | `uv run --project backend --extra dev pytest -v` | 310 passed |
| Frontend | `node --experimental-default-type=module --test frontend_tests/*.test.js` | 24 passed |
| Python lint | `uv run --project backend --extra dev ruff check backend` | Passed |
| Python format | `uv run --project backend --extra dev ruff format --check backend` | Passed (43 files) |
| Static security | `uv run --project backend --extra dev bandit -c backend/pyproject.toml -r backend/exitlane` | No findings |
| Dependencies | `uv run --project backend --extra dev pip-audit` | No known vulnerabilities; local ExitLane package not on PyPI |
| Python syntax | `python3 -m compileall -q backend/exitlane` | Passed |
| JavaScript syntax | `find backend/exitlane/static/js -type f -name '*.js' -print0 \| xargs -0 -r -n1 node --check` | Passed |
| Translations | `python3 scripts/check_i18n.py` | Passed: 2 locales, 788 keys, 507 referenced keys |
| Shell syntax | `find installer scripts -type f -name '*.sh' -print0 \| xargs -0 -r -n1 bash -n` | Passed |
| ShellCheck | `find installer scripts -type f -name '*.sh' -print0 \| xargs -0 -r shellcheck` | Passed |
| Package | `uvx --from build pyproject-build --outdir /tmp/exitlane-dist backend` | Wheel and sdist built |
| Network namespaces | `./scripts/test_killswitch_netns.sh` | nft syntax, idempotence, DNS, IPv4, IPv6, and reboot restore passed |
| Patch hygiene | `git diff --check` | Passed |

The first sandboxed `pip-audit` attempt failed because DNS was unavailable in
the restricted development environment. Re-running the same check with approved
network access passed. This was an environment limitation, not a product defect.
Gitleaks was not installed locally; the pinned Gitleaks GitHub Actions job remains
the authoritative secret scan.

## Alpha gaps relevant to beta

- Database changes are idempotent but have no explicit schema-version contract.
- There is no encrypted appliance backup or verified restore workflow.
- The installer is idempotent for a clean reinstall, but it has no lifecycle
  lock, pre-upgrade backup, transactional upgrade state, or rollback procedure.
- Disaster recovery content, compatibility boundaries, and negative restore
  cases are not yet documented or tested.
- The threat model predates the beta lifecycle boundary and needs traceability
  to positive, negative, and appliance-level tests.

These gaps are beta release blockers until implemented and validated. This file
records the baseline only; it does not claim beta readiness.
