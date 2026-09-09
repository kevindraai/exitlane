# Development

Exitlane uses short-lived feature branches and pull requests. Keep a branch focused, rebase or
merge the current `main` as appropriate, and do not commit directly to `main`. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for commit and review expectations.

## Local checks

The backend supports Python 3.11 or newer. Install its development dependencies and run linting
and tests from `backend/`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
pytest -v
```

The frontend has no build step. Run its tests with Node.js 22 and validate translations from the
repository root:

```bash
node --experimental-default-type=module --test frontend_tests/*.test.js
python3 scripts/check_i18n.py
```

CI repeats these checks, validates source and data-file syntax, checks installer shell scripts,
and builds the Python distribution. A pull request is not ready to merge until required CI passes.

## Test appliance

Runtime changes must also be exercised on the test LXC. `scripts/deploy_worktree_to_test.sh`
copies the current working tree to the appliance and installs it as a candidate. For a pushed
branch, deployment may instead be performed from the corresponding checkout on the test host.

Use this native test-appliance path for NordVPN status, connect, disconnect, and latency tests.
Running the application with `docker compose` is suitable for frontend/API development only and
cannot test or control the NordVPN client installed on the Docker host.

The LXC check catches systemd, permissions, TUN/WireGuard, NordVPN CLI, and host-integration
problems that unit tests cannot represent. Record both automated and manual verification in the
pull request before merge.

After recreating a WireGuard interface, do not treat `active` service state and a restored route as
proof that its demand-driven peer session is already usable. From the QA peer, run the bounded
dataplane gate and only continue after its separate steady-state probe succeeds:

```bash
sudo python3 scripts/wireguard_dataplane_readiness.py \
  --interface <qa-wireguard-interface> \
  --target <external-test-address> \
  --deadline-seconds 35 \
  --steady-count 5
```

The bootstrap probe may initiate a fresh handshake. A handshake by itself never passes the gate;
the final five-packet probe must be lossless. Use the same command with Mullvad and NordVPN active.

The direct provider policy-routing layer also has an isolated namespace regression:

```console
sudo ./scripts/test_provider_egress_netns.sh
```

It proves host-main-route preservation, interface-bound probe routing, IPv4 fail-closed teardown
and unconditional protected IPv6 blocking without contacting a provider.
