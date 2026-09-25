# Mullvad direct WireGuard candidate: disposable appliance validation

Date: 2026-09-25 UTC. This is candidate evidence, not final-main release evidence.

## Source and environment

- Base source: `feat/mullvad-provider@9be082a0295ea192ef8ba0b383a27c5cb780beae`.
- Applied candidate correction: `backend/exitlane/services/provider_wireguard.py` and its regression tests. The appliance-tested correction archive SHA-256 is recorded below; the final source still requires an exact reviewed PR head.
- Disposable `nlf-provision create-lxc --profile exitlane` container: VMID 128, `exitlane-mullvad-qa-20260925`, Debian 13 `amd64`, VLAN 135, 2 cores, 2048 MiB RAM, 16 GiB disk.
- Source archive SHA-256 before the correction: `378ff101bb449de4b8072a0b57618efbc6b39f09d6c5474af632078f30c983c6`. The correction archive SHA-256 was `4901771ff950355ddf0bdd9292a5f57f79d0c09d7cdbf04045dd6dde604b7ffd`.
- Candidate installed with `installer/install-debian.sh`. The first clean install and a same-version candidate upgrade both completed. The upgrade created a root-only recovery snapshot.
- The temporary SSH transfer key was removed after each encrypted source transfer. The account and token remained in the runner's existing `~/exitlane_cred.env`; neither value was copied into the source tree or printed in evidence.

## Finding and correction

The first live Mullvad connect returned `provider_egress_apply_failed`. On a fresh kernel route table, `ip -j -4 route show table 51820` and its IPv6 counterpart return exit code 2, JSON `[]`, and the exact `FIB table does not exist` diagnostic. The provider preflight treated this expected empty state as an apply failure before it could install the unreachable guard.

The correction accepts only that exact missing-table diagnostic as an empty table. Other command errors and foreign routes still fail closed. Two regression tests cover fresh IPv4/IPv6 tables and unrelated route-command failure. After installing the corrected candidate, the first connect succeeded.

## Live acceptance results

| Scenario | Result |
| --- | --- |
| Clean Debian 13 install, setup diagnostics, first-run administrator, Mullvad account/device registration, WireGuard ingress | Passed |
| Corrected first connect, exact-peer handshake, provider table `51820`, ingress rule, IPv6 unreachable route | Passed |
| Protected WireGuard client namespace: three IPv4 pings, Mullvad DNS query, HTTPS external IP | Passed; three pings received, DNS responded, HTTPS returned a Mullvad exit IP |
| Physical uplink nftables forward counter for `wg0` → `eth0` traffic during those client probes | Zero packets and zero bytes |
| Three disconnect/cold-connect cycles | Passed; each returned connected and `wg-mullvad` was observed |
| Country/relay switch | Explicit switch to Netherlands succeeded. An earlier automatically selected other-country relay timed out; the prior Australian relay and handshake remained connected. This is a retained availability observation, not evidence of plaintext fallback. |
| Reboot with active generation | Passed; the provider-egress, ingress and application units started, table `51820` contained only the unreachable default, protected route lookup returned `No route to host`, and management health remained available. Reconnect succeeded. |
| Deletion of `wg-mullvad` while active | Passed; the unreachable route remained, protected route lookup returned `No route to host`, management health remained available, and reconnect succeeded. |
| Mullvad sign-out and remote device reconciliation | Passed twice. Each time the account had three devices before sign-out; only the one device with ExitLane's public key was removed and the other two IDs remained. |
| NordVPN regression | Managed installation, token authentication, connection and status passed. A protected WireGuard client completed three IPv4 pings and HTTPS through NordVPN, with zero packets/bytes on the `wg0` → `eth0` nftables counter. |
| Connected provider switch NordVPN → Mullvad → NordVPN | Passed; only the selected provider was connected after each switch. Both test sessions were disconnected and signed out afterward. |
| Account/token redaction in authenticated Activity and `exitlane.service` journal | Passed; neither test credential occurred in the captured responses/logs. |
| Isolated provider-egress and killswitch namespace checks | Passed, including the existing DNS/IPv4/IPv6 packet-capture and reboot-restore check. |

## Candidate checks

- Backend: 578 tests passed after the dependency-lock update. The restricted local network sandbox stalled even a minimal FastAPI `TestClient`; the same test and full suite passed on the approved local test surface. Two upstream deprecation warnings remain.
- Frontend: all 35 Node test files passed. EN/NL i18n validation passed with 1,092 keys per locale and 640 referenced keys.
- Ruff check and format, Bash syntax, ShellCheck on the installer and relevant namespace scripts, workflow Action-pin policy, and `git diff --check` passed.
- Bandit initially flagged the fixed `/auth/v1/webtoken` URL path as a low-severity hardcoded-password false positive. An exact `B105` suppression with source comment made the configured Bandit gate pass.
- The prior `uv.lock` pinned `anyio 4.10.0`, for which `pip-audit` reported CVE-2026-63374 and CVE-2026-64847. The lock and local development environment were updated to `anyio 4.15.1`; `pip-audit` then reported no known vulnerabilities. The disposable appliance had already installed `anyio 4.15.1` during its clean install.
- A candidate wheel and sdist built successfully. The wheel had 101 entries and the sdist 137; the path inventory contained no database, key, environment file, backup, log, recovery directory or bytecode cache. Their SHA-256 hashes were `1e07f07c0675cf447ede1d184e5286af9fb0ffa072c392b97c20c2b913661ba9` and `f03563fceaaa7ea2c5f8ab54236e14a1e4cb51a38a3d2e781367fc97a025dd0c`, respectively. Final-main builds remain release work.
- Both provider test sessions were signed out. The disposable VMID 128 was stopped and retained for review; only task-created temporary files and the temporary administrator password were removed from the runner. The runner's pre-existing credential file was left untouched.

## Remaining release work

- This evidence belongs to an unmerged candidate plus a local correction. Repeat required CI, independent review and final-main appliance gates on the exact final SHA before tagging or publishing.
- A single other-country relay timed out. Its rollback preserved the previous tunnel. Determine whether relay retry/selection behavior needs a product change before calling country switching reliable across all advertised locations.
- The live client probes and zero-uplink counter covered steady-state traffic. Continuous client load and packet capture across the actual connect, relay-switch and tunnel-failure windows, plus live DNS-over-TCP, were not run; the isolated killswitch namespace test covers simulated failure and DNS/TCP behavior only.
- The proposed disposable network-integration runner workflow is not yet registered or required in CI; these live tests were executed manually through the authorized runner route.
- This test did not qualify upgrade from a previously released version, disaster restore, or every web-security release gate. Apply the release checklist separately.
