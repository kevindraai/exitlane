# Connection diagnostics

The authenticated **Diagnostics** view tests the path used by routed clients:

```text
Device -> ExitLane -> VPN -> Internet
```

Select **Run connection test** to start a transient, in-process diagnostic run. Each probe moves
from waiting to checking and then to passed, warning, or failed. Select a connection segment to
view its translated troubleshooting result.

## Automatic probes

- **Device -> ExitLane** verifies that the appliance has a usable default network route. Reaching
  the authenticated page is the browser-side device check.
- **ExitLane -> VPN** verifies provider connection state, the expected VPN interface, a recent
  WireGuard handshake when exposed by the provider, and the route used for internet traffic.
- **VPN -> Internet** verifies DNS resolution, reachability of a fixed public test address, and a
  public-IP response over HTTPS.

A warning means that ExitLane could not prove a property; a failure identifies a missing or broken
property. Re-run the test after changing the connection or host configuration.

Results are transient and remain only in process memory. They are not written to the Activity log,
and raw command output never reaches the browser. Restarting ExitLane clears old runs.

## Individual tests

Ping and DNS lookup accept a validated hostname or IP address. External IP uses ExitLane's fixed
HTTPS endpoint. These actions use fixed executable argument lists without a shell.

Speedtest is deliberately separate from automatic diagnostics because it can use significant
bandwidth and sends measurement data to Ookla. It never starts automatically: an administrator
must select it, review the visible notices, confirm personal non-commercial eligibility, accept the
applicable Ookla license/EULA and privacy/GDPR terms, and confirm the bandwidth impact for every
measurement. A second measurement is rejected with a stable warning while one is active.

### Managed official Ookla CLI installation

When the official CLI is absent, an authenticated administrator can explicitly request managed
installation only on Debian 13 `amd64`. The installation dialog separately confirms the Debian
package mutation, personal non-commercial eligibility, license/EULA acceptance, and privacy/GDPR
terms. The UI polls only the allowlisted installation status and phases, so reloads can reconnect to
an active systemd operation without exposing command, package-manager, or download output.

The fixed-purpose root helper downloads only the reviewed Packagecloud artifact:

```text
speedtest_1.2.0.84-1.ea6b6773cf_amd64.deb
SHA-256 35e084567a6388631fb10cf01e5e0d6b57a67d34ede2b72ba111b3d9164c8b94
```

It verifies the digest before installing, uses the shared ExitLane package-operation lock, and then
accepts the CLI only when `/usr/bin/speedtest` is owned by the exact `speedtest` package and pinned
version. ExitLane never executes Packagecloud's repository script, retains an APT source or signing
key, substitutes Debian's unrelated `speedtest-cli` package, or starts a measurement after install.

The proprietary package is intentionally pinned and receives no automatic updates. A failed
download or checksum verification leaves no durable package trust. A partially completed package
installation is reported with a stable error code for local operator recovery; ExitLane does not
automatically remove a package it did not fully validate. Commercial or general use is not supported
unless the operator has suitable separate permission from Ookla. See
[ADR-001](architecture/adr-001-managed-ookla-speedtest-installation.md) for the rationale and
reviewed artifact source.

### Safe operator recovery

The browser receives only the stable phase and error code. It intentionally never receives helper,
download, package-manager, or journal output. On the appliance, use the following fixed commands
to decide the next safe step; do not remove the shared lock or invoke `/usr/bin/speedtest`.

1. Inspect the dedicated installation unit and its recent local journal:

   ```bash
   sudo systemctl status exitlane-speedtest-install.service --no-pager --full
   sudo journalctl -u exitlane-speedtest-install.service -n 100 --no-pager
   ```

2. For `package_operation_in_progress`, inspect the fixed lock. Wait for the owner to finish, then
   retry through the authenticated UI; never delete or bypass this lock.

   ```bash
   sudo ls -l /run/lock/exitlane-package-operation.lock
   ```

3. For download or checksum failures, confirm the pinned helper values before retrying. This is a
   local inspection only: it does not download, install, or run the CLI.

   ```bash
   sudo grep -E '^readonly PACKAGE_(URL|SHA256)=' /usr/local/libexec/exitlane-install-speedtest
   ```

4. For a partial package state, inspect it first. If `dpkg --audit` reports an interrupted
   configuration, a local administrator may run the fixed Debian repair command, then re-check the
   package and retry in the UI.

   ```bash
   sudo dpkg --audit
   sudo dpkg-query --show --showformat='${Package}|${Version}|${Status}\n' speedtest
   sudo dpkg --configure -a
   sudo dpkg-query --listfiles speedtest
   sudo test -x /usr/bin/speedtest
   ```

5. Treat missing ownership, a wrong version, a missing executable, or a failed validation as a
   partial state. Do not manually copy a binary, add a Packagecloud repository or signing key, or
   use Debian's unrelated `speedtest-cli` package. Correct the local package state and use the UI's
   explicit retry; each future measurement still requires its own confirmation and is never part of
   this recovery procedure.

## API

The normal authenticated API and same-origin write protections apply:

- `POST /api/diagnostics/connection-runs` starts a run and returns `202 Accepted`.
- `GET /api/diagnostics/connection-runs/{run_id}` returns its current structured snapshot.
- `POST /api/diagnostics/actions/{ping|dns|external-ip|speedtest}` runs an explicit action. Ping
  and DNS accept `{"target": "example.com"}`. Speedtest additionally requires all four explicit
  boolean confirmations; other actions do not use those fields.
- `GET /api/diagnostics/speedtest/installation` returns the browser-safe managed-installation
  snapshot.
- `POST /api/diagnostics/speedtest/installation` returns `202 Accepted` only after all four
  installation confirmations are `true`.

The setup wizard's `GET /api/diagnostics` endpoint is separate and retains its original system
prerequisite contract.
