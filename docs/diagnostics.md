# Connection diagnostics

The authenticated **Diagnostics** view tests the path used by routed clients:

```text
Device -> ExitLane -> VPN -> Internet
```

Open **Diagnostics** and select **Run connection test**. Each line progresses from waiting to
checking and then passed, warning, or failed. Select a line to see the individual probe results
and a bounded troubleshooting explanation.

## Automatic probes

- **Device -> ExitLane** verifies that the appliance has a usable default network route. Reaching
  the authenticated page is the browser-side device check.
- **ExitLane -> VPN** verifies provider connection state, the expected VPN interface, a recent
  WireGuard handshake when the provider exposes one, and the route used for internet traffic.
- **VPN -> Internet** verifies DNS resolution, reachability of a fixed public test address, and a
  public IP response over HTTPS.

A warning means the path may work but ExitLane could not prove one property. A failure identifies
a broken or missing property. Re-run the test after changing the connection or host configuration.

Diagnostics results are transient and kept only in process memory. They are not added to the
Activity log and raw command output is never sent to the browser. Restarting ExitLane clears old
runs.

## Individual tests

Ping and DNS lookup accept a validated hostname or IP address. External IP always uses ExitLane's
fixed HTTPS lookup endpoint. These actions use fixed executable argument lists without a shell.

Speed test is deliberately separate from the automatic connection test because it can use
significant bandwidth. It runs only after selecting **Speed test** and reports a warning if the
Ookla `speedtest` executable is not installed. ExitLane does not install or accept license terms
for that tool on the administrator's behalf.

## API

The normal authenticated API and same-origin write protections apply:

- `POST /api/diagnostics/connection-runs` starts a run and returns `202 Accepted`.
- `GET /api/diagnostics/connection-runs/{run_id}` returns its current structured snapshot.
- `POST /api/diagnostics/actions/{ping|dns|external-ip|speedtest}` runs an explicit action. Ping
  and DNS accept `{"target": "example.com"}`; the other actions accept an empty JSON object.

The setup wizard's `GET /api/diagnostics` endpoint is separate and retains its original system
prerequisite contract.
