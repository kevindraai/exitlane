# Screenshot automation

This Playwright workflow captures the README and promotional screenshots from a
real ExitLane appliance. It does not intercept or replace network responses.

Run it only against a dedicated reference appliance whose VPN and WireGuard
connections are healthy. Supply a temporary administrator credential without
writing it to disk:

```bash
cd tests/screenshots
npm ci
EXITLANE_SCREENSHOT_PASSWORD='temporary-password' npm run capture
```

The default source is `http://172.16.130.81:8787`. Override it with
`EXITLANE_SCREENSHOT_BASE_URL`. The generated
`docs/images/screenshot-manifest.json` records the runtime-state category and
privacy treatment for every output, together with the exact clean Git commit
and tree used for the deployed product capture.

The workflow runs the normal connection diagnostics but never starts a
Speedtest. It also keeps the WireGuard configuration and QR-code controls
closed and rejects visible secret markers before every capture.

Dashboard and VPN captures first verify the real external IP delivered by the
appliance and then replace only that visible value with an explicit
`Redacted` label. The manifest categorizes these images as
`live-runtime-controlled-redaction`. The workflow fails if any public IP
remains visible; it does not alter health, connectivity, diagnostics, latency,
server, peer, or endpoint state.

The same temporary credential can exercise the normal Settings timezone flow:

```bash
EXITLANE_SCREENSHOT_PASSWORD='temporary-password' \
  EXITLANE_QA_TIMEZONE='Europe/London' npm run qualify:timezone
```

## Provider wizard qualification

`qualify-provider-wizard.mjs` exercises an incomplete first-run wizard on a disposable
Debian 13 test appliance. Prepare the administrator and system-check steps first. The
starting state must have Mullvad's direct WireGuard prerequisites available and NordVPN
not installed. The script changes provider selections and installs NordVPN once through
the real confirmation dialog; it never supplies provider credentials, connects a VPN or
runs Speedtest. Do not point it at a production or personal appliance.

```bash
EXITLANE_QA_BASE_URL='http://<test-appliance>:8787' \
EXITLANE_QA_ADMIN_FILE='/protected/temporary-admin.json' \
EXITLANE_QA_OUTPUT='/protected/wizard-evidence' \
EXITLANE_QA_ALLOW_INSTALL=1 \
node qualify-provider-wizard.mjs
```

The administrator file contains `username` and `password`; keep it private and remove it
after the test. `EXITLANE_QA_CHROMIUM` can select an existing Chromium executable.

Checks include repeated provider switches, native checkbox selection, keyboard-operated
tabs, narrow-screen overflow, cancellation without installation, one real installation,
and resuming that operation after a reload. Two explicit browser fault cases reject a
selection request and delay an unchanged real provider response to check stale-state
handling. Assertions wait for the selected provider's authoritative status, rather than
assuming an earlier page-load event means later requests have completed. Screenshots
show only the provider step without credentials. Keep the separate authenticated Help
rendering check in the task evidence, and restore the disposable appliance's setup state
and remove temporary administrator material afterwards.
