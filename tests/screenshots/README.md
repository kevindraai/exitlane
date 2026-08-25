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
