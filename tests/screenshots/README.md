# Screenshot automation

The six public images show the current ExitLane interface in a healthy,
connected state. They are product illustrations, not evidence of provider,
security, or release qualification. The default synthetic mode loads the
repository's actual HTML, CSS, and JavaScript in Chromium. A small local
fixture supplies only the API observations needed to present those screens;
unknown requests fail closed. Help comes from the canonical documentation
catalog and parser.

Capture after the source change is committed, from a clean working tree:

```bash
cd tests/screenshots
npm ci
EXITLANE_SCREENSHOT_MODE=synthetic npm run capture
```

The manifest records the Git commit and tree of the clean input source,
version, fixture source hash, each image's SHA-256, capture mode, intercepted
API status, viewport, language, appearance, and privacy treatment. Generated PNGs
make the working tree dirty after capture; the clean flag describes the input
source at capture start. The synthetic presentation clock is fixed so relative
times stay reproducible. All synthetic addresses use documentation ranges or
reserved example hostnames. The fixture contains no provider credentials,
private keys, or real appliance data. Capture checks visible content and
closed configuration, QR, credential, and MFA controls before writing each
image.

Run the browser visual check against the same source and fixture:

```bash
npm run visual:qa
```

It covers desktop, tablet, mobile, and narrow layouts in light and dark mode,
English and Dutch, across Dashboard, VPN, Diagnostics, WireGuard, Settings,
Activity, and Help, plus the initial login and wizard screens. It checks page
overflow, browser errors, popover boundaries and dismissal, the killswitch
information control, and mobile WireGuard card layout. For a manual responsive
review, set `EXITLANE_SCREENSHOT_QA_OUTPUT=/tmp/exitlane-visual-qa` before this
command. This is a prefix: each run creates a new private directory and prints
its path. Selected full-page Dashboard, VPN, WireGuard, login, and wizard images
and `run-result.json` are created exclusively with `0600` permissions inside
the `0700` directory. The result records source commit/tree, input worktree
state, matrix coverage, and findings. QA output is local and is never a public
capture or runtime qualification result.

For a separately designated reference appliance, use live mode with a
temporary administrator credential and an explicit private output directory
outside the repository. It reads real API responses and replaces only an
observed public IP before capture:

```bash
EXITLANE_SCREENSHOT_MODE=live \
EXITLANE_SCREENSHOT_BASE_URL='http://reference-appliance:8787' \
EXITLANE_SCREENSHOT_DEPLOYED_COMMIT='<commit deployed to that appliance>' \
EXITLANE_SCREENSHOT_OUTPUT='/tmp/exitlane-live-candidate' \
EXITLANE_SCREENSHOT_PASSWORD='temporary-password' npm run capture
```

Live capture checks the operator's deployed commit assertion, the rendered
version, and served JavaScript and CSS against the local source. The manifest
labels those observations separately. Live images and manifest stay private,
with directory permissions `0700` and file permissions `0600`, for operator
privacy review. They are product image candidates, not runtime qualification
evidence. The publication path `docs/images` accepts only synthetic capture.

The same temporary credential can exercise the normal Settings timezone flow:

```bash
EXITLANE_SCREENSHOT_BASE_URL='http://reference-appliance:8787' \
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
