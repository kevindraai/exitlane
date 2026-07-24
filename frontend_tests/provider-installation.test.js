import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const source = fs.readFileSync(
  new URL("../backend/exitlane/static/js/provider.js", import.meta.url),
  "utf8",
);
const markup = fs.readFileSync(
  new URL("../backend/exitlane/static/partials/wizard/provider.html", import.meta.url),
  "utf8",
);

test("wizard uses provider-neutral managed-installation API and confirmation", () => {
  assert.match(source, /api\/vpn\/providers\/\$\{encodeURIComponent\(providerId\)\}\/installation/);
  assert.match(source, /window\.confirm/);
  assert.doesNotMatch(source, /api\/providers\/nordvpn\/install/);
});

test("wizard always ends busy state and supports success, error, polling and retry", () => {
  assert.match(source, /status\.state === "installing"/);
  assert.match(source, /status\.state === "available"/);
  assert.match(source, /\["failed", "unsupported", "daemon_missing", "daemon_inactive"\]/);
  assert.match(source, /setBusy\(select\("#provider-install"\), false\)/);
  assert.match(source, /window\.setTimeout/);
  assert.match(source, /capabilities\?\.can_install/);
  assert.match(source, /\["not_installed", "daemon_missing", "daemon_inactive"\]/);
  assert.match(source, /select\("#provider-install"\)\.hidden = !installable/);
  assert.match(source, /select\("#provider-login-methods"\)\.hidden = !available/);
  assert.match(source, /if \(available\) \{[\s\S]+clearInlineError\(\)/);
  assert.match(source, /restoreInstallStatus[\s\S]+refreshProviderState\(\{ deduplicate: false \}\)/);
});

test("wizard never exposes provider installation logs", () => {
  assert.doesNotMatch(markup, /provider-install-log/);
  assert.doesNotMatch(source, /status\.logs/);
  assert.doesNotMatch(
    source.slice(source.indexOf("async function pollInstallStatus"), source.indexOf("export async function restoreInstallStatus")),
    /showInlineError\(error\.message\)/,
  );
  assert.match(source, /journalctl -u exitlane-provider-install-nordvpn\.service -n 100 --no-pager/);
});

test("token login maps stable errors and always releases its busy state", () => {
  assert.match(source, /provider\.authentication\.errors\.\$\{code\}/);
  assert.match(source, /finally \{\s*setBusy\(button, false\)/);
});
