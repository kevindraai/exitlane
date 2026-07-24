import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const providers = await readFile(
  new URL("../backend/exitlane/static/js/providers.js", import.meta.url),
  "utf8",
);
const dashboard = await readFile(
  new URL("../backend/exitlane/static/js/dashboard.js", import.meta.url),
  "utf8",
);
const vpnMarkup = await readFile(
  new URL("../backend/exitlane/static/partials/views/vpn-overview.html", import.meta.url),
  "utf8",
);
const dashboardMarkup = await readFile(
  new URL("../backend/exitlane/static/partials/views/dashboard.html", import.meta.url),
  "utf8",
);

test("killswitch confirmation is compact and contains no repeated credentials", () => {
  assert.match(vpnMarkup, /class="compact-dialog"[^>]+id="killswitch-dialog"/);
  assert.doesNotMatch(vpnMarkup, /killswitch-password|type="password"/);
  assert.doesNotMatch(vpnMarkup, /killswitch-confirm-loss|type="checkbox"/);
  assert.doesNotMatch(vpnMarkup, /button-danger/);
  assert.match(providers, /killswitch\.enable_impact/);
  assert.match(providers, /killswitch\.disable_impact/);
});

test("one confirmation performs one mutation and updates status immediately", () => {
  assert.equal(
    (providers.match(/api\(`\/api\/vpn\/killswitch\/\$\{action\}`/g) || []).length,
    1,
  );
  assert.match(providers, /killswitchStatus = await api[\s\S]+renderKillswitchStatus\(killswitchStatus\)/);
  assert.match(providers, /showMessage\(t\(`killswitch\.\$\{action\}d`/);
  assert.match(providers, /catch \(error\)[\s\S]+killswitch-dialog-error/);
});

test("dialog traps focus, Escape cancels, and closing restores trigger focus", () => {
  assert.match(providers, /addEventListener\("cancel"[\s\S]+event\.preventDefault\(\)/);
  assert.match(providers, /event\.key !== "Tab"/);
  assert.match(providers, /killswitchDialogTrigger\?\.focus\(\)/);
  assert.match(providers, /requestAnimationFrame\(\(\) => select\("#killswitch-cancel"\)\.focus\(\)\)/);
});

test("dashboard permanently renders explicit killswitch text and icon", () => {
  assert.match(dashboardMarkup, /id="dashboard-killswitch-state"/);
  assert.match(dashboardMarkup, /id="dashboard-killswitch-icon"/);
  assert.match(dashboardMarkup, /id="dashboard-killswitch-description"/);
  assert.match(dashboard, /data\.killswitch\?\.available/);
  assert.match(dashboard, /dashboard\.killswitch_active_description/);
  assert.match(dashboard, /dashboard\.killswitch_disabled_description/);
  assert.match(dashboard, /dashboard\.killswitch_unknown/);
  assert.match(dashboard, /shield-check[\s\S]+shield[\s\S]+shield-alert/);
});
