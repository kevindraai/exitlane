import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const source = fs.readFileSync(
  new URL("../backend/exitlane/static/js/provider.js", import.meta.url),
  "utf8",
);
const component = fs.readFileSync(
  new URL("../backend/exitlane/static/js/long-task.js", import.meta.url),
  "utf8",
);
const markup = fs.readFileSync(
  new URL("../backend/exitlane/static/partials/wizard/provider.html", import.meta.url),
  "utf8",
);
const css = fs.readFileSync(
  new URL("../backend/exitlane/static/style.css", import.meta.url),
  "utf8",
);
const english = fs.readFileSync(
  new URL("../backend/exitlane/static/locales/en.json", import.meta.url),
  "utf8",
);

test("installation is a resumable server-side checklist in phase order", () => {
  assert.match(source, /api\/vpn\/providers\/\$\{encodeURIComponent\(providerId\)\}\/installation/);
  assert.match(source, /status\.installation_in_progress/);
  assert.match(source, /INSTALL_POLL_INTERVAL_MS = 1500/);
  assert.match(source, /restoreInstallStatus[\s\S]+renderInstallationStatus\(status\)/);
  assert.doesNotMatch(source, /INSTALLATION_TIMEOUT|installTimeout/);
  assert.match(markup, /class="long-task-list"/);
  assert.match(markup, /Dit kan op een schone installatie enkele minuten duren/);
});

test("initial installation state is compact and expands only after starting", () => {
  assert.match(markup, /id="provider-install-start"[\s\S]+id="provider-install"/);
  assert.match(markup, /<details aria-expanded="false" class="long-task" hidden="" id="provider-install-disclosure">/);
  assert.match(source, /disclosure\.hidden = !started/);
  assert.match(source, /startPanel\.hidden = started/);
  assert.match(source, /renderInstallationStatus\(result\)/);
});

test("active, pending, completed and failed steps use the required icon states", () => {
  assert.match(component, /"pending", "active", "completed", "failed"/);
  assert.match(component, /icon\.dataset\.status = status/);
  assert.match(css, /\.long-task-icon\[data-status="active"\][\s\S]+background: var\(--text\)/);
  assert.match(css, /\.long-task-icon\[data-status="completed"\][\s\S]+var\(--success\)/);
  assert.match(css, /\.long-task-icon\[data-status="failed"\][\s\S]+var\(--danger\)/);
  assert.match(css, /\.long-task-icon[\s\S]+border: 2px solid var\(--text\)/);
  assert.match(component, /const status = ALLOWED_STATUSES\.has\(step\.status\)/);
});

test("gateway settings are part of the same flow and the loose wizard button is gone", () => {
  assert.match(english, /applying_gateway_settings/);
  assert.doesNotMatch(markup, /id="provider-defaults"/);
  assert.doesNotMatch(source, /configure-defaults/);
});

test("success collapses to an accessible expandable summary and activates sign-in", () => {
  assert.match(markup, /<details aria-expanded="false" class="long-task"/);
  assert.match(source, /completed_summary/);
  assert.match(component, /details\.open = false/);
  assert.match(component, /details\.setAttribute\("aria-expanded"/);
  assert.match(source, /select\("#provider-login-methods"\)\.hidden = false/);
  assert.match(source, /mullvadControls[\s\S]+select\("#mullvad-account-number"\)[\s\S]+select\("#nord-token"\)/);
  assert.match(source, /input\?\.focus/);
});

test("failure marks one step, preserves completed steps and offers retry", () => {
  assert.match(component, /status === "failed"/);
  assert.match(component, /long-task-step-error/);
  assert.match(source, /provider-install-retry/);
  assert.match(source, /installProvider\(\{ confirm: false \}\)/);
  assert.match(source, /reapply_gateway_settings/);
  assert.match(source, /retry_gateway/);
  assert.match(source, /recheck_provider/);
  assert.match(source, /journalctl -u exitlane-provider-install-\$\{providerId\}\.service -n 100 --no-pager/);
  assert.doesNotMatch(markup, /provider-install-log/);
  assert.doesNotMatch(source, /status\.logs|apt.*output|journal.*output/);
});

test("token login remains explicit and always releases busy state", () => {
  assert.match(source, /const prefix = metadata\?\.authentication_method === "account_number"/);
  assert.match(source, /provider\.authentication\.errors/);
  assert.match(source, /finally \{\s*input\.value = "";\s*setBusy\(button, false\)/);
  assert.doesNotMatch(source, /void loginWithToken\(\)|await loginWithToken\(\)/);
  assert.doesNotMatch(source, /void startBrowserLogin\(\)|await startBrowserLogin\(\)/);
});
