import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("shared Alert component maps every semantic type to one Lucide icon", async () => {
  const [ui, icons] = await Promise.all([
    read("../backend/exitlane/static/js/ui.js"),
    read("../backend/exitlane/static/js/icons.js"),
  ]);
  assert.match(ui, /SUCCESS: "success"/);
  assert.match(ui, /INFORMATION: "information"/);
  assert.match(ui, /WARNING: "warning"/);
  assert.match(ui, /ERROR: "error"/);
  assert.match(ui, /success: "circle-check"/);
  assert.match(ui, /information: "info"/);
  assert.match(ui, /warning: "triangle-alert"/);
  assert.match(ui, /error: "circle-x"/);
  assert.match(ui, /element\.className = `alert alert-\$\{alertType\}`/);
  assert.match(ui, /alertType === ALERT_TYPES\.ERROR \? "alert" : "status"/);
  assert.match(icons, /"circle-x"/);
  assert.match(icons, /"triangle-alert"/);
});

test("toasts and inline Settings banners use the shared Alert renderer", async () => {
  const [ui, settings, markup] = await Promise.all([
    read("../backend/exitlane/static/js/ui.js"),
    read("../backend/exitlane/static/js/settings.js"),
    read("../backend/exitlane/static/partials/views/settings.html"),
  ]);
  assert.match(ui, /renderAlert\(toast, message, type\)/);
  assert.match(ui, /toast\.classList\.add\("toast"\)/);
  assert.match(settings, /ALERT_TYPES\.SUCCESS/);
  assert.match(settings, /ALERT_TYPES\.INFORMATION/);
  assert.match(settings, /ALERT_TYPES\.WARNING/);
  assert.match(settings, /ALERT_TYPES\.ERROR/);
  assert.match(settings, /settings\.authentication\.mfa\.enabled_success/);
  assert.match(settings, /settings\.authentication\.mfa\.disabled_success/);
  assert.match(settings, /settings\.authentication\.mfa\.recovery_regenerated_success/);
  assert.match(markup, /class="alert" hidden="" id="settings-password-status"/);
  assert.match(markup, /class="alert" hidden="" id="settings-network-information"/);
  assert.match(markup, /class="alert" id="settings-network-confirm-description"/);
  assert.doesNotMatch(markup, /class="authentication-status"/);
});

test("Alert variants have distinct theme-aware colors and never reuse error-only styling", async () => {
  const css = await read("../backend/exitlane/static/style.css");
  for (const variant of ["success", "information", "warning", "error"]) {
    assert.match(css, new RegExp(`\\.alert-${variant} \\{`));
  }
  assert.match(css, /\.alert-success[\s\S]+var\(--success-border\)/);
  assert.match(css, /\.alert-information[\s\S]+var\(--information-border\)/);
  assert.match(css, /\.alert-warning[\s\S]+var\(--warning-border\)/);
  assert.match(css, /\.alert-error[\s\S]+var\(--danger-border\)/);
  assert.doesNotMatch(css, /\.toast\.error/);
});
