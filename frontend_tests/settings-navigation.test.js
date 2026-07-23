import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  SETTINGS_SECTIONS,
  availableSettingsSections,
  validSettingsSection,
} from "../backend/exitlane/static/js/settings-navigation.js";
import { navigationTarget } from "../backend/exitlane/static/js/navigation.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("Settings registry is ordered, allowlisted, and hides unfinished sections", () => {
  assert.deepEqual(
    availableSettingsSections().map(({ id }) => id),
    ["general", "security", "network", "notifications", "about"],
  );
  assert.equal(validSettingsSection("security"), true);
  assert.equal(validSettingsSection("backup"), false);
  assert.equal(validSettingsSection("updates"), false);
  assert.equal(validSettingsSection("<script>"), false);
  assert.ok(SETTINGS_SECTIONS.every((item) =>
    typeof item.route === "string"
    && item.route === `settings/${item.id}`
    && item.labelKey.startsWith("nav.settings_")
    && Number.isInteger(item.order)));
});

test("every Settings submenu entry retains its registered route target", () => {
  for (const { id } of availableSettingsSections()) {
    assert.deepEqual(
      navigationTarget({ dataset: { view: "settings", settingsSection: id } }),
      { view: "settings", section: id },
    );
  }
  assert.deepEqual(
    navigationTarget({ dataset: { view: "dashboard" } }),
    { view: "dashboard", section: null },
  );
});

test("Settings is an accessible independent sidebar group without standalone Security", async () => {
  const sidebar = await read("../backend/exitlane/static/partials/sidebar.html");
  assert.match(sidebar, /aria-controls="settings-navigation-items"/);
  assert.match(sidebar, /aria-expanded="false"[^>]+id="settings-navigation-toggle"/);
  assert.match(sidebar, /id="settings-navigation-items"/);
  assert.doesNotMatch(sidebar, /data-view="security"/);
  assert.doesNotMatch(sidebar, /settings_backup|settings_updates/);
});

test("Settings routes default, deep-link, preserve history, and redirect legacy Security", async () => {
  const [source, styles] = await Promise.all([
    read("../backend/exitlane/static/js/navigation.js"),
    read("../backend/exitlane/static/style.css"),
  ]);
  assert.match(source, /const DEFAULT_SETTINGS_SECTION = "general"/);
  assert.match(source, /parts\[0\] === "security"/);
  assert.match(source, /section: "security"/);
  assert.match(source, /historyMode: "replace"/);
  assert.match(source, /`#settings\/\$\{state\.settingsSection\}`/);
  assert.match(source, /window\.addEventListener\("popstate"/);
  assert.match(source, /settingsActive \|\| settingsGroupManuallyExpanded/);
  assert.match(source, /showView\(target\.view, \{ section: target\.section \}\)/);
  assert.match(source, /button\.setAttribute\("aria-current", "page"\)/);
  assert.match(source, /button\.removeAttribute\("aria-current"\)/);
  assert.match(styles, /@media \(max-width: 900px\)[\s\S]+\.sidebar[\s\S]+flex-direction: column/);
});

test("submenu controls retain native button keyboard semantics", async () => {
  const source = await read("../backend/exitlane/static/js/settings-navigation.js");
  assert.match(source, /document\.createElement\("button"\)/);
  assert.match(source, /button\.type = "button"/);
  assert.doesNotMatch(source, /tabindex|keydown|preventDefault/);
});

test("Settings pages contain the existing functionality exactly once", async () => {
  const markup = await read("../backend/exitlane/static/partials/views/settings.html");
  for (const section of ["general", "security", "network", "notifications", "about"]) {
    assert.match(markup, new RegExp(`data-settings-page="${section}"`));
  }
  for (const id of [
    "settings-password-form",
    "settings-mfa-card",
    "settings-recovery-codes",
    "settings-session-list",
    "settings-network-form",
    "settings-network-proxies",
    "webhook-form",
    "settings-version",
  ]) {
    assert.equal(markup.match(new RegExp(`id="${id}"`, "g"))?.length, 1);
  }
  assert.doesNotMatch(markup, /data-settings-page="(?:backup|updates)"/);
});

test("English and Dutch expose every visible Settings navigation label", async () => {
  const [english, dutch] = await Promise.all([
    read("../backend/exitlane/static/locales/en.json").then(JSON.parse),
    read("../backend/exitlane/static/locales/nl.json").then(JSON.parse),
  ]);
  for (const { labelKey } of availableSettingsSections()) {
    const key = labelKey.replace("nav.", "");
    assert.equal(typeof english.nav[key], "string");
    assert.equal(typeof dutch.nav[key], "string");
  }
});
