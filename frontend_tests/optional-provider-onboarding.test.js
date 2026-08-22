import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const wizard = fs.readFileSync(
  new URL("../backend/exitlane/static/js/wizard.js", import.meta.url),
  "utf8",
);
const provider = fs.readFileSync(
  new URL("../backend/exitlane/static/js/provider.js", import.meta.url),
  "utf8",
);
const markup = fs.readFileSync(
  new URL("../backend/exitlane/static/partials/wizard/provider.html", import.meta.url),
  "utf8",
);
const english = JSON.parse(fs.readFileSync(
  new URL("../backend/exitlane/static/locales/en.json", import.meta.url),
  "utf8",
));
const dutch = JSON.parse(fs.readFileSync(
  new URL("../backend/exitlane/static/locales/nl.json", import.meta.url),
  "utf8",
));

test("provider deferral is an explicit provider-neutral wizard action", () => {
  assert.match(markup, /id="provider-defer"/);
  assert.match(markup, /id="provider-deferred-status"/);
  assert.match(wizard, /postJson\("\/api\/setup\/provider\/defer"\)/);
  assert.match(wizard, /addEventListener\("click", deferProviderSetup\)/);
  assert.doesNotMatch(wizard, /deferProviderSetup[\s\S]+provider-install/);
  assert.doesNotMatch(wizard, /deferProviderSetup[\s\S]+authenticate/);
});

test("deferred setup advances honestly without pretending the provider is ready", () => {
  assert.match(wizard, /setup\.provider_deferred/);
  assert.match(wizard, /"completion\.deferred"/);
  assert.match(provider, /authenticated \|\| deferred/);
  assert.match(provider, /provider\.status\.deferred/);
  assert.equal(english.completion.deferred, "Deferred");
  assert.equal(dutch.completion.deferred, "Uitgesteld");
});

test("copy explains direct egress, later provider setup and no provider killswitch", () => {
  for (const locale of [english, dutch]) {
    const copy = locale.step3.defer_description.toLowerCase();
    assert.match(copy, /wireguard/);
    assert.match(copy, /killswitch/);
    assert.ok(locale.step3.defer_action);
    assert.ok(locale.step3.deferred_description);
    assert.ok(locale.provider.description.deferred);
  }
  assert.doesNotMatch(wizard, /speedtest|vpn\/connect|killswitch\/enable/);
});
