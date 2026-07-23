import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { configurationViewState } from "../backend/exitlane/static/js/wireguard-management.js";

const sourceUrl = new URL("../backend/exitlane/static/js/wireguard-management.js", import.meta.url);
const markupUrl = new URL("../backend/exitlane/static/partials/views/wireguard.html", import.meta.url);

test("configuration stays out of the rendered code field until explicitly shown", () => {
  const payload = { available: true, configuration: "PrivateKey = synthetic" };
  assert.deepEqual(configurationViewState(payload), {
    available: true,
    configuration: payload.configuration,
    displayedConfiguration: "",
  });
  assert.equal(configurationViewState(payload, true).displayedConfiguration, payload.configuration);
  assert.equal(configurationViewState({ available: false }).available, false);
});

test("management UI uses one confirmed mutation with busy cleanup", async () => {
  const source = await readFile(sourceUrl, "utf8");
  assert.equal(source.match(/postJson\("\/api\/ingress\/wireguard\/config\/regenerate"\)/g)?.length, 1);
  assert.match(source, /if \(regenerating\) return/);
  assert.match(source, /finally \{\s*regenerating = false;\s*setConfigurationBusy\(false\)/);
  assert.match(source, /navigator\.clipboard\.writeText\(currentConfiguration\)/);
  assert.match(source, /showModal\(\)/);
});

test("confirmation dialog and secret controls are accessible and translated", async () => {
  const markup = await readFile(markupUrl, "utf8");
  assert.match(markup, /<dialog[^>]+aria-labelledby="wireguard-regenerate-title"/);
  assert.match(markup, /aria-describedby="wireguard-regenerate-description"/);
  assert.match(markup, /aria-controls="management-wireguard-config" aria-expanded="false"/);
  assert.match(markup, /download="exitlane-wireguard\.conf"/);
  assert.match(markup, /<dialog[^>]+aria-describedby="wireguard-qr-description"[^>]+aria-labelledby="wireguard-qr-title"/);
  for (const key of ["show", "copy", "qr", "download", "regenerate", "cancel", "confirm"]) {
    assert.match(markup, new RegExp(`data-i18n="wireguard_management\\.${key}"`));
  }
});

test("QR flow requires a configuration and removes the sensitive image on close", async () => {
  const source = await readFile(sourceUrl, "utf8");
  assert.match(source, /if \(!currentConfiguration\) return false/);
  assert.match(source, /wireguard-config-qr.*addEventListener\("click", openConfigurationQr\)/);
  assert.match(source, /qrDialog\.addEventListener\("close", clearConfigurationQr\)/);
  assert.match(source, /image\.removeAttribute\("src"\)/);
  assert.match(source, /confirmRegeneration[\s\S]+clearConfigurationQr\(\)/);
  assert.doesNotMatch(source, /configuration=.*config\/qr/);
});
