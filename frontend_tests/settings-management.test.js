import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const sourceUrl = new URL("../backend/exitlane/static/js/settings.js", import.meta.url);
const markupUrl = new URL("../backend/exitlane/static/partials/views/settings.html", import.meta.url);

test("credential forms use protected APIs and always clear secret fields", async () => {
  const source = await readFile(sourceUrl, "utf8");
  assert.match(source, /api\("\/api\/auth\/password"/);
  assert.match(source, /api\("\/api\/providers\/nordvpn\/token"/);
  assert.match(source, /finally \{\s*clearSecretFields\(\.\.\.fields\)/);
  assert.match(source, /finally \{\s*field\.value = ""/);
  assert.match(source, /setBusy\(button, true/);
  assert.match(source, /setBusy\(button, false/);
});

test("settings exposes functional sections without duplicating WireGuard controls", async () => {
  const markup = await readFile(markupUrl, "utf8");
  for (const section of ["settings-authentication", "settings-vpn", "settings-wireguard", "settings-network"]) {
    assert.match(markup, new RegExp(`id="${section}"`));
  }
  assert.match(markup, /data-open-view="wireguard"/);
  assert.doesNotMatch(markup, /\/api\/ingress\/wireguard\/config\/regenerate/);
  assert.match(markup, /autocomplete="current-password"/);
  assert.match(markup, /autocomplete="new-password"/);
  assert.match(markup, /id="settings-nordvpn-token"[^>]+type="password"/);
});
