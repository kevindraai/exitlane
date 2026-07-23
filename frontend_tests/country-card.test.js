import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { isCountryConnected, providerControlState } from "../backend/exitlane/static/js/provider.js";

test("country card keeps stable child markup while connecting", async () => {
  const source = await readFile(new URL("../backend/exitlane/static/js/provider.js", import.meta.url), "utf8");
  assert.match(source, /button\.append\(flag, name, detail, status\)/);
  assert.match(source, /country-card__flag/);
  assert.match(source, /country-card__name/);
  assert.match(source, /country-card__latency/);
  assert.match(source, /country-card__status/);
  assert.match(source, /country-card--connecting/);
  assert.doesNotMatch(source, /setBusy\(button, true, t\("provider\.action\.connecting/);
  assert.match(source, /finally \{\s*stopActionPolling\(\)/);
  assert.match(source, /timeoutMilliseconds: 130000/);
});

test("disconnect and provider mutations follow fresh operation state", () => {
  assert.equal(providerControlState({ connected: false }, { state: "idle" }).disconnectDisabled, true);
  const connected = { connected: true, management: {
    authentication: { state: "signed_in" },
    connection: { state: "connected" },
    capabilities: { can_disconnect: true, can_select_location: true },
  } };
  assert.deepEqual(providerControlState(connected, { state: "recovering" }), {
    reconnectDisabled: true,
    disconnectDisabled: true,
    measureDisabled: true,
  });
  assert.equal(providerControlState(connected, { state: "connected" }).disconnectDisabled, false);
});

test("only fresh provider status marks a country as connected", () => {
  assert.equal(isCountryConnected("NL", { connected: false, country_code: null }, { state: "idle" }), false);
  assert.equal(isCountryConnected("NL", { connected: true, country_code: "BE" }, { state: "connected" }), false);
  assert.equal(isCountryConnected("NL", { connected: true, country_code: "NL" }, { state: "connected" }), true);
  assert.equal(isCountryConnected("NL", { connected: true, country_code: "NL" }, { state: "connecting" }), false);
});
