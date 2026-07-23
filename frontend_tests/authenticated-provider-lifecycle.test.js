import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  shouldLoadAuthenticatedProviderData,
} from "../backend/exitlane/static/js/provider.js";

const providerUrl = new URL("../backend/exitlane/static/js/provider.js", import.meta.url);
const appUrl = new URL("../backend/exitlane/static/js/app.js", import.meta.url);
const authUrl = new URL("../backend/exitlane/static/js/auth.js", import.meta.url);

test("protected provider data is gated by dashboard mode and authentication", () => {
  assert.equal(shouldLoadAuthenticatedProviderData(
    { mode: "login" },
    { data: { authenticated: false } },
  ), false);
  assert.equal(shouldLoadAuthenticatedProviderData(
    { mode: "wizard" },
    { data: { authenticated: false } },
  ), false);
  assert.equal(shouldLoadAuthenticatedProviderData(
    { mode: "dashboard" },
    { data: { authenticated: false } },
  ), false);
  assert.equal(shouldLoadAuthenticatedProviderData(
    { mode: "dashboard" },
    { data: { authenticated: true } },
  ), true);
});

test("provider controls do not load countries before authenticated activation", async () => {
  const source = await readFile(providerUrl, "utf8");
  const initialiseStart = source.indexOf("export function initialiseProviderControls()");
  const initialiseEnd = source.indexOf("\n}", initialiseStart);
  const initialiseBody = source.slice(initialiseStart, initialiseEnd);
  assert.doesNotMatch(initialiseBody, /refreshCountries\(/);
  assert.match(source, /if \(countriesLoaded\) return Promise\.resolve\(true\)/);
  assert.match(source, /if \(!countryLoadPromise\)/);
  assert.match(source, /countryLoadController\?\.abort\("authentication-ended"\)/);
  assert.match(source, /error\.code === "aborted"/);
});

test("dashboard activation loads protected data and logout/session expiry tears it down", async () => {
  const app = await readFile(appUrl, "utf8");
  const auth = await readFile(authUrl, "utf8");
  assert.match(app, /await activateAuthenticatedProviderData\(\)/);
  assert.match(app, /lifecycle\.stop\(\);\s*deactivateAuthenticatedProviderData\(\)/);
  assert.match(auth, /deactivateAuthenticatedProviderData\(\);\s*await postJson\("\/api\/auth\/logout"\)/);
  assert.match(auth, /resetAuthenticatedState\(\);\s*showLogin\(\)/);
});

test("country load errors remain visible only on the authenticated loader path", async () => {
  const source = await readFile(providerUrl, "utf8");
  const activationStart = source.indexOf("export function activateAuthenticatedProviderData()");
  const deactivationStart = source.indexOf("export function deactivateAuthenticatedProviderData()");
  const activationBody = source.slice(activationStart, deactivationStart);
  assert.match(activationBody, /provider\.country_selection\.load_failed/);
  assert.match(activationBody, /showMessage\(/);
  assert.equal(
    source.slice(source.indexOf("export function initialiseProviderControls()"))
      .includes("provider.country_selection.load_failed"),
    false,
  );
});
