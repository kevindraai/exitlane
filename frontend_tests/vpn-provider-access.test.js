import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { vpnProviderAccess } from "../backend/exitlane/static/js/provider-management.js";

const status = (authentication, capabilities = {}, connection = "disconnected", errorCode = null) => ({
  management: {
    authentication: { state: authentication },
    connection: { state: connection },
    capabilities,
    error_code: errorCode,
  },
});

test("provider access distinguishes signed out, unavailable, unknown and transient states", () => {
  assert.deepEqual(
    vpnProviderAccess(status("signed_out")).state,
    "signed_out",
  );
  assert.equal(vpnProviderAccess(status("unavailable")).state, "unavailable");
  assert.equal(vpnProviderAccess(status("unknown")).state, "unknown");
  assert.equal(vpnProviderAccess(status("signing_in")).busy, true);
  assert.equal(vpnProviderAccess(status("signing_out")).busy, true);
  assert.equal(vpnProviderAccess(status("signed_out", {}, "connected")).state, "unknown");
});

test("only explicit signed-in capabilities enable provider controls", () => {
  const access = vpnProviderAccess(status("signed_in", {
    can_connect: true,
    can_disconnect: false,
    can_select_location: true,
  }));
  assert.equal(access.blocked, false);
  assert.equal(access.canSelectLocation, true);
  assert.equal(access.canManageProviderKillswitch, false);
  assert.equal(vpnProviderAccess(status("signed_out")).blocked, true);
});

test("VPN markup provides an accessible inert blocking layer without killswitch UI", async () => {
  const markup = await readFile(
    new URL("../backend/exitlane/static/partials/views/vpn.html", import.meta.url),
    "utf8",
  );
  assert.match(markup, /id="vpn-provider-blocker" role="status"/);
  assert.match(markup, /id="vpn-provider-controls"/);
  assert.match(markup, /id="vpn-provider-go-to-sign-in"/);
  assert.doesNotMatch(markup, /vpn-provider-open-settings|provider\.access\.open_settings/);
  assert.doesNotMatch(markup, /killswitch/i);
});

test("signed-out action stays on the provider route and focuses authentication", async () => {
  const [source, english, dutch] = await Promise.all([
    readFile(new URL("../backend/exitlane/static/js/provider.js", import.meta.url), "utf8"),
    readFile(new URL("../backend/exitlane/static/locales/en.json", import.meta.url), "utf8").then(JSON.parse),
    readFile(new URL("../backend/exitlane/static/locales/nl.json", import.meta.url), "utf8").then(JSON.parse),
  ]);
  assert.match(source, /vpn-provider-go-to-sign-in"\)\.addEventListener\("click"/);
  assert.match(source, /provider-authentication-card"\)\.scrollIntoView/);
  assert.match(source, /provider-token"\)\?\.focus\(\)/);
  assert.doesNotMatch(source, /vpn-provider-go-to-sign-in[\s\S]{0,400}(showView|history|location\.)/);
  assert.equal(english.provider.access.go_to_sign_in, "Go to sign in");
  assert.equal(dutch.provider.access.go_to_sign_in, "Naar aanmelden");
  assert.match(english.provider.access.sign_in_required_description, /Sign in above/);
  assert.match(dutch.provider.access.sign_in_required_description, /hierboven aan/);
  assert.equal("open_settings" in english.provider.access, false);
  assert.equal("open_settings" in dutch.provider.access, false);
});

test("handlers and provider data loading use explicit provider capabilities", async () => {
  const source = await readFile(
    new URL("../backend/exitlane/static/js/provider.js", import.meta.url),
    "utf8",
  );
  assert.match(source, /controls\.inert = access\.blocked/);
  assert.match(source, /canSelectLocation\) return/);
  assert.match(source, /canDisconnect\) return/);
  assert.match(source, /application\.activeView === "vpn-provider"/);
  assert.match(source, /providerApiPath\("\/locations"\)/);
  assert.doesNotMatch(source, /showView\("settings"/);
});
