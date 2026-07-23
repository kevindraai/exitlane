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
    can_manage_killswitch: false,
  }));
  assert.equal(access.blocked, false);
  assert.equal(access.canSelectLocation, true);
  assert.equal(access.canManageKillswitch, false);
  assert.equal(vpnProviderAccess(status("signed_out")).blocked, true);
});

test("VPN markup provides an accessible inert blocking layer without killswitch UI", async () => {
  const markup = await readFile(
    new URL("../backend/exitlane/static/partials/views/vpn.html", import.meta.url),
    "utf8",
  );
  assert.match(markup, /id="vpn-provider-blocker" role="status"/);
  assert.match(markup, /id="vpn-provider-controls"/);
  assert.match(markup, /id="vpn-provider-open-settings"/);
  assert.doesNotMatch(markup, /killswitch/i);
});

test("handlers and provider data loading use explicit provider capabilities", async () => {
  const source = await readFile(
    new URL("../backend/exitlane/static/js/provider.js", import.meta.url),
    "utf8",
  );
  assert.match(source, /controls\.inert = access\.blocked/);
  assert.match(source, /canSelectLocation\) return/);
  assert.match(source, /canDisconnect\) return/);
  assert.match(source, /application\.activeView === "vpn"/);
  assert.match(source, /showView\("settings", \{ section: "vpn" \}\)/);
});
