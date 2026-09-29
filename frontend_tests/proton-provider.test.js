import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { providerAuthenticationView } from "../backend/exitlane/static/js/provider.js";
import { providerConnectFailureCode, providerManagementView, vpnProviderAccess } from "../backend/exitlane/static/js/provider-management.js";

test("Proton profile connect distinguishes a proven connection from failed provider results", () => {
  assert.equal(providerConnectFailureCode({ ok: true, success: true }), null);
  assert.equal(providerConnectFailureCode({ ok: true, success: false, error: "connection_failed" }), "connection_failed");
  assert.equal(providerConnectFailureCode({ ok: false, error_code: "vpn_connect_timeout" }), "vpn_connect_timeout");
  assert.equal(providerConnectFailureCode({ success: false, error: "secret value" }), "provider_connect_failed");
});

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("Proton profiles remain a configured local provider, not an account session", () => {
  const view = providerAuthenticationView({ id: "proton", display_name: "Proton VPN", authentication_method: "profile_import" });
  assert.equal(view.method, "profile_import");
  assert.equal(view.protonControls, true);
  assert.equal(view.piaControls, false);
  const configured = {
    is_active: true,
    management: {
      provider: { id: "proton", installation_state: "available" },
      authentication: { state: "configured" },
      connection: { state: "disconnected" },
      capabilities: { can_connect: true, can_select_location: true, can_sign_in: false },
    },
  };
  assert.equal(providerManagementView(configured).authenticationState, "configured");
  assert.equal(vpnProviderAccess(configured).blocked, false);
  configured.management.authentication.state = "unconfigured";
  assert.equal(vpnProviderAccess(configured).blocked, true);
});

test("Proton import controls are provider-specific and never echo profile text", async () => {
  const [wizard, management, source] = await Promise.all([
    read("../backend/exitlane/static/partials/wizard/provider.html"),
    read("../backend/exitlane/static/partials/views/vpn.html"),
    read("../backend/exitlane/static/js/providers.js"),
  ]);
  assert.match(wizard, /id="provider-auth-proton"/);
  assert.match(wizard, /id="proton-import-form"/);
  assert.match(management, /id="provider-proton-file"/);
  assert.match(management, /id="provider-proton-list"/);
  assert.match(source, /fileInput\.value = ""/);
  assert.match(source, /detail\.textContent =/);
  assert.doesNotMatch(source, /innerHTML\s*=\s*config/);
});
