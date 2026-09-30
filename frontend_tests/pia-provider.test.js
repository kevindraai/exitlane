import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { providerAuthenticationView, providerAuthenticationErrorCode } from "../backend/exitlane/static/js/provider.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("PIA authentication has its own username and password form in both flows", async () => {
  assert.deepEqual(providerAuthenticationView({
    id: "pia", display_name: "Private Internet Access", authentication_method: "username_password",
  }), {
    providerId: "pia", providerName: "Private Internet Access", method: "username_password",
    nordControls: false, mullvadControls: false, piaControls: true, protonControls: false,
  });
  assert.equal(providerAuthenticationErrorCode({ error: "invalid_credentials" }), "invalid_credentials");
  const [wizard, management, wizardSource, managementSource] = await Promise.all([
    read("../backend/exitlane/static/partials/wizard/provider.html"),
    read("../backend/exitlane/static/partials/views/vpn.html"),
    read("../backend/exitlane/static/js/provider.js"),
    read("../backend/exitlane/static/js/providers.js"),
  ]);
  for (const id of ["pia-username", "pia-password"]) assert.match(wizard, new RegExp(`id="${id}"`));
  for (const id of ["provider-pia-username", "provider-pia-password"]) assert.match(management, new RegExp(`id="${id}"`));
  assert.match(wizardSource, /username\.value = "";/);
  assert.match(wizardSource, /password\.value = "";/);
  assert.match(managementSource, /username\.value = "";/);
  assert.match(managementSource, /password\.value = "";/);
  assert.match(managementSource, /t\("provider\.description\.not_installed", \{ provider: name \}/);
});
