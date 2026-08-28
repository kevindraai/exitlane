import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  providerAuthenticationErrorCode,
  providerAuthenticationView,
} from "../backend/exitlane/static/js/provider.js";
import { vpnProviderAccess } from "../backend/exitlane/static/js/provider-management.js";
import { providerOverviewView } from "../backend/exitlane/static/js/providers.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

const readyStatus = (isActive) => ({
  installed: true,
  available: true,
  authenticated: true,
  connected: false,
  is_active: isActive,
  management: {
    provider: { id: "mullvad", installation_state: "available" },
    authentication: { state: "signed_in" },
    connection: { state: "disconnected" },
    capabilities: {
      can_connect: isActive,
      can_select_location: isActive,
      can_sign_out: true,
    },
  },
});

test("NordVPN and Mullvad select isolated authentication renderers from metadata", () => {
  assert.deepEqual(providerAuthenticationView({
    id: "nordvpn",
    display_name: "NordVPN",
    authentication_method: "token",
  }), {
    providerId: "nordvpn",
    providerName: "NordVPN",
    method: "token",
    nordControls: true,
    mullvadControls: false,
  });
  assert.deepEqual(providerAuthenticationView({
    id: "mullvad",
    display_name: "Mullvad VPN",
    authentication_method: "account_number",
  }), {
    providerId: "mullvad",
    providerName: "Mullvad VPN",
    method: "account_number",
    nordControls: false,
    mullvadControls: true,
  });
  assert.equal(providerAuthenticationErrorCode({ error: "too_many_devices" }), "too_many_devices");
  assert.equal(providerAuthenticationErrorCode({ error: "invalid_account" }), "invalid_account");
});

test("Mullvad account-number controls are masked, accessible and cleared immediately", async () => {
  const [markup, source] = await Promise.all([
    read("../backend/exitlane/static/partials/wizard/provider.html"),
    read("../backend/exitlane/static/js/provider.js"),
  ]);
  assert.match(markup, /id="provider-auth-mullvad"/);
  assert.match(markup, /id="mullvad-account-number"[^>]+inputmode="numeric"/);
  assert.match(markup, /id="mullvad-account-number"[^>]+maxlength="19"[^>]+minlength="16"/);
  assert.match(markup, /id="mullvad-account-number"[^>]+pattern="\[0-9 \]\{16,19\}"/);
  assert.match(markup, /id="mullvad-account-number"[^>]+type="password"/);
  assert.match(markup, /<input autocomplete="off" id="mullvad-account-number"/);
  assert.match(markup, /href="https:\/\/mullvad\.net\/account\/"[^>]+rel="noopener noreferrer"/);

  const start = source.indexOf("async function loginWithCredential");
  const end = source.indexOf("async function loginWithCallback");
  const flow = source.slice(start, end);
  assert.match(flow, /\{ credential: input\.value \}/);
  assert.match(flow, /const request = postJson[\s\S]+input\.value = "";[\s\S]+const result = await request/);
  assert.match(flow, /finally \{\s*input\.value = "";/);
  assert.doesNotMatch(flow, /localStorage|sessionStorage|console\.|result\.(?:stdout|stderr)/);
});

test("provider management removes account-number validation when rendering NordVPN", async () => {
  const source = await read("../backend/exitlane/static/js/providers.js");
  assert.match(source, /if \(accountNumber\) \{[\s\S]+setAttribute\("pattern", "\[0-9 \]\{16,19\}"\)/);
  assert.match(source, /else \{[\s\S]+removeAttribute\("pattern"\)/);
  assert.doesNotMatch(source, /credential\.pattern\s*=\s*accountNumber\s*\?[^;]+:\s*""/);
});

test("first-run provider selection is an accessible independent multi-select with an exclusive none flow", async () => {
  const [markup, wizard] = await Promise.all([
    read("../backend/exitlane/static/partials/wizard/provider.html"),
    read("../backend/exitlane/static/js/wizard.js"),
  ]);
  assert.match(markup, /id="wizard-provider-choices" role="list"/);
  assert.doesNotMatch(markup, /<select[^>]+provider/i);
  assert.match(wizard, /item\.setAttribute\("role", "checkbox"\)/);
  assert.match(wizard, /item\.setAttribute\("aria-checked", String\(selected\)\)/);
  assert.match(wizard, /selected\s*\?\s*selectedIds\.filter[\s\S]+\[\.\.\.selectedIds, provider\.id\]/);
  assert.match(wizard, /postJson\("\/api\/setup\/providers", \{ provider_ids: providerIds \}\)/);
  assert.match(wizard, /providerSelectionInFlight/);
  assert.match(wizard, /postJson\("\/api\/setup\/provider\/defer"\)/);
  assert.match(wizard, /\/api\/setup\/providers\/\$\{encodeURIComponent\(providerId\)\}\/skip/);
  assert.match(wizard, /active_provider_selection_required/);
  assert.match(wizard, /\/api\/vpn\/providers\/\$\{encodeURIComponent\(providerId\)\}\/activate/);
});

test("active state is separate from authentication and inactive controls fail closed", () => {
  const inactiveStatus = readyStatus(false);
  const access = vpnProviderAccess(inactiveStatus);
  assert.equal(access.authenticationState, "signed_in");
  assert.equal(access.isActive, false);
  assert.equal(access.state, "inactive");
  assert.equal(access.blocked, true);
  assert.equal(access.canConnect, false);

  const inactive = providerOverviewView({
    id: "mullvad",
    display_name: "Mullvad VPN",
    active: false,
    status: inactiveStatus,
  });
  assert.equal(inactive.active, false);
  assert.equal(inactive.authenticationState, "signed_in");
  assert.equal(inactive.canActivate, true);

  const active = providerOverviewView({
    id: "nordvpn",
    display_name: "NordVPN",
    active: true,
    status: readyStatus(true),
  });
  assert.equal(active.active, true);
  assert.equal(active.canActivate, false);
});

test("Mullvad and active-provider copy has EN/NL parity and responsive styling", async () => {
  const [english, dutch, styles] = await Promise.all([
    read("../backend/exitlane/static/locales/en.json").then(JSON.parse),
    read("../backend/exitlane/static/locales/nl.json").then(JSON.parse),
    read("../backend/exitlane/static/style.css"),
  ]);
  const requiredErrors = [
    "invalid_account_format",
    "invalid_account",
    "too_many_devices",
    "account_expired",
    "daemon_unavailable",
    "command_unavailable",
    "timeout",
    "already_logged_in",
    "credential_replacement_unsupported",
    "provider_error",
  ];
  for (const locale of [english, dutch]) {
    assert.ok(locale.step3.active_provider_title);
    assert.ok(locale.step3.skip_provider);
    assert.ok(locale.provider.active);
    assert.ok(locale.provider.inactive);
    assert.ok(locale.provider.make_active.includes("{provider}"));
    assert.ok(locale.provider.access.inactive_description.includes("{provider}"));
    for (const key of requiredErrors) assert.ok(locale.provider.mullvad.errors[key]);
  }
  assert.match(styles, /\.provider-choice--selected/);
  assert.match(styles, /\.provider-activity-controls/);
  assert.match(styles, /@media \(max-width: 650px\)[\s\S]+\.provider-card-actions/);
});
