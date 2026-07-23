import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  passwordErrorTarget,
  passwordRequirementState,
} from "../backend/exitlane/static/js/password-validation.js";
import { providerManagementView } from "../backend/exitlane/static/js/provider-management.js";

const sourceUrl = new URL("../backend/exitlane/static/js/settings.js", import.meta.url);
const markupUrl = new URL("../backend/exitlane/static/partials/views/settings.html", import.meta.url);
const englishUrl = new URL("../backend/exitlane/static/locales/en.json", import.meta.url);
const dutchUrl = new URL("../backend/exitlane/static/locales/nl.json", import.meta.url);

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

test("password status is a stable full-width region outside the field grid", async () => {
  const markup = await readFile(markupUrl, "utf8");
  const status = markup.indexOf('id="settings-password-status"');
  const gridStart = markup.indexOf('id="settings-password-fields"');
  const gridEnd = markup.indexOf("</div>", gridStart);
  assert.ok(status > -1 && status < gridStart);
  assert.ok(status < gridStart || status > gridEnd);
  assert.match(markup, /class="authentication-status"[^>]+hidden[^>]+role="status"/);
  assert.match(markup, /class="form-grid authentication-fields"/);
  assert.match(markup, /class="authentication-form-footer"/);
});

test("password requirements validate minimum, difference, match, and submit readiness", () => {
  const neutral = passwordRequirementState({
    currentPassword: "",
    newPassword: "",
    confirmation: "",
    minimumLength: 12,
  });
  assert.deepEqual(
    { minimum: neutral.minimum, different: neutral.different, matches: neutral.matches, complete: neutral.complete },
    { minimum: null, different: null, matches: null, complete: false },
  );

  const tooShort = passwordRequirementState({
    currentPassword: "current password",
    newPassword: "short",
    confirmation: "short",
    minimumLength: 12,
  });
  assert.equal(tooShort.minimum, false);
  assert.equal(tooShort.matches, true);
  assert.equal(tooShort.complete, false);

  const unchanged = passwordRequirementState({
    currentPassword: "same password",
    newPassword: "same password",
    confirmation: "same password",
    minimumLength: 12,
  });
  assert.equal(unchanged.different, false);
  assert.equal(unchanged.complete, false);

  const mismatch = passwordRequirementState({
    currentPassword: "current password",
    newPassword: "a valid new password",
    confirmation: "another password",
    minimumLength: 12,
  });
  assert.equal(mismatch.matches, false);
  assert.equal(mismatch.complete, false);

  const valid = passwordRequirementState({
    currentPassword: "current password",
    newPassword: "a valid new password",
    confirmation: "a valid new password",
    minimumLength: 12,
  });
  assert.equal(valid.complete, true);
});

test("password server errors map to one field or the general status", () => {
  assert.equal(passwordErrorTarget("invalid_credentials"), "#settings-current-password-error");
  assert.equal(passwordErrorTarget("password_mismatch"), "#settings-confirm-password-error");
  assert.equal(passwordErrorTarget("password_unchanged"), "#settings-new-password-error");
  assert.equal(passwordErrorTarget("password_policy"), "#settings-new-password-error");
  assert.equal(passwordErrorTarget("too_many_attempts"), "#settings-password-status");
});

test("password feedback is accessible and not identifiable by color alone", async () => {
  const markup = await readFile(markupUrl, "utf8");
  const source = await readFile(sourceUrl, "utf8");
  for (const describedBy of [
    "settings-current-password-error",
    "settings-password-minimum settings-password-different settings-new-password-error",
    "settings-password-match settings-confirm-password-error",
  ]) {
    assert.match(markup, new RegExp(`aria-describedby="${describedBy}"`));
  }
  assert.match(markup, /aria-live="polite"/);
  assert.match(source, /"○"/);
  assert.match(source, /"✓"/);
  assert.match(source, /"✕"/);
  assert.match(source, /frontendConfig\.password\.minimumLength/);
});

test("English and Dutch expose password rules and safe token diagnostics", async () => {
  const [english, dutch] = await Promise.all(
    [englishUrl, dutchUrl].map(async (url) => JSON.parse(await readFile(url, "utf8"))),
  );
  for (const locale of [english, dutch]) {
    for (const rule of ["minimum", "different", "matches"]) {
      assert.ok(locale.settings.authentication.requirements[rule]);
    }
    for (const code of [
      "already_logged_in",
      "invalid_token",
      "timeout",
      "daemon_unavailable",
      "command_unavailable",
      "token_replacement_unsupported",
      "provider_error",
    ]) {
      assert.ok(locale.settings.vpn.errors[code]);
    }
    assert.ok(locale.settings.vpn.signed_in_limitation);
  }
});

test("provider management keeps authentication and tunnel state distinct", () => {
  const signedIn = providerManagementView({
    management: {
      provider: { id: "nordvpn", installation_state: "installed" },
      authentication: { state: "signed_in" },
      connection: { state: "connected" },
      capabilities: {
        can_sign_in: false,
        can_sign_out: true,
        can_manage_killswitch: false,
      },
    },
  });
  assert.equal(signedIn.authenticationState, "signed_in");
  assert.equal(signedIn.connectionState, "connected");
  assert.equal(signedIn.canSignOut, true);
  assert.equal(signedIn.canSignIn, false);
  assert.equal(signedIn.canManageKillswitch, false);

  const signedOut = providerManagementView({
    management: {
      authentication: { state: "signed_out" },
      connection: { state: "disconnected" },
      capabilities: { can_sign_in: true, can_sign_out: false },
    },
  });
  assert.equal(signedOut.canSignIn, true);
  assert.equal(signedOut.canSignOut, false);

  const olderUnknown = providerManagementView({});
  assert.equal(olderUnknown.authenticationState, "unknown");
  assert.equal(olderUnknown.canSignOut, false);
  assert.equal(olderUnknown.canManageKillswitch, false);
});

test("NordVPN card has state regions and no killswitch control", async () => {
  const markup = await readFile(markupUrl, "utf8");
  const source = await readFile(sourceUrl, "utf8");
  assert.match(markup, /<div hidden="" id="settings-provider-signed-in"/);
  assert.match(markup, /id="settings-token-form"/);
  assert.match(markup, /<div hidden="" id="settings-provider-unavailable"/);
  assert.match(markup, /id="settings-provider-end-session"/);
  assert.doesNotMatch(markup, /killswitch/i);
  const statusRegion = markup.indexOf('class="provider-management-status-region"');
  const signedInRegion = markup.indexOf('id="settings-provider-signed-in"');
  const tokenForm = markup.indexOf('id="settings-token-form"');
  assert.ok(statusRegion > -1 && statusRegion < signedInRegion && signedInRegion < tokenForm);
  assert.match(source, /settings-provider-signed-in"\)\.hidden = !signedIn/);
  assert.match(source, /settings-token-form"\)\.hidden = !\(signedOut && view\.canSignIn\)/);
  assert.match(source, /settings-provider-unavailable"\)\.hidden = !unavailable/);
  assert.match(source, /settings-provider-end-session"\)\.hidden = !view\.canSignOut/);
});

test("session ending uses an accessible confirmed single-flight mutation", async () => {
  const markup = await readFile(markupUrl, "utf8");
  const source = await readFile(sourceUrl, "utf8");
  assert.match(markup, /<dialog[^>]+aria-describedby="settings-provider-sign-out-description"[^>]+aria-labelledby="settings-provider-sign-out-title"/);
  assert.match(markup, /class="button button-danger"[^>]+id="settings-provider-sign-out-confirm"/);
  assert.equal(source.match(/api\("\/api\/providers\/nordvpn\/session\/end"/g)?.length, 1);
  assert.match(source, /if \(signingOut\) return/);
  assert.match(source, /if \(!signingOut\) select\("#settings-provider-sign-out-dialog"\)\.close\(\)/);
  assert.match(source, /authenticationState !== "signed_out"/);
  assert.match(source, /finally \{\s*signingOut = false;\s*setBusy\(button, false\)/);
});

test("token sign-in refreshes provider state and always clears the token", async () => {
  const source = await readFile(sourceUrl, "utf8");
  assert.match(source, /api\("\/api\/providers\/nordvpn\/token"[\s\S]+await refreshProviderState/);
  assert.match(source, /finally \{\s*field\.value = ""/);
});
