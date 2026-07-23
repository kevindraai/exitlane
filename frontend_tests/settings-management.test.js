import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  passwordErrorTarget,
  passwordRequirementState,
} from "../backend/exitlane/static/js/password-validation.js";
import { providerManagementView } from "../backend/exitlane/static/js/provider-management.js";
import {
  MFA_STATES,
  beginEnrollmentState,
  clearMfaSecrets,
  createMfaState,
  mfaVisibility,
  reconcileMfaState,
  revealRecoveryCodes,
} from "../backend/exitlane/static/js/mfa-state.js";

const sourceUrl = new URL("../backend/exitlane/static/js/settings.js", import.meta.url);
const markupUrl = new URL("../backend/exitlane/static/partials/views/settings.html", import.meta.url);
const providerSourceUrl = new URL("../backend/exitlane/static/js/providers.js", import.meta.url);
const providerMarkupUrl = new URL("../backend/exitlane/static/partials/views/vpn.html", import.meta.url);
const englishUrl = new URL("../backend/exitlane/static/locales/en.json", import.meta.url);
const dutchUrl = new URL("../backend/exitlane/static/locales/nl.json", import.meta.url);

test("credential forms use protected APIs and always clear secret fields", async () => {
  const source = await readFile(sourceUrl, "utf8");
  const providerSource = await readFile(providerSourceUrl, "utf8");
  assert.match(source, /api\("\/api\/auth\/password"/);
  assert.match(providerSource, /\/api\/vpn\/providers\/\$\{encodeURIComponent\(providerId\)\}\/authenticate/);
  assert.match(source, /finally \{\s*clearSecretFields\(\.\.\.fields\)/);
  assert.match(providerSource, /finally \{\s*field\.value = ""/);
  assert.match(source, /setBusy\(button, true/);
  assert.match(source, /setBusy\(button, false/);
});

test("settings contains application settings but no provider or WireGuard management cards", async () => {
  const markup = await readFile(markupUrl, "utf8");
  for (const section of ["settings-authentication", "settings-network"]) {
    assert.match(markup, new RegExp(`id="${section}"`));
  }
  assert.doesNotMatch(markup, /id="settings-vpn"/);
  assert.doesNotMatch(markup, /id="settings-wireguard"/);
  assert.doesNotMatch(markup, /\/api\/ingress\/wireguard\/config\/regenerate/);
  assert.match(markup, /autocomplete="current-password"/);
  assert.match(markup, /autocomplete="new-password"/);
  assert.doesNotMatch(markup, /NordVPN|provider-token/i);
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

test("password field wrappers do not stretch to the tallest validation column", async () => {
  const css = await readFile(
    new URL("../backend/exitlane/static/style.css", import.meta.url),
    "utf8",
  );
  assert.match(css, /\.authentication-fields[\s\S]{0,100}align-items: start/);
  assert.match(css, /\.authentication-fields > label[\s\S]{0,140}align-self: start/);
  assert.doesNotMatch(css, /\.authentication-fields[\s\S]{0,160}height:\s*100%/);
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

test("MFA main states are exclusive and clear secrets atomically", () => {
  const state = createMfaState();
  assert.deepEqual(mfaVisibility(state.mode), {
    disabled: true, enrollment: false, enabled: false, recovery: false,
  });
  beginEnrollmentState(state, {
    enrollment: "dummy-enrollment",
    setup_key: "DUMMYSETUPKEY",
    qr_svg: "<svg>dummy</svg>",
  });
  assert.deepEqual(mfaVisibility(state.mode), {
    disabled: false, enrollment: true, enabled: false, recovery: false,
  });
  assert.equal(state.pendingEnrollment, "dummy-enrollment");
  revealRecoveryCodes(state, ["dummy-one", "dummy-two"]);
  assert.deepEqual(mfaVisibility(state.mode), {
    disabled: false, enrollment: false, enabled: true, recovery: true,
  });
  assert.equal(state.pendingEnrollment, null);
  clearMfaSecrets(state, MFA_STATES.ENABLED);
  assert.deepEqual(state.recoveryCodes, []);
  assert.equal(state.qrSvg, null);
  assert.equal(state.setupKey, null);
});

test("backend disabled status always overrides client MFA secret state", () => {
  const state = createMfaState();
  beginEnrollmentState(state, {
    enrollment: "dummy-enrollment",
    setup_key: "DUMMYSETUPKEY",
    qr_svg: "<svg>dummy</svg>",
  });
  revealRecoveryCodes(state, ["dummy-recovery"]);
  reconcileMfaState(state, { enabled: false });
  assert.equal(state.mode, MFA_STATES.DISABLED);
  assert.equal(state.pendingEnrollment, null);
  assert.equal(state.setupKey, null);
  assert.equal(state.qrSvg, null);
  assert.deepEqual(state.recoveryCodes, []);
});

test("MFA markup and lifecycle enforce exclusive controls and secret cleanup", async () => {
  const [markup, source, css] = await Promise.all([
    readFile(markupUrl, "utf8"),
    readFile(sourceUrl, "utf8"),
    readFile(new URL("../backend/exitlane/static/style.css", import.meta.url), "utf8"),
  ]);
  assert.match(markup, /<form[^>]+hidden[^>]+id="settings-mfa-enable-form"/);
  assert.match(markup, /id="settings-mfa-enrollment"/);
  assert.match(markup, /<form[^>]+hidden[^>]+id="settings-mfa-manage-form"/);
  assert.match(markup, /<dialog[^>]+aria-describedby="settings-recovery-description"[^>]+aria-labelledby="settings-recovery-title"/);
  assert.match(markup, /id="settings-recovery-saved"/);
  assert.match(source, /mfaVisibility\(mfaState\.mode\)/);
  assert.match(source, /settings-mfa-enable-form"\)\.hidden = !visibility\.disabled/);
  assert.match(source, /settings-mfa-enrollment"\)\.hidden = !visibility\.enrollment/);
  assert.match(source, /settings-mfa-manage-form"\)\.hidden = !visibility\.enabled/);
  assert.match(source, /clearTemporaryMfaState\(MFA_STATES\.DISABLED\)/);
  assert.match(source, /event\.detail\.view !== "settings"[\s\S]+clearTemporaryMfaState/);
  assert.match(source, /exitlane:authenticationrequired"[\s\S]+clearTemporaryMfaState/);
  assert.match(source, /pagehide"[\s\S]+clearTemporaryMfaState/);
  assert.match(source, /settings-recovery-code-list"\)\.textContent = ""/);
  assert.match(css, /\.mfa-enrollment-grid[\s\S]+0\.45fr[\s\S]+0\.55fr/);
  assert.match(css, /\.mfa-qr-zone[\s\S]+place-items: center/);
  assert.match(css, /\.mfa-qr-frame[\s\S]+aspect-ratio: 1[\s\S]+background: #fff/);
  assert.match(css, /\.mfa-qr-frame > svg\.mfa-qr-svg[\s\S]+background: #fff/);
  assert.match(css, /#settings-mfa-setup-key[\s\S]+overflow-wrap: anywhere/);
  assert.doesNotMatch(css, /#settings-mfa-setup-key[\s\S]{0,160}overflow-x: auto/);
  assert.match(markup, /class="mfa-setup-key-control"[\s\S]+data-lucide-icon="copy"/);
  assert.match(markup, /id="settings-mfa-confirm-code" inputmode="numeric" maxlength="6"/);
  assert.match(markup, /autocomplete="one-time-code"[^>]+id="settings-mfa-confirm-code"/);
  assert.match(source, /settings\.authentication\.mfa\.setting_up/);
  assert.match(css, /@media \(max-width: 820px\)[\s\S]+\.mfa-enrollment-grid/);
});

test("network deployment status and editable security configuration stay separate", async () => {
  const [markup, source] = await Promise.all([
    readFile(markupUrl, "utf8"),
    readFile(sourceUrl, "utf8"),
  ]);
  assert.match(markup, /id="settings-network-status-title"[\s\S]+id="settings-deployment-status"/);
  assert.match(markup, /id="settings-network-configuration-title"[\s\S]+id="settings-network-form"/);
  assert.match(markup, /id="settings-network-public-url"/);
  assert.match(markup, /id="settings-network-proxies" rows="5"/);
  assert.match(markup, /id="settings-network-cookie-policy"/);
  assert.match(markup, /id="settings-network-password" required="" type="password"/);
  assert.match(markup, /id="settings-network-totp-field"/);
  assert.match(markup, /id="settings-network-confirm"/);
  assert.match(source, /configuration\.environment_overrides\[field\]/);
  assert.match(source, /controlSelector\)\.disabled = locked/);
  assert.match(source, /method: "PUT"/);
  assert.match(source, /access_loss_confirmation_required/);
  assert.match(source, /broad_proxy_confirmation_required/);
  assert.match(source, /direct_peer: deployment\.direct_peer/);
});

test("MFA copy actions retain unformatted state and are explicit user actions", async () => {
  const source = await readFile(sourceUrl, "utf8");
  assert.match(source, /settings-mfa-copy-key"\)\.addEventListener\("click"/);
  assert.match(source, /navigator\.clipboard\.writeText\(mfaState\.setupKey\)/);
  assert.match(source, /settings-recovery-copy"\)\.addEventListener\("click"/);
  assert.match(source, /navigator\.clipboard\.writeText\(mfaState\.recoveryCodes\.join\("\\n"\)\)/);
  assert.doesNotMatch(source, /localStorage[\s\S]{0,80}(setupKey|recoveryCodes)/);
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
    for (const key of [
      "setup_key", "copy_setup_key", "copied", "recovery_title", "copy_codes",
      "codes_saved", "close_codes", "scan", "manual", "enrollment_title",
      "qr_description", "enabled", "disabled", "remaining", "scan_or_manual",
      "or", "manual_label", "setup_key_safety", "verify_six_digits", "setting_up",
    ]) {
      assert.ok(locale.settings.authentication.mfa[key]);
    }
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

test("provider page has state regions and no killswitch control", async () => {
  const markup = await readFile(providerMarkupUrl, "utf8");
  const source = await readFile(providerSourceUrl, "utf8");
  assert.match(markup, /<div hidden="" id="provider-signed-in"/);
  assert.match(markup, /id="provider-token-form"/);
  assert.match(markup, /<div hidden="" id="provider-unavailable"/);
  assert.match(markup, /id="provider-end-session"/);
  assert.doesNotMatch(markup, /killswitch/i);
  const statusRegion = markup.indexOf('class="provider-management-status-region"');
  const signedInRegion = markup.indexOf('id="provider-signed-in"');
  const tokenForm = markup.indexOf('id="provider-token-form"');
  assert.ok(statusRegion > -1 && statusRegion < signedInRegion && signedInRegion < tokenForm);
  assert.match(source, /provider-signed-in"\)\.hidden = !signedIn/);
  assert.match(source, /provider-token-form"\)\.hidden = !\(signedOut && view\.canSignIn\)/);
  assert.match(source, /provider-end-session"\)\.hidden = !view\.canSignOut/);
});

test("session ending uses an accessible confirmed single-flight mutation", async () => {
  const markup = await readFile(providerMarkupUrl, "utf8");
  const source = await readFile(providerSourceUrl, "utf8");
  assert.match(markup, /<dialog[^>]+aria-describedby="provider-sign-out-description"[^>]+aria-labelledby="provider-sign-out-title"/);
  assert.match(markup, /class="button button-danger"[^>]+id="provider-sign-out-confirm"/);
  assert.match(source, /\/api\/vpn\/providers\/\$\{encodeURIComponent\(id\)\}\/sign-out/);
  assert.match(source, /if \(signingOut\) return/);
  assert.match(source, /if \(!signingOut\) select\("#provider-sign-out-dialog"\)\.close\(\)/);
  assert.match(source, /finally \{\s*signingOut = false;\s*setBusy\(button, false\)/);
});

test("token sign-in refreshes provider state and always clears the token", async () => {
  const source = await readFile(providerSourceUrl, "utf8");
  assert.match(source, /\/authenticate`[\s\S]+refreshProviderState/);
  assert.match(source, /finally \{\s*field\.value = ""/);
});
