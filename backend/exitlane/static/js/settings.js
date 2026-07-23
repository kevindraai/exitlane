import { api } from "./api.js";
import {
  getCurrentLanguage,
  t,
} from "./i18n.js";
import {
  getColorSchemePreference,
} from "./theme.js";
import {
  clearInlineError,
  select,
  setBusy,
  showInlineError,
  showMessage,
} from "./ui.js";
import { getSlice, resetAuthenticatedState } from "./state.js";
import { frontendConfig } from "./config.js";
import {
  passwordErrorTarget,
  passwordRequirementState,
} from "./password-validation.js";
import {
  MFA_STATES,
  beginEnrollmentState,
  clearMfaSecrets,
  createMfaState,
  mfaVisibility,
  reconcileMfaState,
  revealRecoveryCodes,
} from "./mfa-state.js";

let savedGeneral = null;
let savedSettings = null;
let settingsLoaded = false;
let loadingSettings = false;
const mfaState = createMfaState();

function removeRenderedMfaSecrets() {
  select("#settings-mfa-setup-key").textContent = "";
  select("#settings-mfa-qr").replaceChildren();
  select("#settings-mfa-confirm-code").value = "";
  select("#settings-recovery-code-list").textContent = "";
}

function closeRecoveryCodes() {
  const dialog = select("#settings-recovery-codes");
  if (dialog.open) dialog.close();
  select("#settings-recovery-saved").checked = false;
  select("#settings-recovery-close").disabled = true;
}

function renderMfaState() {
  const visibility = mfaVisibility(mfaState.mode);
  select("#settings-mfa-enable-form").hidden = !visibility.disabled;
  select("#settings-mfa-enrollment").hidden = !visibility.enrollment;
  select("#settings-mfa-manage-form").hidden = !visibility.enabled;
  if (visibility.enrollment) {
    select("#settings-mfa-setup-key").textContent = mfaState.setupKey
      ?.match(/.{1,4}/g)?.join(" ") || "";
    const documentNode = new DOMParser().parseFromString(mfaState.qrSvg, "image/svg+xml");
    select("#settings-mfa-qr").replaceChildren(
      document.importNode(documentNode.documentElement, true),
    );
  }
  if (visibility.recovery) {
    const codeList = select("#settings-recovery-code-list");
    codeList.replaceChildren(...mfaState.recoveryCodes.map((code) => {
      const item = document.createElement("code");
      item.textContent = code;
      return item;
    }));
    const dialog = select("#settings-recovery-codes");
    if (!dialog.open) dialog.showModal();
    select("#settings-recovery-title").focus();
  } else {
    closeRecoveryCodes();
  }
}

function clearTemporaryMfaState(mode = MFA_STATES.DISABLED) {
  clearMfaSecrets(mfaState, mode);
  removeRenderedMfaSecrets();
  clearSecretFields(
    "#settings-mfa-password",
    "#settings-mfa-manage-password",
    "#settings-mfa-manage-code",
  );
  renderMfaState();
}

function showRecoveryCodes(codes) {
  revealRecoveryCodes(mfaState, codes);
  removeRenderedMfaSecrets();
  renderMfaState();
}

async function loadAuthenticationSecurity() {
  const [security, deployment] = await Promise.all([
    api("/api/auth/security"),
    api("/api/deployment/security"),
  ]);
  reconcileMfaState(mfaState, security.mfa);
  renderMfaState();
  select("#settings-mfa-status").textContent = security.mfa.enabled
    ? t("settings.authentication.mfa.enabled", {}, "Enabled")
    : t("settings.authentication.mfa.disabled", {}, "Disabled");
  select("#settings-mfa-recovery-count").textContent = security.mfa.enabled
    ? t(
      "settings.authentication.mfa.remaining",
      { count: security.mfa.recovery_codes_remaining },
      `${security.mfa.recovery_codes_remaining} recovery codes remaining`,
    )
    : "";
  const list = select("#settings-session-list");
  list.replaceChildren();
  for (const session of security.sessions) {
    const row = document.createElement("div");
    row.className = "session-row";
    const description = document.createElement("span");
    description.textContent = `${session.user_agent} · ${session.client_ip}${session.current ? ` · ${t("settings.authentication.sessions.current", {}, "Current session")}` : ""}`;
    row.appendChild(description);
    if (!session.current) {
      const revoke = document.createElement("button");
      revoke.className = "button button-secondary";
      revoke.textContent = t("settings.authentication.sessions.revoke", {}, "Revoke");
      revoke.addEventListener("click", async () => {
        await api(`/api/auth/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
        await loadAuthenticationSecurity();
      });
      row.appendChild(revoke);
    }
    list.appendChild(row);
  }
  const status = select("#settings-deployment-status");
  status.replaceChildren();
  for (const [key, value] of Object.entries({
    https: deployment.https,
    reverse_proxy: deployment.reverse_proxy,
    trusted_proxy: deployment.direct_peer_trusted,
    secure_cookie: deployment.secure_cookie,
    public_url: deployment.public_url || "—",
    warnings: deployment.warnings.join(", ") || "—",
  })) {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const detail = document.createElement("dd");
    term.textContent = t(`settings.network.${key}`, {}, key);
    detail.textContent = typeof value === "boolean" ? (value ? t("common.yes", {}, "Yes") : t("common.no", {}, "No")) : value;
    row.append(term, detail);
    status.appendChild(row);
  }
}

function generalFormValue() {
  return {
    timezone: select("#settings-timezone").value,
    provider_refresh_interval_seconds: Number(
      select("#settings-polling-interval").value,
    ),
  };
}

function generalChanged() {
  return savedGeneral !== null &&
    JSON.stringify(generalFormValue()) !== JSON.stringify(savedGeneral);
}

function changedGeneralValues() {
  const current = generalFormValue();
  return Object.fromEntries(
    Object.entries(current).filter(([key, value]) => value !== savedGeneral[key]),
  );
}

function updateSaveState() {
  select("#settings-general-save").disabled = !generalChanged();
}

function fillTimezones(timezones, selected) {
  const field = select("#settings-timezone");
  field.replaceChildren();
  for (const timezone of timezones) {
    const option = document.createElement("option");
    option.value = timezone;
    option.textContent = timezone;
    option.selected = timezone === selected;
    field.appendChild(option);
  }
}

export function renderAbout(about) {
  select("#settings-product").textContent = about.product;
  select("#settings-version").textContent = about.version;
  select("#settings-runtime").textContent = about.runtime_environment;
  select("#settings-python").textContent = about.python_version;
  select("#settings-platform").textContent = about.platform;
  select("#settings-setup-status").textContent = about.setup_complete
    ? t("settings.about.setup_complete", {}, "Complete")
    : t("settings.about.setup_incomplete", {}, "Incomplete");
  select("#settings-repository").href = about.repository_url;
  select("#settings-license").textContent = about.license;
}

export function renderSettings(data) {
  savedSettings = JSON.parse(JSON.stringify(data));
  savedGeneral = { ...data.general };
  fillTimezones(data.timezones, data.general.timezone);
  select("#settings-polling-interval").value =
    data.general.provider_refresh_interval_seconds;
  select("#settings-hostname").textContent = data.system.hostname;
  select("#settings-system-timezone").textContent = data.system.system_timezone;
  select("#settings-session-duration").value =
    data.system.session_duration_seconds;
  select("#settings-language").value = getCurrentLanguage();
  select("#settings-color-scheme").value = getColorSchemePreference();
  renderAbout(data.about);
  clearInlineError("#settings-general-error");
  updateSaveState();
}

export async function loadSettings({ force = false } = {}) {
  if (loadingSettings || (settingsLoaded && !force)) return;
  loadingSettings = true;
  try {
    const data = await api("/api/settings");
    renderSettings(data);
    await loadAuthenticationSecurity();
    settingsLoaded = true;
    return data;
  } catch (error) {
    showMessage(t("settings.errors.load", {}, error.message), "error");
  } finally {
    loadingSettings = false;
  }
  return null;
}

async function beginMfa(event) {
  event.preventDefault();
  const result = await api("/api/auth/mfa/enrollment", {
    method: "POST",
    body: JSON.stringify({ current_password: select("#settings-mfa-password").value }),
  });
  select("#settings-mfa-password").value = "";
  beginEnrollmentState(mfaState, result);
  removeRenderedMfaSecrets();
  renderMfaState();
  select("#settings-mfa-confirm-code").focus();
}

async function confirmMfa(event) {
  event.preventDefault();
  const result = await api("/api/auth/mfa/enrollment/confirm", {
    method: "POST",
    body: JSON.stringify({
      enrollment: mfaState.pendingEnrollment,
      code: select("#settings-mfa-confirm-code").value,
    }),
  });
  showRecoveryCodes(result.recovery_codes);
  await loadAuthenticationSecurity();
}

async function cancelMfa() {
  await api("/api/auth/mfa/enrollment", { method: "DELETE" });
  clearTemporaryMfaState(MFA_STATES.DISABLED);
  await loadAuthenticationSecurity();
  select("#settings-mfa-password").focus();
}

async function manageMfa(event) {
  event.preventDefault();
  const action = event.submitter?.dataset.action;
  const payload = {
    current_password: select("#settings-mfa-manage-password").value,
    code: select("#settings-mfa-manage-code").value,
  };
  if (action === "disable") {
    await api("/api/auth/mfa/disable", { method: "POST", body: JSON.stringify(payload) });
    clearTemporaryMfaState(MFA_STATES.DISABLED);
    window.dispatchEvent(new CustomEvent("exitlane:authenticationrequired"));
  } else {
    clearTemporaryMfaState(MFA_STATES.ENABLED);
    const result = await api("/api/auth/mfa/recovery-codes", { method: "POST", body: JSON.stringify(payload) });
    showRecoveryCodes(result.recovery_codes);
    await loadAuthenticationSecurity();
  }
  clearSecretFields("#settings-mfa-manage-password", "#settings-mfa-manage-code");
}

export async function saveGeneralSettings(event) {
  event.preventDefault();
  if (!generalChanged()) return;
  const button = select("#settings-general-save");
  clearInlineError("#settings-general-error");
  setBusy(button, true, t("settings.messages.saving", {}, "Saving…"));
  try {
    const updated = await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({ general: changedGeneralValues() }),
    });
    let data;
    try {
      data = await api("/api/settings");
    } catch {
      data = updated;
    }
    renderSettings(data);
    window.dispatchEvent(new CustomEvent("exitlane:settingschange", {
      detail: { providerRefreshIntervalSeconds:
        data.general.provider_refresh_interval_seconds },
    }));
    showMessage(t("settings.messages.saved", {}, "Settings saved."));
  } catch (error) {
    renderSettings(savedSettings);
    showInlineError(
      t("settings.errors.save", { message: error.message }, `Could not save: ${error.message}`),
      "#settings-general-error",
    );
  } finally {
    setBusy(button, false);
    updateSaveState();
  }
}

function clearSecretFields(...selectors) {
  for (const selector of selectors) select(selector).value = "";
}

function clearPasswordFeedback() {
  select("#settings-password-status").hidden = true;
  select("#settings-password-status").textContent = "";
  for (const selector of [
    "#settings-current-password-error",
    "#settings-new-password-error",
    "#settings-confirm-password-error",
  ]) {
    select(selector).hidden = true;
    select(selector).textContent = "";
  }
}

function renderPasswordRule(selector, result, key, parameters = {}) {
  const state = result === null ? "neutral" : result ? "valid" : "invalid";
  const symbol = result === null ? "○" : result ? "✓" : "✕";
  const element = select(selector);
  element.dataset.state = state;
  element.textContent = `${symbol} ${t(key, parameters)}`;
}

export function updatePasswordValidation() {
  const currentPassword = select("#settings-current-password").value;
  const newPassword = select("#settings-new-password").value;
  const confirmation = select("#settings-confirm-password").value;
  const minimumLength = frontendConfig.password.minimumLength;
  const validation = passwordRequirementState({
    currentPassword,
    newPassword,
    confirmation,
    minimumLength,
  });
  renderPasswordRule(
    "#settings-password-minimum",
    validation.minimum,
    "settings.authentication.requirements.minimum",
    { length: minimumLength },
  );
  renderPasswordRule(
    "#settings-password-different",
    validation.different,
    "settings.authentication.requirements.different",
  );
  renderPasswordRule(
    "#settings-password-match",
    validation.matches,
    "settings.authentication.requirements.matches",
  );
  select("#settings-password-save").disabled = !validation.complete;
  return validation;
}

function showPasswordError(code) {
  const target = passwordErrorTarget(code);
  const message = t(
    `settings.authentication.errors.${code || "failed"}`,
    {},
    t("settings.authentication.errors.failed"),
  );
  if (target !== "#settings-password-status") {
    select(target).textContent = message;
    select(target).hidden = false;
    return;
  }
  select("#settings-password-status").textContent = message;
  select("#settings-password-status").hidden = false;
}

export async function changePassword(event) {
  event.preventDefault();
  const button = select("#settings-password-save");
  const fields = [
    "#settings-current-password",
    "#settings-new-password",
    "#settings-confirm-password",
  ];
  clearPasswordFeedback();
  if (!updatePasswordValidation().complete) return;
  setBusy(button, true, t("settings.messages.saving", {}, "Saving…"));
  try {
    const newPassword = select(fields[1]).value;
    const confirmation = select(fields[2]).value;
    if (newPassword !== confirmation) {
      showPasswordError("password_mismatch");
      return;
    }
    await api("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: select(fields[0]).value,
        new_password: newPassword,
        confirmation,
      }),
    });
    resetAuthenticatedState();
    window.dispatchEvent(new CustomEvent("exitlane:authenticationrequired"));
  } catch (error) {
    showPasswordError(error.payload?.detail || "failed");
  } finally {
    clearSecretFields(...fields);
    setBusy(button, false);
    updatePasswordValidation();
  }
}

export function initialiseSettings() {
  const form = select("#settings-general-form");
  form.addEventListener("submit", saveGeneralSettings);
  form.addEventListener("input", updateSaveState);
  form.addEventListener("change", updateSaveState);
  select("#settings-password-form").addEventListener("submit", changePassword);
  select("#settings-mfa-enable-form").addEventListener("submit", beginMfa);
  select("#settings-mfa-confirm-form").addEventListener("submit", confirmMfa);
  select("#settings-mfa-cancel").addEventListener("click", cancelMfa);
  select("#settings-mfa-manage-form").addEventListener("submit", manageMfa);
  select("#settings-mfa-copy-key").addEventListener("click", async () => {
    if (mfaState.setupKey) await navigator.clipboard.writeText(mfaState.setupKey);
    select("#settings-mfa-message").textContent = t(
      "settings.authentication.mfa.copied", {}, "Copied.",
    );
  });
  select("#settings-recovery-copy").addEventListener("click", async () => {
    if (mfaState.recoveryCodes.length) {
      await navigator.clipboard.writeText(mfaState.recoveryCodes.join("\n"));
    }
  });
  select("#settings-recovery-saved").addEventListener("change", (event) => {
    select("#settings-recovery-close").disabled = !event.currentTarget.checked;
  });
  select("#settings-recovery-close").addEventListener("click", () => {
    clearTemporaryMfaState(MFA_STATES.ENABLED);
    select("#settings-mfa-manage-password").focus();
  });
  select("#settings-recovery-codes").addEventListener("cancel", (event) => {
    event.preventDefault();
    select("#settings-recovery-saved").focus();
  });
  select("#settings-revoke-sessions").addEventListener("click", async () => {
    await api("/api/auth/sessions/revoke-others", { method: "POST" });
    await loadAuthenticationSecurity();
  });
  select("#settings-password-form").addEventListener("input", () => {
    clearPasswordFeedback();
    updatePasswordValidation();
  });
  updatePasswordValidation();
  window.addEventListener("exitlane:viewchange", (event) => {
    const dashboardActive = getSlice("application").mode === "dashboard";
    if (event.detail.view !== "settings") {
      clearTemporaryMfaState(MFA_STATES.DISABLED);
    } else if (dashboardActive) {
      loadSettings({ force: true });
    }
  });
  window.addEventListener("exitlane:languagechange", () => {
    const dashboardActive = getSlice("application").mode === "dashboard";
    if (dashboardActive && settingsLoaded) renderAbout(savedSettings.about);
    updatePasswordValidation();
  });
  window.addEventListener("exitlane:authenticationrequired", () => {
    clearTemporaryMfaState(MFA_STATES.DISABLED);
  });
  window.addEventListener("pagehide", () => {
    clearTemporaryMfaState(MFA_STATES.DISABLED);
  });
  window.addEventListener("exitlane:configchange", updatePasswordValidation);
}
