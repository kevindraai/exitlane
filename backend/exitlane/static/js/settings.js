import { api } from "./api.js";
import {
  getCurrentLanguage,
  t,
} from "./i18n.js";
import {
  getColorSchemePreference,
} from "./theme.js";
import {
  ALERT_TYPES,
  clearAlert,
  renderAlert,
  select,
  setBusy,
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
let networkMfaRequired = false;
let networkBroadTrustConfirmation = false;

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
    select("#settings-mfa-status").textContent = t(
      "settings.authentication.mfa.setting_up", {}, "Setting up",
    );
  }
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

function showMfaError(error) {
  const code = error?.payload?.detail;
  const message = code === "invalid_mfa_code"
    ? t("settings.authentication.mfa.invalid_code", {}, "Enter a valid six-digit code.")
    : t(
      "settings.authentication.errors.invalid_credentials",
      {},
      "The current password is incorrect.",
    );
  renderAlert(select("#settings-mfa-message"), message, ALERT_TYPES.ERROR);
  return message;
}

async function loadAuthenticationSecurity() {
  const [security, deployment] = await Promise.all([
    api("/api/auth/security"),
    api("/api/deployment/security"),
  ]);
  reconcileMfaState(mfaState, security.mfa);
  renderMfaState();
  if (mfaState.mode !== MFA_STATES.ENROLLMENT_PENDING) {
    select("#settings-mfa-status").textContent = security.mfa.enabled
      ? t("settings.authentication.mfa.enabled", {}, "Enabled")
      : t("settings.authentication.mfa.disabled", {}, "Disabled");
  }
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
    direct_peer: deployment.direct_peer,
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
  const configuration = deployment.configuration;
  select("#settings-network-public-url").value = configuration.public_url || "";
  select("#settings-network-proxies").value = configuration.trusted_proxies.join("\n");
  select("#settings-network-cookie-policy").value = configuration.secure_cookie_policy;
  const fields = {
    public_url: [
      "#settings-network-public-url",
      "#settings-network-public-url-override",
      "#settings-network-public-url-source",
    ],
    trusted_proxies: [
      "#settings-network-proxies",
      "#settings-network-proxies-override",
      "#settings-network-proxies-source",
    ],
    secure_cookie_policy: [
      "#settings-network-cookie-policy",
      "#settings-network-cookie-override",
      "#settings-network-cookie-source",
    ],
  };
  for (const [field, [controlSelector, helpSelector, sourceSelector]] of Object.entries(fields)) {
    const locked = Boolean(configuration.environment_overrides[field]);
    select(controlSelector).disabled = locked;
    select(helpSelector).hidden = !locked;
    const source = configuration.sources[field];
    select(sourceSelector).textContent = t(
      `settings.network.sources.${source}`,
      {},
      `Source: ${source}`,
    );
  }
  select("#settings-network-cookie-warning").hidden =
    configuration.secure_cookie_policy !== "never";
  const hasEnvironmentOverrides = Object.values(
    configuration.environment_overrides,
  ).some(Boolean);
  renderAlert(
    select("#settings-network-information"),
    hasEnvironmentOverrides
      ? t(
        "settings.network.managed_environment_information",
        {},
        "Environment-managed values are read-only. Other changes apply immediately.",
      )
      : t(
        "settings.network.configuration_help",
        {},
        "Changes are applied immediately.",
      ),
    ALERT_TYPES.INFORMATION,
  );
  renderAlert(
    select("#settings-network-confirm-description"),
    t(
      "settings.network.confirm_description",
      {},
      "This change may end access through your current browser origin or direct HTTP.",
    ),
    ALERT_TYPES.WARNING,
  );
  networkMfaRequired = Boolean(deployment.mfa_required);
  select("#settings-network-totp-field").hidden = !networkMfaRequired;
  select("#settings-network-totp").required = networkMfaRequired;
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
  select("#settings-release-channel").textContent = about.release_channel;
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
  select("#settings-session-duration-display").textContent =
    data.system.session_duration_seconds;
  select("#settings-language").value = getCurrentLanguage();
  select("#settings-color-scheme").value = getColorSchemePreference();
  renderAbout(data.about);
  clearAlert(select("#settings-general-error"));
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
  clearAlert(select("#settings-mfa-message"));
  try {
    const result = await api("/api/auth/mfa/enrollment", {
      method: "POST",
      body: JSON.stringify({ current_password: select("#settings-mfa-password").value }),
    });
    beginEnrollmentState(mfaState, result);
    removeRenderedMfaSecrets();
    renderMfaState();
    select("#settings-mfa-confirm-code").focus();
  } catch (error) {
    showMfaError(error);
    select("#settings-mfa-password").focus();
  } finally {
    select("#settings-mfa-password").value = "";
  }
}

async function confirmMfa(event) {
  event.preventDefault();
  const button = select("#settings-mfa-confirm");
  const error = select("#settings-mfa-confirm-error");
  error.hidden = true;
  clearAlert(select("#settings-mfa-message"));
  setBusy(button, true, t("settings.authentication.mfa.confirming", {}, "Confirming…"));
  try {
    const result = await api("/api/auth/mfa/enrollment/confirm", {
      method: "POST",
      body: JSON.stringify({
        enrollment: mfaState.pendingEnrollment,
        code: select("#settings-mfa-confirm-code").value,
      }),
    });
    showMessage(
      t("settings.authentication.mfa.enabled_success", {}, "MFA enabled."),
      ALERT_TYPES.SUCCESS,
    );
    showRecoveryCodes(result.recovery_codes);
    await loadAuthenticationSecurity();
  } catch (apiError) {
    error.textContent = showMfaError(apiError);
    error.hidden = false;
    select("#settings-mfa-confirm-code").focus();
  } finally {
    setBusy(button, false);
  }
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
  clearAlert(select("#settings-mfa-message"));
  try {
    if (action === "disable") {
      await api("/api/auth/mfa/disable", { method: "POST", body: JSON.stringify(payload) });
      clearTemporaryMfaState(MFA_STATES.DISABLED);
      showMessage(
        t("settings.authentication.mfa.disabled_success", {}, "MFA disabled."),
        ALERT_TYPES.SUCCESS,
      );
      window.dispatchEvent(new CustomEvent("exitlane:authenticationrequired"));
    } else {
      clearTemporaryMfaState(MFA_STATES.ENABLED);
      const result = await api("/api/auth/mfa/recovery-codes", { method: "POST", body: JSON.stringify(payload) });
      showRecoveryCodes(result.recovery_codes);
      showMessage(
        t(
          "settings.authentication.mfa.recovery_regenerated_success",
          {},
          "Recovery codes regenerated.",
        ),
        ALERT_TYPES.SUCCESS,
      );
      await loadAuthenticationSecurity();
    }
  } catch (error) {
    showMfaError(error);
  } finally {
    clearSecretFields("#settings-mfa-manage-password", "#settings-mfa-manage-code");
  }
}

function networkSecurityPayload(confirmAccessLoss = false) {
  return {
    public_url: select("#settings-network-public-url").value.trim(),
    trusted_proxies: select("#settings-network-proxies").value
      .split(/\r?\n/).map((entry) => entry.trim()).filter(Boolean),
    secure_cookie_policy: select("#settings-network-cookie-policy").value,
    current_password: select("#settings-network-password").value,
    code: networkMfaRequired ? select("#settings-network-totp").value : null,
    confirm_broad_trust: networkBroadTrustConfirmation,
    confirm_access_loss: confirmAccessLoss,
  };
}

async function submitNetworkSecurity({ confirmAccessLoss = false } = {}) {
  const button = select("#settings-network-save");
  const errorTarget = select("#settings-network-error");
  clearAlert(errorTarget);
  clearAlert(select("#settings-network-status"));
  setBusy(button, true, t("settings.network.saving", {}, "Saving…"));
  try {
    await api("/api/deployment/security", {
      method: "PUT",
      body: JSON.stringify(networkSecurityPayload(confirmAccessLoss)),
    });
    clearSecretFields("#settings-network-password", "#settings-network-totp");
    await loadAuthenticationSecurity();
    showMessage(
      t("settings.network.saved", {}, "Network configuration saved."),
      ALERT_TYPES.SUCCESS,
    );
  } catch (error) {
    const detail = error.payload?.detail;
    const code = typeof detail === "object" ? detail.code : detail;
    if (code === "access_loss_confirmation_required" ||
        code === "broad_proxy_confirmation_required") {
      networkBroadTrustConfirmation = code === "broad_proxy_confirmation_required";
      select("#settings-network-confirm").showModal();
      return;
    }
    renderAlert(
      errorTarget,
      t(
        `settings.network.errors.${code || "save_failed"}`,
        {
          line: detail?.line || "",
          value: detail?.value || "",
        },
        "The network configuration could not be saved.",
      ),
      ALERT_TYPES.ERROR,
    );
  } finally {
    setBusy(button, false);
  }
}

async function saveNetworkSecurity(event) {
  event.preventDefault();
  await submitNetworkSecurity();
}

export async function saveGeneralSettings(event) {
  event.preventDefault();
  if (!generalChanged()) return;
  const button = select("#settings-general-save");
  clearAlert(select("#settings-general-error"));
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
    showMessage(
      t("settings.messages.saved", {}, "Settings saved."),
      ALERT_TYPES.SUCCESS,
    );
  } catch (error) {
    renderSettings(savedSettings);
    renderAlert(
      select("#settings-general-error"),
      t("settings.errors.save", { message: error.message }, `Could not save: ${error.message}`),
      ALERT_TYPES.ERROR,
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
  clearAlert(select("#settings-password-status"));
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
  renderAlert(
    select("#settings-password-status"),
    message,
    ALERT_TYPES.ERROR,
  );
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
    showMessage(
      t(
        "settings.authentication.password_changed",
        {},
        "Password changed. Sign in again.",
      ),
      ALERT_TYPES.SUCCESS,
    );
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
  select("#settings-network-form").addEventListener("submit", saveNetworkSecurity);
  select("#settings-network-cookie-policy").addEventListener("change", (event) => {
    select("#settings-network-cookie-warning").hidden = event.currentTarget.value !== "never";
  });
  select("#settings-network-confirm-cancel").addEventListener("click", () => {
    select("#settings-network-confirm").close();
    networkBroadTrustConfirmation = false;
  });
  select("#settings-network-confirm-save").addEventListener("click", async () => {
    select("#settings-network-confirm").close();
    await submitNetworkSecurity({ confirmAccessLoss: true });
    networkBroadTrustConfirmation = false;
  });
  select("#settings-mfa-enable-form").addEventListener("submit", beginMfa);
  select("#settings-mfa-confirm-form").addEventListener("submit", confirmMfa);
  select("#settings-mfa-cancel").addEventListener("click", cancelMfa);
  select("#settings-mfa-manage-form").addEventListener("submit", manageMfa);
  select("#settings-mfa-copy-key").addEventListener("click", async () => {
    if (mfaState.setupKey) await navigator.clipboard.writeText(mfaState.setupKey);
    const status = select("#settings-mfa-enrollment-status");
    renderAlert(
      status,
      t("settings.authentication.mfa.copied", {}, "Copied."),
      ALERT_TYPES.SUCCESS,
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
