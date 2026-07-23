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
import { getSlice, resetAuthenticatedState, subscribe } from "./state.js";
import { frontendConfig } from "./config.js";
import {
  passwordErrorTarget,
  passwordRequirementState,
} from "./password-validation.js";

let savedGeneral = null;
let savedSettings = null;
let settingsLoaded = false;
let loadingSettings = false;

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
    settingsLoaded = true;
    return data;
  } catch (error) {
    showMessage(t("settings.errors.load", {}, error.message), "error");
  } finally {
    loadingSettings = false;
  }
  return null;
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

export function renderNordvpnTokenManagement(status = {}) {
  const signedIn = status.authenticated === true;
  select("#settings-token-status").hidden = !signedIn;
  select("#settings-token-form").hidden = signedIn;
  select("#settings-token-save").disabled = signedIn;
}

export async function updateNordvpnToken(event) {
  event.preventDefault();
  const button = select("#settings-token-save");
  const field = select("#settings-nordvpn-token");
  clearInlineError("#settings-token-error");
  setBusy(button, true, t("settings.vpn.updating", {}, "Validating…"));
  try {
    await api("/api/providers/nordvpn/token", {
      method: "POST",
      body: JSON.stringify({ token: field.value }),
    });
    showMessage(t("settings.vpn.updated", {}, "NordVPN token updated."));
  } catch (error) {
    showInlineError(
      t(`settings.vpn.errors.${error.payload?.detail || "invalid_token"}`, {}, t("settings.vpn.errors.invalid_token")),
      "#settings-token-error",
    );
  } finally {
    field.value = "";
    setBusy(button, false);
  }
}

export function initialiseSettings() {
  const form = select("#settings-general-form");
  form.addEventListener("submit", saveGeneralSettings);
  form.addEventListener("input", updateSaveState);
  form.addEventListener("change", updateSaveState);
  select("#settings-password-form").addEventListener("submit", changePassword);
  select("#settings-password-form").addEventListener("input", () => {
    clearPasswordFeedback();
    updatePasswordValidation();
  });
  select("#settings-token-form").addEventListener("submit", updateNordvpnToken);
  subscribe("provider", (slice) => renderNordvpnTokenManagement(slice.data || {}), {
    immediate: true,
  });
  updatePasswordValidation();
  window.addEventListener("exitlane:viewchange", (event) => {
    const dashboardActive = getSlice("application").mode === "dashboard";
    if (dashboardActive && event.detail.view === "settings") loadSettings();
  });
  window.addEventListener("exitlane:languagechange", () => {
    const dashboardActive = getSlice("application").mode === "dashboard";
    if (dashboardActive && settingsLoaded) renderAbout(savedSettings.about);
    updatePasswordValidation();
  });
  window.addEventListener("exitlane:configchange", updatePasswordValidation);
}
