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
  setStatusPill,
  showInlineError,
  showMessage,
} from "./ui.js";
import { getSlice, resetAuthenticatedState, subscribe } from "./state.js";
import { frontendConfig } from "./config.js";
import {
  passwordErrorTarget,
  passwordRequirementState,
} from "./password-validation.js";
import { providerManagementView } from "./provider-management.js";
import { refreshProviderState } from "./lifecycle.js";

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

function providerStatusText(view) {
  if (view.installationState === "not_installed") {
    return t("settings.vpn.states.not_installed", {}, "The NordVPN CLI is not installed.");
  }
  if (view.authenticationState === "signed_in") {
    return t("settings.vpn.states.signed_in", {}, "The local NordVPN client is signed in.");
  }
  if (view.authenticationState === "signed_out") {
    return t("settings.vpn.states.signed_out", {}, "The local NordVPN client is signed out.");
  }
  if (view.errorCode) {
    return t(
      `settings.vpn.errors.${view.errorCode}`,
      {},
      t("settings.vpn.states.unknown", {}, "The NordVPN authentication state is unknown."),
    );
  }
  return t("settings.vpn.states.unknown", {}, "The NordVPN authentication state is unknown.");
}

let currentProviderView = providerManagementView();
let signingOut = false;

export function renderNordvpnTokenManagement(status = {}) {
  const view = providerManagementView(status);
  currentProviderView = view;
  const signedIn = view.authenticationState === "signed_in";
  const signedOut = view.authenticationState === "signed_out";
  const unavailable = !signedIn && !signedOut;
  setStatusPill(
    select("#settings-provider-authentication-state"),
    t(
      `settings.vpn.authentication.${view.authenticationState}`,
      {},
      view.authenticationState,
    ),
    signedIn ? "success" : signedOut ? "neutral" : "danger",
  );
  select("#settings-provider-status-message").textContent = providerStatusText(view);
  select("#settings-provider-signed-in").hidden = !signedIn;
  select("#settings-token-form").hidden = !(signedOut && view.canSignIn);
  select("#settings-provider-unavailable").hidden = !unavailable;
  select("#settings-provider-end-session").hidden = !view.canSignOut;
  select("#settings-provider-end-session").disabled = !view.canSignOut || signingOut;
  select("#settings-token-save").disabled = !(signedOut && view.canSignIn);
  return view;
}

function providerActionError(code) {
  return t(
    `settings.vpn.errors.${code || "provider_error"}`,
    {},
    t("settings.vpn.errors.provider_error", {}, "NordVPN could not complete the action."),
  );
}

export function openProviderSignOutDialog() {
  if (!currentProviderView.canSignOut || signingOut) return false;
  clearInlineError("#settings-provider-sign-out-error");
  select("#settings-provider-sign-out-dialog").showModal();
  select("#settings-provider-sign-out-cancel").focus();
  return true;
}

export async function endProviderSession() {
  if (signingOut) return;
  signingOut = true;
  const button = select("#settings-provider-sign-out-confirm");
  clearInlineError("#settings-provider-sign-out-error");
  clearInlineError("#settings-provider-error");
  setBusy(button, true, t("settings.vpn.signing_out", {}, "Ending session…"));
  try {
    await api("/api/providers/nordvpn/session/end", { method: "POST" });
    const status = await refreshProviderState({ deduplicate: false });
    const view = renderNordvpnTokenManagement(status);
    if (view.authenticationState !== "signed_out") {
      throw new Error("provider_state_unknown");
    }
    select("#settings-provider-sign-out-dialog").close();
    showMessage(t("settings.vpn.signed_out", {}, "NordVPN session ended."), "success");
  } catch (error) {
    try {
      const status = await refreshProviderState({ deduplicate: false });
      const view = renderNordvpnTokenManagement(status);
      if (view.authenticationState === "signed_out") {
        select("#settings-provider-sign-out-dialog").close();
        showMessage(t("settings.vpn.signed_out", {}, "NordVPN session ended."), "success");
        return;
      }
    } catch {
      // Keep the last confirmed signed-in state and the dialog open.
    }
    showInlineError(
      providerActionError(error.payload?.detail || error.message),
      "#settings-provider-sign-out-error",
    );
  } finally {
    signingOut = false;
    setBusy(button, false);
    renderNordvpnTokenManagement(getSlice("provider").data || {});
  }
}

export async function retryProviderManagementStatus() {
  const button = select("#settings-provider-retry");
  clearInlineError("#settings-provider-error");
  setBusy(button, true, t("settings.vpn.retrying", {}, "Checking…"));
  try {
    await refreshProviderState({ deduplicate: false });
  } catch (error) {
    showInlineError(providerActionError(error.code), "#settings-provider-error");
  } finally {
    setBusy(button, false);
  }
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
    await refreshProviderState({ deduplicate: false });
    showMessage(t("settings.vpn.updated", {}, "NordVPN signed in."));
  } catch (error) {
    const errorCode = error.payload?.detail || error.code || "provider_error";
    showInlineError(
      t(`settings.vpn.errors.${errorCode}`, {}, t("settings.vpn.errors.provider_error")),
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
  select("#settings-provider-end-session").addEventListener("click", openProviderSignOutDialog);
  select("#settings-provider-sign-out-cancel").addEventListener("click", () => {
    if (!signingOut) select("#settings-provider-sign-out-dialog").close();
  });
  select("#settings-provider-sign-out-confirm").addEventListener("click", endProviderSession);
  select("#settings-provider-sign-out-dialog").addEventListener("cancel", (event) => {
    if (signingOut) event.preventDefault();
  });
  select("#settings-provider-sign-out-form").addEventListener("submit", (event) => {
    event.preventDefault();
  });
  select("#settings-provider-retry").addEventListener("click", retryProviderManagementStatus);
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
    renderNordvpnTokenManagement(getSlice("provider").data || {});
  });
  window.addEventListener("exitlane:configchange", updatePasswordValidation);
}
