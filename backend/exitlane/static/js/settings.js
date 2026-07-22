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
import { getSlice } from "./state.js";

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

export function initialiseSettings() {
  const form = select("#settings-general-form");
  form.addEventListener("submit", saveGeneralSettings);
  form.addEventListener("input", updateSaveState);
  form.addEventListener("change", updateSaveState);
  window.addEventListener("exitlane:viewchange", (event) => {
    const dashboardActive = getSlice("application").mode === "dashboard";
    if (dashboardActive && event.detail.view === "settings") loadSettings();
  });
  window.addEventListener("exitlane:languagechange", () => {
    const dashboardActive = getSlice("application").mode === "dashboard";
    if (dashboardActive && settingsLoaded) renderAbout(savedSettings.about);
  });
}
