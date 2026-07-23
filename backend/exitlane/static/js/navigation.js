import { getSlice, updateSlice } from "./state.js";
import {
  renderSettingsNavigation,
  setSettingsGroupExpanded,
  validSettingsSection,
} from "./settings-navigation.js";

const STORAGE_KEY = "exitlane-active-view";
const DEFAULT_VIEW = "dashboard";
const APPLICATION_MODES = new Set(["wizard", "login", "dashboard"]);
const DEFAULT_SETTINGS_SECTION = "general";
let initialised = false;
let settingsGroupManuallyExpanded = false;

function validView(name, root) {
  return Boolean(name && root.querySelector(`[data-view-panel="${name}"]`));
}

export function normaliseApplicationState(application, root = document) {
  const mode = APPLICATION_MODES.has(application.mode) ? application.mode : "login";
  const activeView = validView(application.activeView, root)
    ? application.activeView
    : DEFAULT_VIEW;
  const providerId = typeof application.providerId === "string" ? application.providerId : null;
  const settingsSection = validSettingsSection(application.settingsSection)
    ? application.settingsSection
    : DEFAULT_SETTINGS_SECTION;
  return { ...application, mode, activeView, providerId, settingsSection };
}

export function renderApplicationState(application, root = document, auth = getSlice("auth")) {
  const state = normaliseApplicationState(application, root);
  const dashboardMode = state.mode === "dashboard";
  const shell = root.querySelector(".app-shell");

  shell.dataset.applicationMode = state.mode;
  shell.classList.toggle("has-sidebar", dashboardMode);
  root.querySelector("#wizard-panel").hidden = state.mode !== "wizard";
  root.querySelector("#login-panel").hidden = state.mode !== "login";
  root.querySelector("#dashboard-panel").hidden = !dashboardMode;
  root.querySelector("#sidebar").hidden = !dashboardMode;
  const logout = root.querySelector("#logout-button");
  if (logout) logout.hidden = !(dashboardMode && auth.data?.authenticated);

  root.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.hidden = !dashboardMode || panel.dataset.viewPanel !== state.activeView;
  });
  root.querySelectorAll("[data-view]").forEach((button) => {
    const active = button.dataset.view === state.activeView
      && (!button.dataset.settingsSection
        || button.dataset.settingsSection === state.settingsSection)
      && (!button.dataset.providerId || button.dataset.providerId === state.providerId);
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  root.querySelectorAll("[data-settings-page]").forEach((page) => {
    page.hidden = !dashboardMode
      || state.activeView !== "settings"
      || page.dataset.settingsPage !== state.settingsSection;
  });
  const settingsToggle = root.querySelector("#settings-navigation-toggle");
  if (settingsToggle) {
    const settingsActive = state.activeView === "settings";
    settingsToggle.classList.toggle("active", settingsActive);
    setSettingsGroupExpanded(settingsActive || settingsGroupManuallyExpanded);
  }

  return state;
}

function transitionApplication(patch, { persistView = false } = {}) {
  const next = renderApplicationState({ ...getSlice("application"), ...patch });
  updateSlice("application", next);
  if (persistView) localStorage.setItem(STORAGE_KEY, next.activeView);
  return next;
}

export function setApplicationMode(mode) {
  if (!APPLICATION_MODES.has(mode)) throw new Error(`Unknown application mode: ${mode}`);
  const state = transitionApplication({ mode });
  window.dispatchEvent(new CustomEvent("exitlane:modechange", { detail: { mode: state.mode } }));
}

export function showView(
  name,
  { persist = true, section = null, historyMode = "push" } = {},
) {
  const settingsSection = name === "settings"
    ? (validSettingsSection(section) ? section : DEFAULT_SETTINGS_SECTION)
    : getSlice("application").settingsSection;
  const state = transitionApplication(
    { activeView: name, settingsSection },
    { persistView: persist },
  );
  window.dispatchEvent(new CustomEvent("exitlane:viewchange", {
    detail: { view: state.activeView, settingsSection: state.settingsSection },
  }));
  const route = state.activeView === "settings"
    ? `#settings/${state.settingsSection}`
    : `#${state.activeView}${section ? `/${section}` : ""}`;
  if (window.location.hash !== route && historyMode !== "none") {
    window.history[historyMode === "replace" ? "replaceState" : "pushState"](null, "", route);
  }
  return state;
}

export const setActiveView = showView;

export function navigationTarget(button) {
  return {
    view: button.dataset.view,
    section: button.dataset.settingsSection || null,
  };
}

export function showProviderView(providerId, options = {}) {
  const state = transitionApplication(
    { activeView: "vpn-provider", providerId },
    { persistView: options.persist !== false },
  );
  window.dispatchEvent(new CustomEvent("exitlane:viewchange", {
    detail: { view: state.activeView, providerId },
  }));
  const route = `#vpn/provider/${encodeURIComponent(providerId)}`;
  if (window.location.hash !== route && options.historyMode !== "none") {
    window.history[options.historyMode === "replace" ? "replaceState" : "pushState"](
      null, "", route,
    );
  }
  return state;
}

function applyRoute({ historyMode = "none", persist = false } = {}) {
  const parts = window.location.hash.replace(/^#/, "").split("/");
  if (parts[0] === "vpn" && parts[1] === "provider" && parts[2]) {
    return showProviderView(decodeURIComponent(parts[2]), { historyMode, persist });
  }
  if (parts[0] === "security") {
    return showView("settings", {
      section: "security",
      historyMode: "replace",
      persist,
    });
  }
  if (parts[0] === "settings") {
    return showView("settings", {
      section: validSettingsSection(parts[1]) ? parts[1] : DEFAULT_SETTINGS_SECTION,
      historyMode: parts[1] && validSettingsSection(parts[1]) ? historyMode : "replace",
      persist,
    });
  }
  const view = validView(parts[0], document)
    ? parts[0]
    : localStorage.getItem(STORAGE_KEY) || getSlice("application").activeView;
  return showView(view, { persist, historyMode });
}

export function initialiseNavigation() {
  if (initialised) {
    renderApplicationState(getSlice("application"));
    return;
  }
  initialised = true;
  renderSettingsNavigation(document.querySelector("#settings-navigation-items"));
  const settingsToggle = document.querySelector("#settings-navigation-toggle");
  settingsToggle.addEventListener("click", () => {
    settingsGroupManuallyExpanded = settingsToggle.getAttribute("aria-expanded") !== "true";
    setSettingsGroupExpanded(settingsGroupManuallyExpanded);
  });
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.disabled = false;
    button.addEventListener("click", () => {
      const target = navigationTarget(button);
      showView(target.view, { section: target.section });
    });
  });
  document.querySelectorAll("[data-open-view]").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.openView, {
      section: button.dataset.openSection || null,
    }));
  });
  window.addEventListener("popstate", () => applyRoute());
  applyRoute({ historyMode: "replace" });
}
