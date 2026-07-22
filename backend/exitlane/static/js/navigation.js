import { getSlice, updateSlice } from "./state.js";

const STORAGE_KEY = "exitlane-active-view";
const DEFAULT_VIEW = "dashboard";
const APPLICATION_MODES = new Set(["wizard", "login", "dashboard"]);
let initialised = false;

function validView(name, root) {
  return Boolean(name && root.querySelector(`[data-view-panel="${name}"]`));
}

export function normaliseApplicationState(application, root = document) {
  const mode = APPLICATION_MODES.has(application.mode) ? application.mode : "login";
  const activeView = validView(application.activeView, root)
    ? application.activeView
    : DEFAULT_VIEW;
  return { ...application, mode, activeView };
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
    const active = button.dataset.view === state.activeView;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });

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

export function showView(name, { persist = true } = {}) {
  const state = transitionApplication({ activeView: name }, { persistView: persist });
  window.dispatchEvent(new CustomEvent("exitlane:viewchange", { detail: { view: state.activeView } }));
}

export const setActiveView = showView;

export function initialiseNavigation() {
  if (initialised) {
    renderApplicationState(getSlice("application"));
    return;
  }
  initialised = true;
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.disabled = false;
    button.addEventListener("click", () => showView(button.dataset.view));
  });
  document.querySelectorAll("[data-open-view]").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.openView));
  });
  showView(localStorage.getItem(STORAGE_KEY) || getSlice("application").activeView, {
    persist: false,
  });
}
