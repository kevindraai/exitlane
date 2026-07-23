import { postJson, api } from "./api.js";
import { t } from "./i18n.js";
import { appState, getSlice, resetAuthenticatedState, subscribe, succeedRefresh } from "./state.js";
import { setApplicationMode } from "./navigation.js";
import {
  select,
  setBusy,
} from "./ui.js";
import { deactivateAuthenticatedProviderData } from "./provider.js";

let refreshApplication;
let initialised = false;

export function showLogin() {
  setApplicationMode("login");
}

export function isLogoutVisible(application, auth) {
  return application.mode === "dashboard" && Boolean(auth.data?.authenticated);
}

export function applyLogoutVisibility(button, application, auth) {
  button.hidden = !isLogoutVisible(application, auth);
}

function updateLogoutVisibility() {
  applyLogoutVisibility(
    select("#logout-button"),
    getSlice("application"),
    getSlice("auth"),
  );
}

export async function refreshSession() {
  appState.session = await api("/api/auth/session");
  succeedRefresh("auth", appState.session);
  return appState.session;
}

async function login(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const errorElement = select("#login-error");
  errorElement.hidden = true;
  setBusy(button, true, t("auth.logging_in", {}, "Signing in…"));
  try {
    await postJson("/api/auth/login", {
      username: select("#login-username").value,
      password: select("#login-password").value,
    });
    select("#login-password").value = "";
    await refreshApplication();
  } catch {
    errorElement.textContent = t(
      "auth.invalid_credentials",
      {},
      "Invalid username or password.",
    );
    errorElement.hidden = false;
  } finally {
    setBusy(button, false);
  }
}

async function logout() {
  deactivateAuthenticatedProviderData();
  await postJson("/api/auth/logout");
  appState.session = { authenticated: false, user: null };
  succeedRefresh("auth", appState.session);
  resetAuthenticatedState();
  showLogin();
}

export function initialiseAuth(refreshCallback) {
  refreshApplication = refreshCallback;
  if (initialised) return;
  initialised = true;
  subscribe("application", updateLogoutVisibility, { immediate: true });
  subscribe("auth", updateLogoutVisibility);
  select("#login-form").addEventListener("submit", login);
  select("#logout-button").addEventListener("click", logout);
  window.addEventListener("exitlane:authenticationrequired", () => {
    appState.session = { authenticated: false, user: null, setup_complete: true };
    succeedRefresh("auth", appState.session);
    resetAuthenticatedState();
    showLogin();
  });
}
