import { postJson, api } from "./api.js";
import { t } from "./i18n.js";
import { appState } from "./state.js";
import {
  select,
  setBusy,
} from "./ui.js";

let refreshApplication;

export function showLogin() {
  select("#login-panel").hidden = false;
  select("#wizard-panel").hidden = true;
  select("#dashboard-panel").hidden = true;
  select("#sidebar").hidden = true;
  select("#logout-button").hidden = true;
}

function hideLogin() {
  select("#login-panel").hidden = true;
  select("#logout-button").hidden = !appState.session?.authenticated;
}

export async function refreshSession() {
  appState.session = await api("/api/auth/session");
  if (appState.session.authenticated) {
    hideLogin();
  }
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
    hideLogin();
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
  await postJson("/api/auth/logout");
  appState.session = { authenticated: false, user: null };
  showLogin();
}

export function initialiseAuth(refreshCallback) {
  refreshApplication = refreshCallback;
  select("#login-form").addEventListener("submit", login);
  select("#logout-button").addEventListener("click", logout);
  window.addEventListener("exitlane:authenticationrequired", showLogin);
}
