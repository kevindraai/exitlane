import { postJson, api } from "./api.js";
import { t } from "./i18n.js";
import { appState, getSlice, resetAuthenticatedState, subscribe, succeedRefresh } from "./state.js";
import { resetSessionNavigation, setApplicationMode } from "./navigation.js";
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

export function loginErrorTranslationKey(error) {
  const detail = error?.payload?.detail;
  if (detail === "invalid_credentials") return "auth.invalid_credentials";
  if (["invalid_origin", "csrf_failed", "deployment_origin_mismatch"].includes(detail)) {
    return "auth.deployment_security";
  }
  if (detail === "too_many_attempts" || error?.status === 429) return "auth.rate_limited";
  if (error?.status === 422) return "auth.invalid_request";
  if (!error?.status || error.status >= 500) return "auth.service_unavailable";
  return "auth.sign_in_failed";
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
    const result = await postJson("/api/auth/login", {
      username: select("#login-username").value,
      password: select("#login-password").value,
    });
    select("#login-password").value = "";
    if (result.mfa_required) {
      select("#login-form").hidden = true;
      select("#mfa-login-form").hidden = false;
      select("#mfa-login-code").focus();
      return;
    }
    resetSessionNavigation();
    await refreshApplication();
  } catch (error) {
    const translationKey = loginErrorTranslationKey(error);
    errorElement.textContent = t(translationKey, {}, "Sign-in could not be completed.");
    errorElement.hidden = false;
  } finally {
    setBusy(button, false);
  }
}

async function verifyMfa(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const errorElement = select("#mfa-login-error");
  errorElement.hidden = true;
  setBusy(button, true, t("auth.mfa.verifying", {}, "Verifying…"));
  try {
    await postJson("/api/auth/mfa", {
      code: select("#mfa-login-code").value,
      mode: select("#mfa-login-mode").value,
    });
    select("#mfa-login-code").value = "";
    resetSessionNavigation();
    await refreshApplication();
  } catch (error) {
    errorElement.textContent = t(`auth.mfa.errors.${error.payload?.detail || "invalid"}`, {}, "The code is invalid or expired.");
    errorElement.hidden = false;
  } finally {
    setBusy(button, false);
  }
}

async function backToPasswordLogin() {
  try {
    await api("/api/auth/mfa", { method: "DELETE" });
  } catch {
    // The server-side challenge is short-lived and cannot authorize application APIs.
  }
  select("#mfa-login-code").value = "";
  select("#mfa-login-form").hidden = true;
  select("#login-form").hidden = false;
  select("#login-username").focus();
}

async function logout() {
  deactivateAuthenticatedProviderData();
  appState.session = { authenticated: false, user: null };
  succeedRefresh("auth", appState.session);
  resetAuthenticatedState();
  resetSessionNavigation();
  showLogin();
  await postJson("/api/auth/logout");
}

export function initialiseAuth(refreshCallback) {
  refreshApplication = refreshCallback;
  if (initialised) return;
  initialised = true;
  subscribe("application", updateLogoutVisibility, { immediate: true });
  subscribe("auth", updateLogoutVisibility);
  select("#login-form").addEventListener("submit", login);
  select("#mfa-login-form").addEventListener("submit", verifyMfa);
  select("#mfa-login-back").addEventListener("click", backToPasswordLogin);
  select("#logout-button").addEventListener("click", logout);
  window.addEventListener("exitlane:authenticationrequired", () => {
    appState.session = { authenticated: false, user: null, setup_complete: true };
    succeedRefresh("auth", appState.session);
    resetAuthenticatedState();
    resetSessionNavigation();
    showLogin();
  });
}
