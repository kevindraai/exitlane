import { api } from "./api.js";
import { t } from "./i18n.js";
import { showProviderView, showView } from "./navigation.js";
import { providerManagementView } from "./provider-management.js";
import { refreshProviderState } from "./lifecycle.js";
import { getSlice, subscribe, succeedRefresh, updateSlice } from "./state.js";
import {
  clearInlineError,
  select,
  setBusy,
  setStatusPill,
  showInlineError,
  showMessage,
} from "./ui.js";

let initialised = false;
let signingOut = false;

export function activeProviderId() {
  return getSlice("application").providerId
    || getSlice("providers").data?.activeProviderId
    || null;
}

export async function loadProviders() {
  const response = await api("/api/vpn/providers");
  const data = {
    activeProviderId: response.active_provider_id,
    items: response.providers || [],
  };
  succeedRefresh("providers", data);
  const requested = getSlice("application").providerId;
  if (requested && !data.items.some((item) => item.id === requested)) {
    updateSlice("providers", { error: "provider_not_found" });
    showView("vpn", { historyMode: "replace" });
  } else if (!requested && data.activeProviderId) {
    updateSlice("application", { providerId: data.activeProviderId });
  }
  return data;
}

function providerMetadata() {
  const id = activeProviderId();
  return getSlice("providers").data?.items?.find((item) => item.id === id) || null;
}

function providerStatusText(view, name) {
  if (view.installationState === "not_installed") {
    return t("settings.vpn.states.not_installed", { provider: name }, `${name} is not installed.`);
  }
  if (view.authenticationState === "signed_in") {
    return t("settings.vpn.states.signed_in", { provider: name }, `${name} is signed in.`);
  }
  if (view.authenticationState === "signed_out") {
    return t("settings.vpn.states.signed_out", { provider: name }, `${name} is signed out.`);
  }
  return t("settings.vpn.states.unknown", { provider: name }, `${name} authentication is unknown.`);
}

export function renderProviderManagement(status = {}) {
  const metadata = providerMetadata();
  if (!metadata) return;
  const name = metadata.display_name;
  select("#vpn-provider-title").textContent = name;
  select("#vpn-provider-description").textContent = metadata.description || "";
  const view = providerManagementView(status);
  const signedIn = view.authenticationState === "signed_in";
  const signedOut = view.authenticationState === "signed_out";
  setStatusPill(
    select("#provider-authentication-state"),
    t(`settings.vpn.authentication.${view.authenticationState}`, {}, view.authenticationState),
    signedIn ? "success" : signedOut ? "neutral" : "danger",
  );
  select("#provider-status-message").textContent = providerStatusText(view, name);
  select("#provider-signed-in").hidden = !signedIn;
  select("#provider-token-form").hidden = !(signedOut && view.canSignIn);
  select("#provider-unavailable").hidden = signedIn || signedOut;
  select("#provider-end-session").hidden = !view.canSignOut;
  select("#provider-end-session").disabled = !view.canSignOut || signingOut;
}

function renderProviderNavigation(slice = getSlice("providers")) {
  const items = slice.data?.items || [];
  const navigation = select("#vpn-provider-navigation");
  const overview = select("#vpn-overview-providers");
  const application = getSlice("application");
  const providerViewActive = application.activeView === "vpn-provider";
  const toggle = select("#vpn-navigation-toggle");
  const expanded = providerViewActive || application.activeView === "vpn";
  toggle.setAttribute("aria-expanded", String(expanded));
  select("#vpn-navigation-items").hidden = !expanded;
  navigation.replaceChildren();
  overview.replaceChildren();
  for (const provider of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sidebar-item sidebar-subitem";
    button.dataset.view = "vpn-provider";
    button.dataset.providerId = provider.id;
    button.textContent = provider.display_name;
    const active = providerViewActive && application.providerId === provider.id;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    button.addEventListener("click", () => showProviderView(provider.id));
    navigation.append(button);

    const card = document.createElement("button");
    card.type = "button";
    card.className = "card provider-overview-card";
    card.dataset.providerId = provider.id;
    const name = document.createElement("strong");
    name.textContent = provider.display_name;
    const description = document.createElement("span");
    description.textContent = provider.description || "";
    card.append(name, description);
    card.addEventListener("click", () => showProviderView(provider.id));
    overview.append(card);
  }
  select("#vpn-overview-error").hidden = !slice.error;
}

async function authenticateProvider(event) {
  event.preventDefault();
  const providerId = activeProviderId();
  const field = select("#provider-token");
  const button = select("#provider-token-save");
  clearInlineError("#provider-token-error");
  setBusy(button, true, t("settings.vpn.updating", {}, "Validating…"));
  try {
    await api(`/api/vpn/providers/${encodeURIComponent(providerId)}/authenticate`, {
      method: "POST",
      body: JSON.stringify({ token: field.value }),
    });
    await Promise.all([loadProviders(), refreshProviderState({ deduplicate: false })]);
    showMessage(t("settings.vpn.updated", {}, "Provider signed in."), "success");
  } catch (error) {
    const code = error.payload?.detail || error.code || "provider_error";
    showInlineError(t(`settings.vpn.errors.${code}`, {}, code), "#provider-token-error");
  } finally {
    field.value = "";
    setBusy(button, false);
  }
}

async function signOutProvider() {
  if (signingOut) return;
  signingOut = true;
  const id = activeProviderId();
  const button = select("#provider-sign-out-confirm");
  setBusy(button, true, t("settings.vpn.signing_out", {}, "Ending session…"));
  clearInlineError("#provider-sign-out-error");
  try {
    await api(`/api/vpn/providers/${encodeURIComponent(id)}/sign-out`, { method: "POST" });
    await refreshProviderState({ deduplicate: false });
    select("#provider-sign-out-dialog").close();
    showMessage(t("settings.vpn.signed_out", {}, "Provider session ended."), "success");
  } catch (error) {
    const code = error.payload?.detail || error.code || "provider_error";
    showInlineError(t(`settings.vpn.errors.${code}`, {}, code), "#provider-sign-out-error");
  } finally {
    signingOut = false;
    setBusy(button, false);
    renderProviderManagement(getSlice("provider").data || {});
  }
}

export function initialiseProviders() {
  if (initialised) return;
  initialised = true;
  const toggle = select("#vpn-navigation-toggle");
  toggle.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") !== "true";
    toggle.setAttribute("aria-expanded", String(expanded));
    select("#vpn-navigation-items").hidden = !expanded;
  });
  select("#provider-token-form").addEventListener("submit", authenticateProvider);
  select("#provider-end-session").addEventListener("click", () => {
    select("#provider-sign-out-dialog").showModal();
  });
  select("#provider-sign-out-cancel").addEventListener("click", () => {
    if (!signingOut) select("#provider-sign-out-dialog").close();
  });
  select("#provider-sign-out-confirm").addEventListener("click", signOutProvider);
  select("#provider-sign-out-form").addEventListener("submit", (event) => event.preventDefault());
  select("#provider-management-retry").addEventListener("click", () => {
    refreshProviderState({ deduplicate: false }).catch(() => {});
  });
  subscribe("providers", renderProviderNavigation, { immediate: true });
  subscribe("provider", (slice) => renderProviderManagement(slice.data || {}), { immediate: true });
  subscribe("application", (application) => {
    if (application.activeView !== "vpn-provider") return;
    renderProviderNavigation();
    renderProviderManagement(getSlice("provider").data || {});
  });
}
