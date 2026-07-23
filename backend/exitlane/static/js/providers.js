import { api } from "./api.js";
import { getCurrentLanguage, t } from "./i18n.js";
import { showProviderView, showView } from "./navigation.js";
import { providerManagementView } from "./provider-management.js";
import { refreshProviderState, refreshProvidersState } from "./lifecycle.js";
import { getSlice, subscribe, updateSlice } from "./state.js";
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
  const data = await refreshProvidersState();
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

const KNOWN_OVERVIEW_STATES = new Set([
  "connected",
  "disconnected",
  "connecting",
  "disconnecting",
  "signed_out",
  "unavailable",
  "error",
  "unknown",
]);

export function providerOverviewView(provider = {}) {
  const status = provider.status || {};
  const management = providerManagementView(status);
  const operationState = status.operation?.state;
  let state = ["connecting", "disconnecting"].includes(operationState)
    ? operationState
    : management.authenticationState === "signed_out"
      ? "signed_out"
      : management.authenticationState === "unavailable"
        || status.available === false
        ? "unavailable"
        : management.connectionState;
  if (
    management.errorCode
    && !["signed_out", "connecting", "disconnecting", "unavailable"].includes(state)
  ) {
    state = "error";
  }
  if (!KNOWN_OVERVIEW_STATES.has(state)) state = "unknown";
  const statusTone = state === "connected"
    ? "success"
    : ["unavailable", "error"].includes(state)
      ? "warning"
      : ["connecting", "disconnecting"].includes(state)
        ? "busy"
        : state === "signed_out"
          ? "info"
          : "neutral";
  const fields = [
    status.country ? { key: "location", value: status.country } : null,
    status.server ? { key: "server", value: status.server } : null,
    status.external_ip ? { key: "external_ip", value: status.external_ip } : null,
    status.latency_ms != null
      ? { key: "latency", value: `${status.latency_ms} ms` }
      : null,
    status.connected_since
      ? { key: "connected_since", value: status.connected_since }
      : null,
  ].filter(Boolean);
  return {
    id: provider.id || null,
    displayName: provider.display_name || "",
    description: provider.description || "",
    icon: provider.icon || "provider-generic",
    active: provider.active === true,
    authenticationState: management.authenticationState,
    connectionState: management.connectionState,
    state,
    statusTone,
    fields,
    observedAt: status.observed_at || null,
    canOpen: Boolean(provider.id) && provider.enabled !== false,
  };
}

export function providerOverviewRoute(providerId) {
  return `#vpn/provider/${encodeURIComponent(providerId)}`;
}

function overviewStatusLabel(state) {
  return t(`vpn.overview.states.${state}`, {}, state);
}

function overviewFieldLabel(key) {
  return t(`vpn.overview.fields.${key}`, {}, key);
}

function formatObservedAt(value) {
  if (!value) return t("vpn.overview.not_available", {}, "Not available");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return t("vpn.overview.not_available", {}, "Not available");
  }
  return new Intl.DateTimeFormat(getCurrentLanguage(), {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(date);
}

function createOverviewCard(provider) {
  const view = providerOverviewView(provider);
  const card = document.createElement("article");
  card.className = "provider-overview-card";
  card.dataset.providerId = view.id || "";
  card.dataset.status = view.state;

  const header = document.createElement("div");
  header.className = "provider-overview-card__header";
  const icon = document.createElement("span");
  icon.className = "provider-overview-card__icon";
  icon.dataset.icon = view.icon;
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "◇";
  const identity = document.createElement("div");
  const name = document.createElement("h2");
  name.textContent = view.displayName;
  const description = document.createElement("p");
  description.textContent = view.description;
  identity.append(name, description);
  const badge = document.createElement("span");
  badge.className = `provider-overview-status provider-overview-status--${view.statusTone}`;
  badge.dataset.status = view.state;
  badge.textContent = overviewStatusLabel(view.state);
  header.append(icon, identity, badge);

  const authentication = document.createElement("div");
  authentication.className = "provider-overview-authentication";
  const authenticationLabel = document.createElement("span");
  authenticationLabel.textContent = t("vpn.overview.authentication", {}, "Authentication");
  const authenticationValue = document.createElement("strong");
  authenticationValue.textContent = overviewStatusLabel(view.authenticationState);
  authentication.append(authenticationLabel, authenticationValue);

  const grid = document.createElement("dl");
  grid.className = "provider-overview-status-grid";
  for (const field of view.fields) {
    const item = document.createElement("div");
    const label = document.createElement("dt");
    label.textContent = overviewFieldLabel(field.key);
    const value = document.createElement("dd");
    value.textContent = field.value;
    item.append(label, value);
    grid.append(item);
  }
  grid.hidden = view.fields.length === 0;

  const footer = document.createElement("div");
  footer.className = "provider-overview-card__footer";
  const action = document.createElement("button");
  action.type = "button";
  action.className = "button button-primary";
  action.dataset.providerId = view.id || "";
  action.dataset.route = view.id ? providerOverviewRoute(view.id) : "";
  action.textContent = t("vpn.overview.open_provider", {}, "Open provider");
  action.disabled = !view.canOpen;
  action.addEventListener("click", () => showProviderView(view.id));
  footer.append(action);
  card.append(header, authentication, grid, footer);
  return card;
}

function renderOverviewSummary(items, activeProviderId) {
  const active = items.find((item) => item.id === activeProviderId) || items[0];
  const view = active ? providerOverviewView(active) : null;
  select("#vpn-overview-active-provider").textContent = view?.displayName
    || t("vpn.overview.not_available", {}, "Not available");
  select("#vpn-overview-current-status").textContent = view
    ? overviewStatusLabel(view.state)
    : t("vpn.overview.not_available", {}, "Not available");
  const location = view?.fields.find((field) => field.key === "location")?.value;
  select("#vpn-overview-location-item").hidden = !location;
  select("#vpn-overview-current-location").textContent = location || "";
  select("#vpn-overview-last-updated").textContent = formatObservedAt(view?.observedAt);
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

    overview.append(createOverviewCard(provider));
  }
  renderOverviewSummary(items, slice.data?.activeProviderId);
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
    if (!["vpn", "vpn-provider"].includes(application.activeView)) return;
    renderProviderNavigation();
    if (application.activeView === "vpn-provider") {
      renderProviderManagement(getSlice("provider").data || {});
    }
  });
  window.addEventListener("exitlane:languagechange", () => renderProviderNavigation());
}
