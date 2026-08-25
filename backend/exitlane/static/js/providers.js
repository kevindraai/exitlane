import { api } from "./api.js";
import { localisedCountryName } from "./country-format.js";
import { createIcon, renderIcon, resolveIconName, statusIconName } from "./icons.js";
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
  setTechnicalValue,
  showInlineError,
  showMessage,
} from "./ui.js";

let initialised = false;
let signingOut = false;
let providerInstallationActive = false;
let providerInstallationPollTimer = null;
let providerInstallationStatusLoadedFor = null;
let killswitchStatus = null;
let killswitchDialogTrigger = null;
const KNOWN_KILLSWITCH_STATES = new Set([
  "disabled",
  "enabled_protected",
  "enabled_waiting_for_tunnel",
  "enabled_degraded",
]);
const PROVIDER_INSTALLATION_POLL_INTERVAL_MS = 1500;

function yesNo(value) {
  return t(value ? "common.yes" : "common.no", {}, value ? "Yes" : "No");
}

function renderKillswitchStatus(status) {
  const state = status?.state || "unknown";
  const known = KNOWN_KILLSWITCH_STATES.has(state);
  const configured = known ? Boolean(status.configured) : null;
  if (status) {
    select("#killswitch-state").textContent = t(`killswitch.states.${state}`, {}, state);
    select("#killswitch-configured").textContent = known ? yesNo(status.configured) : "—";
    select("#killswitch-effective").textContent = known ? yesNo(status.effective) : "—";
    select("#killswitch-tunnel").textContent = known ? yesNo(status.tunnel_available) : "—";
    select("#killswitch-sources").textContent = (status.protected_sources || []).join(", ") || "—";
    select("#killswitch-transition").textContent = formatObservedAt(status.last_transition);
    select("#killswitch-change").textContent = status.configured
      ? t("killswitch.disable", {}, "Disable")
      : t("killswitch.enable", {}, "Enable");
    const tone = state === "enabled_protected" ? "success"
      : ["enabled_waiting_for_tunnel", "enabled_degraded", "error"].includes(state)
        ? "warning" : "neutral";
    select("#killswitch-badge").className = `provider-overview-status provider-overview-status--${tone}`;
    renderIcon(select("#killswitch-icon"), state === "enabled_protected" ? "shield-check" : state === "disabled" ? "shield" : "shield-alert");
    renderIcon(select("#killswitch-badge-icon"), state === "enabled_protected" ? "circle-check" : state === "disabled" ? "circle-minus" : "triangle-alert");
    clearInlineError("#killswitch-error");
  }
  const dashboardTone = state === "enabled_protected" ? "success" : "neutral";
  const dashboardState = configured === true
    ? t("dashboard.killswitch_active", {}, "Active")
    : configured === false
      ? t("dashboard.killswitch_disabled", {}, "Disabled")
      : t("dashboard.killswitch_unknown", {}, "Status unknown");
  setStatusPill(select("#dashboard-killswitch-pill"), dashboardState, dashboardTone);
  renderIcon(
    select("#dashboard-killswitch-icon"),
    state === "enabled_protected"
      ? "shield-check"
      : configured === false ? "shield" : "shield-alert",
  );
  select("#dashboard-killswitch-description").textContent = configured === true
    ? t(
      "dashboard.killswitch_active_description",
      {},
      "Traffic is blocked when the VPN connection is lost.",
    )
    : configured === false
      ? t(
        "dashboard.killswitch_disabled_description",
        {},
        "Traffic can continue without an active VPN connection.",
      )
      : t("dashboard.killswitch_unknown", {}, "Status unknown");
}

async function loadKillswitch() {
  try {
    killswitchStatus = await api("/api/vpn/killswitch");
    renderKillswitchStatus(killswitchStatus);
  } catch (error) {
    renderKillswitchStatus(null);
    showInlineError(t("killswitch.errors.status", {}, "Killswitch status is unavailable."), "#killswitch-error");
  }
}

function closeKillswitchDialog() {
  select("#killswitch-dialog").close();
  killswitchDialogTrigger?.focus();
  killswitchDialogTrigger = null;
}

function openKillswitchDialog() {
  const disabling = Boolean(killswitchStatus?.configured);
  const dialog = select("#killswitch-dialog");
  killswitchDialogTrigger = document.activeElement;
  select("#killswitch-dialog-title").textContent = disabling
    ? t("killswitch.disable_title", {}, "Disable killswitch?")
    : t("killswitch.enable_title", {}, "Enable killswitch?");
  select("#killswitch-dialog-description").textContent = disabling
    ? t(
      "killswitch.disable_impact",
      {},
      "Internet traffic can then continue without an active VPN connection.",
    )
    : t(
      "killswitch.enable_impact",
      {},
      "If the VPN connection is lost, internet traffic is blocked. Local management remains available.",
    );
  const confirm = select("#killswitch-confirm");
  confirm.textContent = disabling
    ? t("killswitch.disable", {}, "Disable")
    : t("killswitch.enable", {}, "Enable");
  confirm.className = `button ${disabling ? "button-warning" : "button-primary"}`;
  clearInlineError("#killswitch-dialog-error");
  dialog.showModal();
  window.requestAnimationFrame(() => select("#killswitch-cancel").focus());
}

async function changeKillswitch(event) {
  event.preventDefault();
  const action = killswitchStatus?.configured ? "disable" : "enable";
  const button = select("#killswitch-confirm");
  setBusy(button, true, t("killswitch.changing", {}, "Applying…"));
  clearInlineError("#killswitch-dialog-error");
  try {
    killswitchStatus = await api(`/api/vpn/killswitch/${action}`, {
      method: "POST",
    });
    renderKillswitchStatus(killswitchStatus);
    closeKillswitchDialog();
    await loadKillswitch();
    showMessage(t(`killswitch.${action}d`, {}, `Killswitch ${action}d.`), "success");
  } catch (error) {
    const code = error.payload?.detail || error.code || "firewall_apply_failed";
    showInlineError(t(`killswitch.errors.${code}`, {}, code), "#killswitch-dialog-error");
  } finally {
    setBusy(button, false);
  }
}

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
  let connectionDisplayState = ["connecting", "disconnecting"].includes(operationState)
    ? operationState
    : management.connectionState;
  if (!KNOWN_OVERVIEW_STATES.has(connectionDisplayState)) connectionDisplayState = "unknown";
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
  const statusTone = connectionDisplayState === "connected"
    ? "success"
    : ["unavailable", "error"].includes(connectionDisplayState)
      ? "warning"
      : ["connecting", "disconnecting"].includes(connectionDisplayState)
        ? "busy"
        : "neutral";
  const fields = [
    status.country || status.country_code
      ? {
          key: "location",
          value: localisedCountryName(status.country_code, status.country),
        }
      : null,
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
    icon: resolveIconName(provider.icon),
    active: provider.active === true,
    authenticationState: management.authenticationState,
    connectionState: management.connectionState,
    connectionDisplayState,
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

export function providerOverviewActionLabel(displayName) {
  return displayName
    ? t("vpn.overview.open_named_provider", { provider: displayName }, `Open ${displayName}`)
    : t("vpn.overview.open_provider", {}, "Open provider");
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
  icon.setAttribute("aria-hidden", "true");
  icon.append(createIcon(view.icon));
  const identity = document.createElement("div");
  const name = document.createElement("h2");
  name.textContent = view.displayName;
  const description = document.createElement("p");
  description.textContent = view.description;
  identity.append(name, description);
  const badge = document.createElement("span");
  badge.className = `provider-overview-status provider-overview-status--${view.statusTone}`;
  badge.dataset.status = view.connectionDisplayState;
  const badgeIcon = createIcon(
    statusIconName(view.connectionDisplayState),
    { className: ["connecting", "disconnecting"].includes(view.connectionDisplayState) ? "lucide-icon--spin" : "" },
  );
  const badgeText = document.createElement("span");
  badgeText.textContent = overviewStatusLabel(view.connectionDisplayState);
  badge.append(badgeIcon, badgeText);
  header.append(icon, identity, badge);

  const authentication = document.createElement("div");
  authentication.className = "provider-overview-authentication";
  const authenticationLabel = document.createElement("span");
  authenticationLabel.append(
    createIcon("user-round-check"),
    document.createTextNode(t("vpn.overview.authentication", {}, "Authentication")),
  );
  const authenticationValue = document.createElement("strong");
  authenticationValue.append(
    createIcon(statusIconName(view.authenticationState)),
    document.createTextNode(overviewStatusLabel(view.authenticationState)),
  );
  authentication.append(authenticationLabel, authenticationValue);

  const grid = document.createElement("dl");
  grid.className = "provider-overview-status-grid";
  for (const field of view.fields) {
    const item = document.createElement("div");
    const label = document.createElement("dt");
    const fieldIcons = {
      location: "map-pinned",
      server: "server",
      external_ip: "globe",
      latency: "gauge",
      connected_since: "history",
    };
    label.append(
      createIcon(fieldIcons[field.key] || "info"),
      document.createTextNode(overviewFieldLabel(field.key)),
    );
    const value = document.createElement("dd");
    if (["server", "external_ip"].includes(field.key)) {
      setTechnicalValue(value, field.value);
    } else {
      value.textContent = field.value;
    }
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
  action.textContent = providerOverviewActionLabel(view.displayName);
  action.setAttribute(
    "aria-label",
    view.displayName
      ? t("vpn.overview.open_named_provider_aria", { provider: view.displayName }, `Open ${view.displayName}`)
      : t("vpn.overview.open_provider_aria", {}, "Open provider"),
  );
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
    ? overviewStatusLabel(view.connectionDisplayState)
    : t("vpn.overview.not_available", {}, "Not available");
  select("#vpn-overview-authentication-state").textContent = view
    ? overviewStatusLabel(view.authenticationState)
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
    return t(
      "provider.management.authentication_ready",
      { provider: name },
      `${name} authentication is ready.`,
    );
  }
  if (view.authenticationState === "signed_out") {
    return t(
      "provider.management.authentication_required",
      { provider: name },
      `Sign in to ${name} below to manage the VPN connection.`,
    );
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
  const installation = select("#provider-management-installation");
  const installButton = select("#provider-management-install");
  const installable = view.canInstall || providerInstallationActive;
  installation.hidden = !installable;
  select("#provider-management-retry").hidden = installable;
  select("#provider-management-install-description").textContent = t(
    "provider.management.install_description",
    { provider: name },
    `${name} is not installed. ExitLane can install the official client for you.`,
  );
  installButton.textContent = t(
    "provider.management.install",
    { provider: name },
    `Install ${name}`,
  );
  installButton.disabled = !view.canInstall || providerInstallationActive;
  select("#provider-end-session").hidden = !view.canSignOut;
  select("#provider-end-session").disabled = !view.canSignOut || signingOut;
  if (view.installationState === "installing") {
    void restoreManagementProviderInstallation();
  }
}

function managementInstallationError(error) {
  const code = error.payload?.detail || error.code || "installation_failed";
  return t(
    `provider.installation.errors.${code}`,
    {},
    t("provider.installation.errors.installation_failed", {}, "The provider installation failed."),
  );
}

function renderManagementInstallationProgress(status) {
  const progress = select("#provider-management-install-status");
  const inProgress = status.installation_in_progress === true;
  progress.hidden = false;
  progress.textContent = inProgress
    ? t(
      `provider.installation.phase.${status.phase}`,
      {},
      t("provider.installation.status.installing", {}, "Installing"),
    )
    : status.phase === "completed" || status.state === "available"
      ? t("provider.installation.success", {}, "The VPN provider is installed and available.")
      : managementInstallationError({ payload: { detail: status.error_code } });
}

async function pollManagementProviderInstallation(providerId) {
  window.clearTimeout(providerInstallationPollTimer);
  try {
    const status = await api(
      `/api/vpn/providers/${encodeURIComponent(providerId)}/installation`,
      { deduplicate: false },
    );
    renderManagementInstallationProgress(status);
    if (status.installation_in_progress) {
      providerInstallationActive = true;
      setBusy(
        select("#provider-management-install"),
        true,
        t("busy.installing", {}, "Installing…"),
      );
      providerInstallationPollTimer = window.setTimeout(
        () => pollManagementProviderInstallation(providerId),
        PROVIDER_INSTALLATION_POLL_INTERVAL_MS,
      );
      return;
    }

    providerInstallationActive = false;
    setBusy(select("#provider-management-install"), false);
    if (status.phase === "completed" || status.state === "available") {
      showMessage(t("provider.installation.success", {}, "The VPN provider is installed and available."), "success");
      await Promise.all([loadProviders(), refreshProviderState({ deduplicate: false })]);
      return;
    }

    const button = select("#provider-management-install");
    button.disabled = false;
    button.textContent = t("provider.installation.retry", {}, "Try again");
    showInlineError(managementInstallationError({ payload: { detail: status.error_code } }), "#provider-management-error");
  } catch (error) {
    providerInstallationPollTimer = window.setTimeout(
      () => pollManagementProviderInstallation(providerId),
      PROVIDER_INSTALLATION_POLL_INTERVAL_MS,
    );
  }
}

async function restoreManagementProviderInstallation() {
  const providerId = activeProviderId();
  if (!providerId || providerInstallationStatusLoadedFor === providerId) return;
  providerInstallationStatusLoadedFor = providerId;
  try {
    const status = await api(
      `/api/vpn/providers/${encodeURIComponent(providerId)}/installation`,
      { deduplicate: false },
    );
    if (status.installation_in_progress) {
      providerInstallationActive = true;
      renderManagementInstallationProgress(status);
      await pollManagementProviderInstallation(providerId);
    }
  } catch {
    providerInstallationStatusLoadedFor = null;
  }
}

async function installProviderFromManagement() {
  if (providerInstallationActive) return;
  const providerId = activeProviderId();
  const metadata = providerMetadata();
  if (!providerId || !metadata) return;
  if (!window.confirm(t(
    "provider.installation.confirm",
    {},
    "Install this VPN provider on this Debian 13 system?",
  ))) return;

  const button = select("#provider-management-install");
  clearInlineError("#provider-management-error");
  providerInstallationActive = true;
  setBusy(button, true, t("busy.installing", {}, "Installing…"));
  select("#provider-management-install-status").hidden = false;
  select("#provider-management-install-status").textContent = t(
    "provider.installation.phase.starting",
    {},
    "Starting the protected installer…",
  );
  try {
    await api(`/api/vpn/providers/${encodeURIComponent(providerId)}/installation`, {
      method: "POST",
    });
    await pollManagementProviderInstallation(providerId);
  } catch (error) {
    if (error.payload?.detail === "installation_in_progress") {
      await pollManagementProviderInstallation(providerId);
      return;
    }
    providerInstallationActive = false;
    setBusy(button, false);
    showInlineError(managementInstallationError(error), "#provider-management-error");
  }
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
  renderIcon(
    select("#vpn-navigation-toggle .sidebar-group-chevron"),
    expanded ? "chevron-down" : "chevron-right",
  );
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
    renderIcon(
      select("#vpn-navigation-toggle .sidebar-group-chevron"),
      expanded ? "chevron-down" : "chevron-right",
    );
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
  select("#provider-management-install").addEventListener(
    "click",
    installProviderFromManagement,
  );
  select("#killswitch-change").addEventListener("click", openKillswitchDialog);
  select("#killswitch-cancel").addEventListener("click", closeKillswitchDialog);
  select("#killswitch-dialog").addEventListener("cancel", (event) => {
    event.preventDefault();
    closeKillswitchDialog();
  });
  select("#killswitch-dialog").addEventListener("keydown", (event) => {
    if (event.key !== "Tab") return;
    const focusable = [...select("#killswitch-dialog").querySelectorAll("button:not(:disabled)")];
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  select("#killswitch-form").addEventListener("submit", changeKillswitch);
  select("#killswitch-refresh").addEventListener("click", loadKillswitch);
  loadKillswitch();
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
