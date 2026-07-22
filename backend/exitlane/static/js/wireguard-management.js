import { formatBytes } from "./dashboard-format.js";
import { api, postJson } from "./api.js";
import { select, setBusy, setStatusPill, showMessage } from "./ui.js";
import { t } from "./i18n.js";
import { getSlice, subscribe } from "./state.js";
import { refreshWireGuardState } from "./lifecycle.js";

function renderStatus(status) {
  const state = select("#management-wireguard-state");
  const message = select("#management-wireguard-message");
  const details = select("#management-wireguard-details");

  if (!status.active) {
    setStatusPill(state, t("dashboard.inactive", {}, "Inactive"), "danger");
    message.textContent = status.message || t("dashboard.wireguard_inactive", {}, "The WireGuard interface is inactive.");
    details.hidden = true;
    return;
  }
  if (!status.connected) {
    setStatusPill(state, t("dashboard.waiting", {}, "Waiting"), "neutral");
    message.textContent = t("dashboard.no_recent_handshake", {}, "No recent WireGuard handshake.");
    details.hidden = true;
    return;
  }

  const peer = status.peers?.[0] || {};
  setStatusPill(state, t("dashboard.connected", {}, "Connected"), "success");
  message.textContent = t("dashboard.wireguard_active", {}, "The router tunnel is active.");
  select("#management-wireguard-client").textContent = status.client || "router";
  select("#management-wireguard-endpoint").textContent = peer.endpoint || "—";
  select("#management-wireguard-received").textContent = formatBytes(peer.received_bytes);
  select("#management-wireguard-sent").textContent = formatBytes(peer.sent_bytes);
  details.hidden = false;
}

let currentConfiguration = "";
let configurationVisible = false;
let regenerating = false;
let configurationLoaded = false;

function configurationError(code) {
  return t(
    `wireguard_management.errors.${code || "load_failed"}`,
    {},
    t("wireguard_management.errors.load_failed", {}, "The WireGuard configuration could not be loaded."),
  );
}

export function renderConfiguration(payload) {
  const loading = select("#wireguard-config-loading");
  const empty = select("#wireguard-config-empty");
  const error = select("#wireguard-config-error");
  const content = select("#wireguard-config-content");
  const pre = select("#management-wireguard-config");
  loading.hidden = true;
  error.hidden = true;
  error.textContent = "";
  const view = configurationViewState(payload, configurationVisible);
  if (!view.available) {
    currentConfiguration = "";
    pre.textContent = "";
    pre.hidden = true;
    empty.hidden = false;
    content.hidden = true;
    return;
  }
  currentConfiguration = view.configuration;
  pre.textContent = view.displayedConfiguration;
  pre.hidden = !configurationVisible;
  empty.hidden = true;
  content.hidden = false;
  select("#wireguard-config-toggle").setAttribute("aria-expanded", String(configurationVisible));
}

export function configurationViewState(payload, visible = false) {
  const available = payload?.available === true && typeof payload.configuration === "string";
  return {
    available,
    configuration: available ? payload.configuration : "",
    displayedConfiguration: available && visible ? payload.configuration : "",
  };
}

function renderConfigurationError(errorCode) {
  currentConfiguration = "";
  select("#wireguard-config-loading").hidden = true;
  select("#wireguard-config-empty").hidden = true;
  select("#wireguard-config-content").hidden = true;
  const error = select("#wireguard-config-error");
  error.textContent = configurationError(errorCode);
  error.hidden = false;
}

export async function loadManagedConfiguration() {
  configurationLoaded = true;
  select("#wireguard-config-loading").hidden = false;
  select("#wireguard-config-empty").hidden = true;
  select("#wireguard-config-content").hidden = true;
  select("#wireguard-config-error").hidden = true;
  try {
    renderConfiguration(await api("/api/ingress/wireguard/config", { deduplicate: false }));
  } catch (error) {
    renderConfigurationError(error.payload?.error || error.code);
  }
}

export function toggleManagedConfiguration() {
  if (!currentConfiguration) return;
  configurationVisible = !configurationVisible;
  const pre = select("#management-wireguard-config");
  pre.textContent = configurationVisible ? currentConfiguration : "";
  pre.hidden = !configurationVisible;
  const button = select("#wireguard-config-toggle");
  button.setAttribute("aria-expanded", String(configurationVisible));
  button.textContent = configurationVisible
    ? t("wireguard_management.hide", {}, "Hide")
    : t("wireguard_management.show", {}, "Show");
}

export async function copyManagedConfiguration() {
  if (!currentConfiguration) return;
  try {
    await navigator.clipboard.writeText(currentConfiguration);
    showMessage(t("wireguard_management.copied", {}, "Configuration copied."), "success");
  } catch {
    showMessage(t("wireguard_management.errors.copy_failed", {}, "Copying failed. Select the configuration manually."), "error");
  }
}

function setConfigurationBusy(busy) {
  for (const selector of ["#wireguard-config-toggle", "#wireguard-config-copy", "#wireguard-config-regenerate"]) {
    select(selector).disabled = busy;
  }
  const download = select("#wireguard-config-download");
  download.setAttribute("aria-disabled", String(busy));
  download.classList.toggle("disabled", busy);
  setBusy(
    select("#wireguard-regenerate-confirm"),
    busy,
    t("wireguard_management.regenerating", {}, "Regenerating…"),
  );
}

export async function confirmRegeneration() {
  if (regenerating) return;
  regenerating = true;
  setConfigurationBusy(true);
  select("#wireguard-regenerate-dialog").close();
  try {
    const result = await postJson("/api/ingress/wireguard/config/regenerate");
    configurationVisible = true;
    renderConfiguration(result);
    showMessage(t("wireguard_management.regenerated", {}, "A new WireGuard configuration was generated."), "success");
    await refreshWireGuardState({ deduplicate: false });
  } catch (error) {
    showMessage(configurationError(error.payload?.error || error.code), "error");
  } finally {
    regenerating = false;
    setConfigurationBusy(false);
  }
}

export async function refreshManagedWireGuard() {
  const button = select("#management-wireguard-refresh");
  setBusy(button, true, t("busy.checking", {}, "Checking…"));
  try {
    await refreshWireGuardState();
  } catch (error) {
    if (error.code === "aborted") return;
    setStatusPill(select("#management-wireguard-state"), t("common.status_error", {}, "Status error"), "danger");
    select("#management-wireguard-message").textContent = error.message;
  } finally {
    setBusy(button, false);
  }
}

export function initialiseWireGuardManagement() {
  const refreshButton = document.querySelector("#management-wireguard-refresh");
  if (!refreshButton) return;
  refreshButton.addEventListener("click", refreshManagedWireGuard);
  select("#wireguard-config-toggle").addEventListener("click", toggleManagedConfiguration);
  select("#wireguard-config-copy").addEventListener("click", copyManagedConfiguration);
  select("#wireguard-config-regenerate").addEventListener("click", () => {
    if (!regenerating) select("#wireguard-regenerate-dialog").showModal();
  });
  select("#wireguard-regenerate-cancel").addEventListener("click", () => {
    select("#wireguard-regenerate-dialog").close();
  });
  select("#wireguard-regenerate-confirm").addEventListener("click", confirmRegeneration);
  select("#wireguard-regenerate-form").addEventListener("submit", (event) => event.preventDefault());
  select("#wireguard-config-download").addEventListener("click", (event) => {
    if (event.currentTarget.getAttribute("aria-disabled") === "true") event.preventDefault();
  });
  const render = (slice) => { if (slice.data) renderStatus(slice.data); };
  subscribe("wireguard", render, { immediate: true });
  subscribe("application", (application) => {
    const active = application.mode === "dashboard" && application.activeView === "wireguard";
    if (active && !configurationLoaded) loadManagedConfiguration();
    if (!active) {
      configurationLoaded = false;
      currentConfiguration = "";
      configurationVisible = false;
      const pre = document.querySelector("#management-wireguard-config");
      if (pre) pre.textContent = "";
    }
  }, { immediate: true });
  window.addEventListener("exitlane:authenticationrequired", () => {
    currentConfiguration = "";
    configurationVisible = false;
    configurationLoaded = false;
    select("#management-wireguard-config").textContent = "";
  });
  window.addEventListener("exitlane:languagechange", () => render(getSlice("wireguard")));
}
