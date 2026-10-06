import { formatBytes } from "./dashboard-format.js";
import { api, postJson } from "./api.js";
import { select, setBusy, setStatusPill, setTechnicalValue, showMessage } from "./ui.js";
import { getCurrentLanguage, t } from "./i18n.js";
import { beginRefresh, failRefresh, getSlice, subscribe, succeedRefresh } from "./state.js";

const PEERS_PATH = "/api/ingress/wireguard/peers";
let initialised = false;
let managementActive = false;
let sessionGeneration = 0;
let listRequest = 0;
let configRequest = 0;
let selectedPeer = null;
let editingPeer = null;
let pendingMutation = null;
let mutating = false;
let currentConfiguration = "";
let configurationVisible = false;

export function peerPath(peerId, suffix = "") {
  return `${PEERS_PATH}/${encodeURIComponent(peerId)}${suffix}`;
}

export function configurationViewState(payload, visible = false) {
  const available = payload?.available === true && typeof payload.configuration === "string";
  return {
    available,
    configuration: available ? payload.configuration : "",
    displayedConfiguration: available && visible ? payload.configuration : "",
  };
}

// Runtime recency is determined centrally by the backend, including keepalive.
export function peerStatusView(peer) {
  if (peer.status === "revoked") return { key: "revoked", label: "Revoked", tone: "danger" };
  const states = {
    active_recently: { key: "active_recently", label: "Active recently", tone: "success" },
    inactive: { key: "inactive", label: "Inactive", tone: "neutral" },
    never_connected: { key: "never_connected", label: "Never connected", tone: "neutral" },
  };
  return states[peer.runtime_status] || { key: "unknown", label: "Unavailable", tone: "warning" };
}

export function peerActions(peer) {
  return peer.status === "revoked"
    ? ["edit", "regenerate", "delete"]
    : ["config", "edit", "regenerate", "revoke"];
}

export function handshakeLabel(peer) {
  if (!peer.latest_handshake) return t("wireguard_management.no_handshake", {}, "Never");
  const age = peer.handshake_age;
  if (!Number.isFinite(age) || age < 0) return "—";
  const units = [[86400, "days", "d"], [3600, "hours", "h"], [60, "minutes", "min"], [1, "seconds", "sec"]];
  const [size, unit, short] = units.find(([size]) => age >= size) || units.at(-1);
  const count = Math.floor(age / size);
  return t(`wireguard_management.age.${unit}`, { count }, `${count} ${short} ago`);
}

function configurationError(error) {
  const detail = error?.payload?.detail;
  const code = typeof detail === "string" ? detail : error?.payload?.error || error?.code || error;
  return t(`wireguard_management.errors.${code || "load_failed"}`, {},
    t("wireguard_management.errors.load_failed", {}, "The WireGuard action could not be completed."));
}

function showError(selector, error) {
  const element = select(selector);
  element.textContent = configurationError(error);
  element.hidden = false;
}

function clearError(selector) {
  select(selector).textContent = "";
  select(selector).hidden = true;
}

function textElement(tag, text, className = "") {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function cell(label, value) {
  const element = document.createElement("td");
  element.dataset.label = t(`wireguard_management.${label}`, {}, label);
  if (typeof value === "string") element.textContent = value;
  else element.append(value);
  return element;
}

export function renderPeerList(payload) {
  const peers = payload?.peers || [];
  setStatusPill(select("#management-wireguard-state"),
    t(`wireguard_management.${payload.active ? "ingress_active" : "ingress_inactive"}`, {}, payload.active ? "Active" : "Inactive"),
    payload.active ? "success" : "neutral");
  setTechnicalValue(select("#management-wireguard-interface"), payload.interface);
  setTechnicalValue(select("#management-wireguard-subnet"), payload.subnet);
  select("#management-wireguard-port").textContent = payload.listen_port ?? "—";
  setTechnicalValue(select("#management-wireguard-endpoint"), payload.endpoint);
  select("#management-wireguard-total").textContent = payload.total_peers ?? peers.length;
  select("#management-wireguard-recent").textContent = payload.recent_peers ?? 0;
  select("#wireguard-peers-loading").hidden = true;
  select("#wireguard-peers-empty").hidden = peers.length > 0;
  select("#wireguard-peers-content").hidden = peers.length === 0;
  const list = select("#wireguard-peer-list");
  const rows = peers.map((peer) => {
    const row = document.createElement("tr");
    row.dataset.peerId = peer.peer_id;
    const identity = document.createElement("div");
    identity.append(textElement("strong", peer.name));
    if (peer.description) identity.append(textElement("small", peer.description, "wireguard-peer-description"));
    const audit = textElement("small", t("wireguard_management.created", {}, "Created") + ": " + formatTimestamp(peer.created_at), "wireguard-peer-audit");
    if (peer.revoked_at) audit.textContent += " · " + t("wireguard_management.revoked", {}, "Revoked") + ": " + formatTimestamp(peer.revoked_at);
    identity.append(audit);
    const address = document.createElement("span");
    setTechnicalValue(address, peer.tunnel_ip);
    const state = peerStatusView(peer);
    const pill = document.createElement("span");
    setStatusPill(pill, t(`wireguard_management.peer_status.${state.key}`, {}, state.label), state.tone);
    const handshake = textElement("span", handshakeLabel(peer));
    if (peer.latest_handshake) handshake.title = formatTimestamp(peer.latest_handshake);
    const endpoint = document.createElement("span");
    setTechnicalValue(endpoint, peer.endpoint);
    const traffic = document.createElement("div");
    traffic.append(textElement("span", `RX ${formatBytes(peer.received_bytes)}`), textElement("span", `TX ${formatBytes(peer.sent_bytes)}`));
    const actions = document.createElement("div");
    actions.className = "wireguard-peer-actions";
    for (const action of peerActions(peer)) {
      const button = textElement("button", t(`wireguard_management.${action}`, {}, action), `button button-${["revoke", "delete"].includes(action) ? "danger" : "secondary"}`);
      button.type = "button";
      button.dataset.peerAction = action;
      button.dataset.peerId = peer.peer_id;
      button.disabled = mutating;
      button.setAttribute("aria-label", `${button.textContent}: ${peer.name}`);
      button.addEventListener("click", () => {
        if (mutating) return;
        if (action === "config") openPeerConfiguration(peer);
        else if (action === "edit") openPeerEditor(peer);
        else openPeerMutation(peer, action);
      });
      actions.append(button);
    }
    row.append(cell("device", identity), cell("tunnel_ip", address), cell("status", pill), cell("last_handshake", handshake), cell("remote_endpoint", endpoint), cell("traffic", traffic), cell("actions", actions));
    return row;
  });
  list.replaceChildren(...rows);
  // Another administrator/tab can revoke or regenerate while this modal is open.
  if (selectedPeer) {
    const current = peers.find((peer) => peer.peer_id === selectedPeer.peer_id);
    if (!current || current.status === "revoked" || current.public_key !== selectedPeer.public_key) closeConfiguration();
    else selectedPeer = current;
  }
}

function formatTimestamp(value) {
  if (!value) return "—";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString(getCurrentLanguage());
}

export async function loadManagedPeers() {
  const generation = sessionGeneration;
  const request = ++listRequest;
  beginRefresh("wireguardPeers");
  clearError("#wireguard-peers-error");
  try {
    const payload = await api(PEERS_PATH, { deduplicate: false });
    if (generation !== sessionGeneration || request !== listRequest) return;
    succeedRefresh("wireguardPeers", payload);
  } catch (error) {
    if (generation !== sessionGeneration || request !== listRequest) return;
    failRefresh("wireguardPeers", error.code);
    select("#wireguard-peers-loading").hidden = true;
    showError("#wireguard-peers-error", error);
  }
}

function clearConfigurationQr() {
  const image = select("#wireguard-qr-image");
  image.removeAttribute("src");
  image.hidden = true;
  select("#wireguard-qr-loading").hidden = false;
  select("#wireguard-qr-error").hidden = true;
}

export function clearManagedConfiguration() {
  ++configRequest;
  currentConfiguration = "";
  configurationVisible = false;
  selectedPeer = null;
  select("#management-wireguard-config").textContent = "";
  select("#management-wireguard-config").hidden = true;
  select("#wireguard-config-content").hidden = true;
  select("#wireguard-config-download").removeAttribute("href");
  select("#wireguard-config-download").removeAttribute("download");
  clearConfigurationQr();
}

function closeConfiguration() {
  select("#wireguard-qr-dialog").close();
  select("#wireguard-config-dialog").close();
  clearManagedConfiguration();
}

export function renderConfiguration(payload) {
  const view = configurationViewState(payload, configurationVisible);
  currentConfiguration = view.configuration;
  select("#wireguard-config-loading").hidden = true;
  clearError("#wireguard-config-error");
  select("#wireguard-config-empty").hidden = view.available;
  select("#wireguard-config-content").hidden = !view.available;
  select("#management-wireguard-config").textContent = view.displayedConfiguration;
  select("#management-wireguard-config").hidden = !view.available || !configurationVisible;
  const toggle = select("#wireguard-config-toggle");
  toggle.setAttribute("aria-expanded", String(configurationVisible));
  toggle.textContent = t(`wireguard_management.${configurationVisible ? "hide" : "show"}`, {}, configurationVisible ? "Hide" : "Show");
  if (view.available && selectedPeer) {
    const download = select("#wireguard-config-download");
    download.href = peerPath(selectedPeer.peer_id, "/config/download");
    if (/^exitlane-[a-z0-9-]+\.conf$/.test(payload.filename || "")) download.download = payload.filename;
  }
}

export async function openPeerConfiguration(peer, payload = null) {
  if (peer.status === "revoked") return;
  clearManagedConfiguration();
  selectedPeer = { ...peer };
  const request = ++configRequest;
  const generation = sessionGeneration;
  select("#wireguard-config-title").textContent = t("wireguard_management.config_for", { name: peer.name }, `Configuration: ${peer.name}`);
  select("#wireguard-config-loading").hidden = false;
  select("#wireguard-config-empty").hidden = true;
  clearError("#wireguard-config-error");
  select("#wireguard-config-dialog").showModal();
  try {
    const result = payload || await api(peerPath(peer.peer_id, "/config"), { deduplicate: false, cache: "no-store" });
    if (request !== configRequest || generation !== sessionGeneration) return;
    renderConfiguration(result);
  } catch (error) {
    if (request !== configRequest || generation !== sessionGeneration) return;
    select("#wireguard-config-loading").hidden = true;
    showError("#wireguard-config-error", error);
  }
}

export function toggleManagedConfiguration() {
  if (!currentConfiguration) return;
  configurationVisible = !configurationVisible;
  renderConfiguration({ available: true, configuration: currentConfiguration });
}

export async function copyManagedConfiguration() {
  if (!currentConfiguration) return;
  try {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(currentConfiguration);
      } catch {
        copyWithTemporarySelection(currentConfiguration);
      }
    } else {
      copyWithTemporarySelection(currentConfiguration);
    }
    showMessage(t("wireguard_management.copied", {}, "Configuration copied."), "success");
  } catch {
    showMessage(t("wireguard_management.errors.copy_failed", {}, "Copying failed. Show and select the configuration manually."), "error");
  }
}

function copyWithTemporarySelection(configuration) {
  const input = document.createElement("textarea");
  const previousFocus = document.activeElement;
  input.value = configuration;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  select("#wireguard-config-dialog").appendChild(input);
  try {
    input.focus({ preventScroll: true });
    input.select();
    if (!document.execCommand?.("copy")) throw new Error("copy_failed");
  } finally {
    input.value = "";
    input.remove();
    if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
  }
}

export function openConfigurationQr() {
  if (!currentConfiguration || !selectedPeer) return false;
  clearConfigurationQr();
  select("#wireguard-qr-image").src = peerPath(selectedPeer.peer_id, "/config/qr");
  select("#wireguard-qr-dialog").showModal();
  return true;
}

export function openPeerEditor(peer = null) {
  if (mutating) return;
  editingPeer = peer ? { ...peer } : null;
  select("#wireguard-peer-editor-title").textContent = t(`wireguard_management.${peer ? "edit_title" : "add"}`, {}, peer ? "Edit device" : "Add device");
  select("#wireguard-peer-name").value = peer?.name || "";
  select("#wireguard-peer-description").value = peer?.description || "";
  clearError("#wireguard-peer-editor-error");
  select("#wireguard-peer-editor-dialog").showModal();
}

function setMutationBusy(busy) {
  mutating = busy;
  for (const selector of ["#wireguard-peer-add", "#wireguard-peer-editor-save", "#wireguard-peer-editor-cancel", "#wireguard-peer-mutation-confirm", "#wireguard-peer-mutation-cancel"]) select(selector).disabled = busy;
  select("#wireguard-peers-content").querySelectorAll("button").forEach((button) => { button.disabled = busy; });
}

export async function savePeerEditor(event) {
  event?.preventDefault();
  if (mutating) return;
  const peer = editingPeer;
  const generation = sessionGeneration;
  const button = select("#wireguard-peer-editor-save");
  const body = { name: select("#wireguard-peer-name").value.trim(), description: select("#wireguard-peer-description").value.trim() };
  if (!body.name) { select("#wireguard-peer-name").reportValidity(); return; }
  clearError("#wireguard-peer-editor-error");
  setMutationBusy(true);
  setBusy(button, true, t("wireguard_management.saving", {}, "Saving…"));
  try {
    const result = peer
      ? await api(peerPath(peer.peer_id), { method: "PATCH", body: JSON.stringify(body) })
      : await postJson(PEERS_PATH, body);
    if (generation !== sessionGeneration) return;
    select("#wireguard-peer-editor-dialog").close();
    await loadManagedPeers();
    if (generation !== sessionGeneration) return;
    showMessage(t(`wireguard_management.${peer ? "updated" : "created_message"}`, {}, peer ? "Device updated." : "Device added."), "success");
    if (!peer) await openPeerConfiguration(result.peer, result);
  } catch (error) {
    if (generation === sessionGeneration) showError("#wireguard-peer-editor-error", error);
  } finally {
    setMutationBusy(false);
    setBusy(button, false);
  }
}

export function openPeerMutation(peer, action) {
  if (mutating || !peerActions(peer).includes(action)) return false;
  pendingMutation = { peer: { ...peer }, action };
  renderMutationConfirmation();
  clearError("#wireguard-peer-mutation-error");
  select("#wireguard-peer-mutation-dialog").showModal();
  return true;
}

function renderMutationConfirmation() {
  if (!pendingMutation) return;
  const { peer, action } = pendingMutation;
  select("#wireguard-peer-mutation-title").textContent = t(`wireguard_management.${action}_title`, { name: peer.name }, `${action}: ${peer.name}`);
  select("#wireguard-peer-mutation-description").textContent = t(`wireguard_management.${action}_description`, { name: peer.name }, action);
  const button = select("#wireguard-peer-mutation-confirm");
  delete button.dataset.originalLabel;
  button.textContent = t(`wireguard_management.${action}`, {}, action);
}

export async function confirmPeerMutation() {
  if (mutating || !pendingMutation) return;
  const { peer, action } = pendingMutation;
  const generation = sessionGeneration;
  const button = select("#wireguard-peer-mutation-confirm");
  // A stale profile/QR must disappear before its identity is replaced or revoked.
  if (selectedPeer?.peer_id === peer.peer_id) closeConfiguration();
  clearError("#wireguard-peer-mutation-error");
  setMutationBusy(true);
  setBusy(button, true, t("wireguard_management.saving", {}, "Saving…"));
  try {
    const result = action === "delete"
      ? await api(peerPath(peer.peer_id), { method: "DELETE" })
      : await postJson(peerPath(peer.peer_id, `/${action}`));
    if (generation !== sessionGeneration) return;
    select("#wireguard-peer-mutation-dialog").close();
    pendingMutation = null;
    await loadManagedPeers();
    if (generation !== sessionGeneration) return;
    showMessage(t(`wireguard_management.${action}_message`, {}, "Device updated."), "success");
    if (action === "regenerate") {
      const current = getSlice("wireguardPeers").data?.peers?.find((item) => item.peer_id === peer.peer_id);
      await openPeerConfiguration(result.peer || current || { ...peer, status: "active" }, result);
    }
  } catch (error) {
    if (generation === sessionGeneration) showError("#wireguard-peer-mutation-error", error);
  } finally {
    setMutationBusy(false);
    setBusy(button, false);
  }
}

export async function refreshManagedWireGuard() {
  const button = select("#management-wireguard-refresh");
  setBusy(button, true, t("busy.checking", {}, "Checking…"));
  try { await loadManagedPeers(); } finally { setBusy(button, false); }
}

function clearManagementSession() {
  ++sessionGeneration;
  ++listRequest;
  closeConfiguration();
  select("#wireguard-peer-editor-dialog").close();
  select("#wireguard-peer-mutation-dialog").close();
  editingPeer = null;
  pendingMutation = null;
  select("#wireguard-peer-name").value = "";
  select("#wireguard-peer-description").value = "";
}

export function initialiseWireGuardManagement() {
  if (initialised || !select("#management-wireguard-refresh")) return;
  initialised = true;
  select("#management-wireguard-refresh").addEventListener("click", refreshManagedWireGuard);
  select("#wireguard-peer-add").addEventListener("click", () => openPeerEditor());
  select("#wireguard-peer-editor-form").addEventListener("submit", savePeerEditor);
  select("#wireguard-peer-editor-cancel").addEventListener("click", () => select("#wireguard-peer-editor-dialog").close());
  select("#wireguard-peer-mutation-cancel").addEventListener("click", () => {
    if (!mutating) { pendingMutation = null; select("#wireguard-peer-mutation-dialog").close(); }
  });
  select("#wireguard-peer-mutation-confirm").addEventListener("click", confirmPeerMutation);
  for (const selector of ["#wireguard-peer-editor-dialog", "#wireguard-peer-mutation-dialog"]) {
    select(selector).addEventListener("cancel", (event) => { if (mutating) event.preventDefault(); });
  }
  select("#wireguard-config-toggle").addEventListener("click", toggleManagedConfiguration);
  select("#wireguard-config-copy").addEventListener("click", copyManagedConfiguration);
  select("#wireguard-config-qr").addEventListener("click", openConfigurationQr);
  select("#wireguard-config-close").addEventListener("click", closeConfiguration);
  select("#wireguard-config-dialog").addEventListener("close", clearManagedConfiguration);
  const qrDialog = select("#wireguard-qr-dialog");
  const qrImage = select("#wireguard-qr-image");
  qrImage.addEventListener("load", () => {
    if (!qrImage.getAttribute("src")) return;
    select("#wireguard-qr-loading").hidden = true;
    qrImage.hidden = false;
  });
  qrImage.addEventListener("error", () => {
    if (!qrImage.getAttribute("src")) return;
    qrImage.hidden = true;
    select("#wireguard-qr-loading").hidden = true;
    select("#wireguard-qr-error").hidden = false;
  });
  qrDialog.addEventListener("close", clearConfigurationQr);
  select("#wireguard-qr-close").addEventListener("click", () => qrDialog.close());
  subscribe("wireguardPeers", (slice) => { if (slice.data && managementActive) renderPeerList(slice.data); });
  subscribe("wireguard", (slice) => { if (slice.data && managementActive && !mutating) loadManagedPeers(); });
  subscribe("application", (application) => {
    const active = application.mode === "dashboard" && application.activeView === "wireguard";
    if (active && !managementActive) {
      managementActive = true;
      select("#wireguard-peers-loading").hidden = false;
      select("#wireguard-peers-content").hidden = true;
      select("#wireguard-peers-empty").hidden = true;
      loadManagedPeers();
    } else if (!active && managementActive) {
      managementActive = false;
      clearManagementSession();
    }
  }, { immediate: true });
  window.addEventListener("exitlane:authenticationrequired", () => {
    managementActive = false;
    clearManagementSession();
  });
  window.addEventListener("pagehide", clearManagementSession);
  window.addEventListener("exitlane:languagechange", () => {
    if (managementActive && getSlice("wireguardPeers").data) renderPeerList(getSlice("wireguardPeers").data);
    renderMutationConfirmation();
    if (selectedPeer) select("#wireguard-config-title").textContent = t("wireguard_management.config_for", { name: selectedPeer.name }, `Configuration: ${selectedPeer.name}`);
  });
}
