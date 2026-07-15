import { api } from "./api.js";
import { appState } from "./state.js";
import {
  select,
  setStatusPill,
  showMessage,
} from "./ui.js";

let statusTimer = null;

function formatBytes(bytes) {
  const value = Number(bytes || 0);

  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }

  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

export function prepareFinishStep({
  clientName,
  clientConfig,
}) {
  const name = clientName || "router";

  appState.generatedClientName = name;
  appState.generatedClientConfig = clientConfig;

  const filename = `exitlane-${name}.conf`;

  select("#finish-config-filename").textContent = filename;

  const download = select("#finish-download");
  download.href =
    `/api/ingress/wireguard/client/${encodeURIComponent(name)}`;
  download.download = filename;

  select("#finish-config-preview").textContent =
    clientConfig || "";

  startWireGuardStatusPolling();
}

async function copyConfiguration() {
  const configuration =
    appState.generatedClientConfig ||
    select("#finish-config-preview").textContent;

  if (!configuration) {
    showMessage(
      "De WireGuard-configuratie is niet beschikbaar.",
      "error",
    );
    return;
  }

  try {
    await navigator.clipboard.writeText(configuration);
    showMessage("WireGuard-configuratie gekopieerd.");
  } catch {
    showMessage(
      "Kopiëren is niet gelukt. Bekijk en kopieer de configuratie handmatig.",
      "error",
    );
  }
}

function togglePreview() {
  const preview = select("#finish-config-preview");
  preview.hidden = !preview.hidden;

  select("#finish-view").textContent = preview.hidden
    ? "Bekijken"
    : "Verbergen";
}

function renderWireGuardStatus(status) {
  const state = select("#wireguard-connection-state");
  const message = select("#wireguard-connection-message");
  const details = select("#wireguard-connection-details");

  if (!status.active) {
    setStatusPill(
      state,
      "Niet actief",
      "danger",
    );

    message.textContent =
      status.message ||
      "De WireGuard-interface is nog niet actief.";

    details.hidden = true;
    return;
  }

  if (!status.connected) {
    setStatusPill(
      state,
      "Wachten",
      "neutral",
    );

    message.textContent =
      "Nog geen WireGuard-handshake ontvangen.";

    details.hidden = true;
    return;
  }

  const peer = status.peers?.[0] || {};

  setStatusPill(
    state,
    "Verbonden",
    "success",
  );

  message.textContent =
    "De router heeft succesvol verbinding gemaakt.";

  select("#wireguard-status-client").textContent =
    status.client || "router";

  select("#wireguard-status-endpoint").textContent =
    peer.endpoint || "—";

  select("#wireguard-status-received").textContent =
    formatBytes(peer.received_bytes);

  select("#wireguard-status-sent").textContent =
    formatBytes(peer.sent_bytes);

  details.hidden = false;
}

export async function refreshWireGuardStatus() {
  try {
    const status = await api(
      "/api/ingress/wireguard/status",
    );

    renderWireGuardStatus(status);
  } catch (error) {
    setStatusPill(
      select("#wireguard-connection-state"),
      "Statusfout",
      "danger",
    );

    select("#wireguard-connection-message").textContent =
      error.message;
  }
}

export function startWireGuardStatusPolling() {
  window.clearInterval(statusTimer);

  refreshWireGuardStatus();

  statusTimer = window.setInterval(
    refreshWireGuardStatus,
    2000,
  );
}

export function stopWireGuardStatusPolling() {
  window.clearInterval(statusTimer);
  statusTimer = null;
}

export function initialiseFinishControls() {
  select("#finish-copy").addEventListener(
    "click",
    copyConfiguration,
  );

  select("#finish-view").addEventListener(
    "click",
    togglePreview,
  );

  select("#wireguard-status-refresh").addEventListener(
    "click",
    refreshWireGuardStatus,
  );
}
