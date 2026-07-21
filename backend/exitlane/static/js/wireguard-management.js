import { api } from "./api.js";
import {
  select,
  setBusy,
  setStatusPill,
} from "./ui.js";

function formatBytes(bytes) {
  const value = Number(bytes || 0);

  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }

  return `${(
    value /
    (1024 * 1024)
  ).toFixed(1)} MiB`;
}

function renderStatus(status) {
  const state = select(
    "#management-wireguard-state",
  );

  const message = select(
    "#management-wireguard-message",
  );

  const details = select(
    "#management-wireguard-details",
  );

  if (!status.active) {
    setStatusPill(
      state,
      "Niet actief",
      "danger",
    );

    message.textContent =
      status.message ||
      "De WireGuard-interface is niet actief.";

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
      "De interface is actief, maar er is nog geen handshake ontvangen.";

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
    "De routertunnel is actief.";

  select(
    "#management-wireguard-client",
  ).textContent =
    status.client || "router";

  select(
    "#management-wireguard-endpoint",
  ).textContent =
    peer.endpoint || "—";

  select(
    "#management-wireguard-received",
  ).textContent =
    formatBytes(peer.received_bytes);

  select(
    "#management-wireguard-sent",
  ).textContent =
    formatBytes(peer.sent_bytes);

  details.hidden = false;
}

export async function refreshManagedWireGuard() {
  const button = select(
    "#management-wireguard-refresh",
  );

  setBusy(
    button,
    true,
    "Controleren...",
  );

  try {
    const status = await api(
      "/api/ingress/wireguard/status",
    );

    renderStatus(status);
  } catch (error) {
    setStatusPill(
      select("#management-wireguard-state"),
      "Statusfout",
      "danger",
    );

    select(
      "#management-wireguard-message",
    ).textContent = error.message;
  } finally {
    setBusy(button, false);
  }
}

export function initialiseWireGuardManagement() {
  const refreshButton = document.querySelector(
    "#management-wireguard-refresh",
  );

  if (!refreshButton) {
    console.warn(
      "WireGuard management view is not available.",
    );
    return;
  }

  refreshButton.addEventListener(
    "click",
    refreshManagedWireGuard,
  );

  refreshManagedWireGuard();
}