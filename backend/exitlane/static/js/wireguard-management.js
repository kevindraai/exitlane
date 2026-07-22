import { formatBytes } from "./dashboard-format.js";
import { select, setBusy, setStatusPill } from "./ui.js";
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
  const render = (slice) => { if (slice.data) renderStatus(slice.data); };
  subscribe("wireguard", render, { immediate: true });
  window.addEventListener("exitlane:languagechange", () => render(getSlice("wireguard")));
}
