import { api } from "./api.js";
import { t } from "./i18n.js";
import { appState } from "./state.js";
import {
  select,
  setStatusPill,
  showMessage,
} from "./ui.js";

let statusTimer = null;
let latestWireGuardStatus = null;

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

  select("#finish-config-filename").textContent =
    filename;

  const download = select("#finish-download");

  download.href =
    `/api/ingress/wireguard/client/${encodeURIComponent(
      name,
    )}`;

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
      t(
        "finish.config_unavailable",
        {},
        "The WireGuard configuration is unavailable.",
      ),
      "error",
    );
    return;
  }

  try {
    await navigator.clipboard.writeText(
      configuration,
    );

    showMessage(
      t(
        "finish.config_copied",
        {},
        "WireGuard configuration copied.",
      ),
    );
  } catch {
    showMessage(
      t(
        "finish.copy_failed",
        {},
        "Copying failed. View and copy the configuration manually.",
      ),
      "error",
    );
  }
}

function renderPreviewButton() {
  const preview = select(
    "#finish-config-preview",
  );

  select("#finish-view").textContent =
    preview.hidden
      ? t(
          "common.view",
          {},
          "View",
        )
      : t(
          "common.hide",
          {},
          "Hide",
        );
}

function togglePreview() {
  const preview = select(
    "#finish-config-preview",
  );

  preview.hidden = !preview.hidden;

  renderPreviewButton();
}

function renderWireGuardStatus(status) {
  latestWireGuardStatus = status;

  const state = select(
    "#wireguard-connection-state",
  );

  const message = select(
    "#wireguard-connection-message",
  );

  const details = select(
    "#wireguard-connection-details",
  );

  if (!status.active) {
    setStatusPill(
      state,
      t(
        "finish.inactive",
        {},
        "Inactive",
      ),
      "danger",
    );

    message.textContent =
      status.message ||
      t(
        "finish.interface_inactive",
        {},
        "The WireGuard interface is not active yet.",
      );

    details.hidden = true;
    return;
  }

  if (!status.connected) {
    setStatusPill(
      state,
      t(
        "common.waiting",
        {},
        "Waiting",
      ),
      "neutral",
    );

    message.textContent = t(
      "finish.no_handshake",
      {},
      "No WireGuard handshake has been received yet.",
    );

    details.hidden = true;
    return;
  }

  const peer = status.peers?.[0] || {};

  setStatusPill(
    state,
    t(
      "finish.connected",
      {},
      "Connected",
    ),
    "success",
  );

  message.textContent = t(
    "finish.router_connected",
    {},
    "The router has connected successfully.",
  );

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
    latestWireGuardStatus = null;

    setStatusPill(
      select("#wireguard-connection-state"),
      t(
        "common.status_error",
        {},
        "Status error",
      ),
      "danger",
    );

    select(
      "#wireguard-connection-message",
    ).textContent =
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

function rerenderFinishStep() {
  renderPreviewButton();

  if (latestWireGuardStatus) {
    renderWireGuardStatus(
      latestWireGuardStatus,
    );
  }
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

  select(
    "#wireguard-status-refresh",
  ).addEventListener(
    "click",
    refreshWireGuardStatus,
  );

  window.addEventListener(
    "exitlane:languagechange",
    rerenderFinishStep,
  );

  renderPreviewButton();
}
