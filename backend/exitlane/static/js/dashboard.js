import { api } from "./api.js";
import { t } from "./i18n.js";
import { renderProviderStatus } from "./provider.js";
import { select, setBusy, setStatusPill } from "./ui.js";
import { formatBytes, formatDuration, formatRelativeTime as formatRelative } from "./dashboard-format.js";
import { createDashboardRefreshState } from "./dashboard-refresh-state.js";

const formatRelativeTime = (value) => formatRelative(value, Date.now(), t);
let lastDashboardData = null;
let initialised = false;
const refreshState = createDashboardRefreshState();

function text(id, value) {
  select(id).textContent = value ?? "—";
}

function bytesOrUnknown(value) {
  return value == null ? "—" : formatBytes(value);
}

export function renderDashboard(data, { successfulRefresh = true } = {}) {
  const healthStyles = { healthy: "success", warning: "neutral", error: "danger" };
  setStatusPill(select("#dashboard-health-state"), t(`dashboard.health.${data.health.status}`, {}, data.health.status), healthStyles[data.health.status]);
  const issues = select("#dashboard-issues");
  issues.replaceChildren(...data.health.issues.map((issue) => {
    const item = document.createElement("li");
    item.textContent = t(`dashboard.issues.${issue}`, {}, issue);
    return item;
  }));
  issues.hidden = data.health.issues.length === 0;

  const vpnState = !data.vpn.available ? "unavailable" : data.vpn.connected ? "connected" : "disconnected";
  setStatusPill(select("#dashboard-vpn-pill"), t(`dashboard.${vpnState}`, {}, vpnState), data.vpn.connected ? "success" : data.vpn.available ? "neutral" : "danger");
  text("#dashboard-vpn-country", data.vpn.country);
  text("#dashboard-vpn-city", data.vpn.city);
  text("#dashboard-vpn-server", data.vpn.server);
  text("#dashboard-external-ip", data.vpn.external_ip);
  text("#dashboard-vpn-target", data.vpn.target);
  text("#dashboard-vpn-updated", data.vpn.updated_at ? formatRelativeTime(data.vpn.updated_at) : t("dashboard.unavailable", {}, "Unavailable"));
  text("#dashboard-vpn-error", data.vpn.error ? t("dashboard.vpn_unavailable", {}, "VPN status is unavailable.") : "");
  select("#dashboard-vpn-error").hidden = !data.vpn.error;

  setStatusPill(select("#dashboard-wg-pill"), t(`dashboard.${data.wireguard.active ? (data.wireguard.connected ? "connected" : "waiting") : "inactive"}`, {}, data.wireguard.active ? "Waiting" : "Inactive"), data.wireguard.connected ? "success" : data.wireguard.active ? "neutral" : "danger");
  text("#dashboard-wg-client", data.wireguard.client);
  text("#dashboard-wg-peers", data.wireguard.peer_count);
  text("#dashboard-wg-handshake", formatRelativeTime(data.wireguard.latest_handshake_at));
  text("#dashboard-wg-received", formatBytes(data.wireguard.received_bytes));
  text("#dashboard-wg-sent", formatBytes(data.wireguard.sent_bytes));
  text("#dashboard-wg-endpoint", data.wireguard.endpoint);

  text("#dashboard-hostname", data.system.hostname);
  text("#dashboard-cpu", data.system.cpu_percent == null ? "—" : `${data.system.cpu_percent}%`);
  text("#dashboard-memory", data.system.memory_percent == null ? "—" : `${bytesOrUnknown(data.system.memory_used_bytes)} / ${bytesOrUnknown(data.system.memory_total_bytes)} (${data.system.memory_percent}%)`);
  text("#dashboard-disk", data.system.disk_percent == null ? "—" : `${bytesOrUnknown(data.system.disk_used_bytes)} / ${bytesOrUnknown(data.system.disk_total_bytes)} (${data.system.disk_percent}%)`);
  text("#dashboard-uptime", data.system.uptime_seconds == null ? "—" : formatDuration(data.system.uptime_seconds));
  text("#dashboard-load", data.system.load_average?.join(" / ") || "—");
  const temperature = select("#dashboard-temperature-metric");
  temperature.hidden = data.system.temperature_celsius == null;
  text("#dashboard-temperature", data.system.temperature_celsius == null ? "—" : `${data.system.temperature_celsius} °C`);
  const systemError = select("#dashboard-system-error");
  systemError.textContent = data.system.available ? "" : t("dashboard.system_unavailable", {}, "System status is unavailable.");
  systemError.hidden = data.system.available;
  text("#dashboard-version", `v${data.version}`);
  text("#dashboard-refreshed", formatRelativeTime(data.generated_at));
  if (successfulRefresh) select("#dashboard-refresh-error").hidden = true;
  select("#dashboard-refreshed").dataset.timestamp = data.generated_at;

  renderProviderStatus(data.vpn);
  lastDashboardData = data;
  if (successfulRefresh) refreshState.succeed(data);
}

export async function refreshDashboard({ signal } = {}) {
  const button = select("#dashboard-refresh");
  setBusy(button, true, t("busy.checking", {}, "Checking…"));
  try {
    const data = await api("/api/dashboard", { signal });
    renderDashboard(data);
    return data;
  } catch (error) {
    refreshState.fail(error.message);
    if (lastDashboardData?.generated_at) {
      text("#dashboard-refreshed", formatRelativeTime(lastDashboardData.generated_at));
    }
    const refreshError = select("#dashboard-refresh-error");
    refreshError.textContent = t("dashboard.refresh_error", { message: error.message }, `Refresh failed: ${error.message}`);
    refreshError.hidden = false;
    throw error;
  } finally {
    setBusy(button, false);
  }
}

export function initialiseDashboard() {
  if (initialised) return;
  initialised = true;
  window.addEventListener("exitlane:languagechange", () => {
    if (lastDashboardData) renderDashboard(lastDashboardData, { successfulRefresh: false });
    for (const selector of ["#dashboard-refresh", "#dashboard-wg-refresh"]) {
      const button = select(selector);
      button.dataset.originalLabel = button.textContent.trim();
    }
  });
}
