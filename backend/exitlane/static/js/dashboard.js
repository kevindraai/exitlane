import { t } from "./i18n.js";
import { createIcon, renderIcon } from "./icons.js";
import { select, setBusy, setStatusPill, setTechnicalValue } from "./ui.js";
import {
  formatBytes,
  formatCpuPercent,
  formatDuration,
  formatRelativeTime as formatRelative,
} from "./dashboard-format.js";
import { createDashboardRefreshState } from "./dashboard-refresh-state.js";
import { getSlice, subscribe } from "./state.js";
import { refreshDashboardState } from "./lifecycle.js";
import { initialiseDashboardInfo, closeDashboardInfo, positionDashboardInfo } from "./dashboard-info.js";
import { providerStatusId } from "./provider-management.js";

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

export function dashboardProviderName(data) {
  return data.active_provider?.display_name || null;
}

export function renderDashboardProvider(data, renderText = text) {
  renderText("#dashboard-vpn-provider", dashboardProviderName(data));
}

export function dashboardLocation(vpn) {
  return [vpn.city, vpn.country].filter((value) => value && value !== "—").join(", ") || "—";
}

export const DASHBOARD_PEER_LIMIT = 5;

export function dashboardPeerSummary(peers = []) {
  // Recent first, then active lifecycle, revoked last; name and durable ID break ties.
  const priority = (peer) => peer.status === "revoked" ? 2 : peer.runtime_status === "active_recently" ? 0 : 1;
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  return [...peers].sort((a, b) => priority(a) - priority(b)
    || compare(a.name.toLowerCase(), b.name.toLowerCase())
    || compare(a.peer_id, b.peer_id)).slice(0, DASHBOARD_PEER_LIMIT);
}

export function renderDashboardPeers(wireguard) {
  const peers = wireguard.peers || [];
  const recent = peers.some((peer) => peer.status !== "revoked" && peer.runtime_status === "active_recently");
  const label = wireguard.available === false ? "unavailable" : !wireguard.active ? "inactive" : recent ? "recently_active" : "waiting";
  setStatusPill(select("#dashboard-wg-pill"), t(`dashboard.${label}`, {}, label),
    recent && wireguard.active ? "success" : wireguard.available === false || wireguard.configured && !wireguard.active ? "danger" : "neutral");
  text("#dashboard-wg-summary", t(peers.length === 1 ? "dashboard.device_count_one" : "dashboard.device_count", { count: peers.length }, peers.length === 1 ? "1 device" : `${peers.length} devices`));
  select("#dashboard-wg-empty").hidden = peers.length !== 0 || wireguard.available === false;
  select("#dashboard-wg-table").hidden = peers.length === 0;
  select("#dashboard-wg-error").hidden = wireguard.available !== false;
  text("#dashboard-wg-error", t("dashboard.wireguard_unavailable", {}, "WireGuard status is unavailable."));
  const shown = dashboardPeerSummary(peers);
  const rows = shown.map((peer) => {
    const row = document.createElement("tr");
    const state = peer.status === "revoked" ? "revoked" : peer.runtime_status === "active_recently" && wireguard.active ? "active_recently" : peer.runtime_status === "never_connected" ? "never_connected" : "inactive";
    const status = document.createElement("td");
    const indicator = document.createElement("span");
    indicator.className = `dashboard-peer-state ${state === "active_recently" ? "status-success" : state === "revoked" ? "status-danger" : "status-neutral"}`;
    indicator.setAttribute("role", "img");
    const statusLabel = state === "inactive"
      ? t("dashboard.not_recently_active", {}, "Not recently active")
      : t(`wireguard_management.peer_status.${state}`, {}, state);
    indicator.setAttribute("aria-label", statusLabel);
    indicator.title = statusLabel;
    indicator.append(createIcon(state === "active_recently" ? "circle-check" : state === "revoked" ? "circle-x" : "circle"));
    status.append(indicator);
    const name = document.createElement("td");
    const nameText = document.createElement("span");
    nameText.textContent = peer.name;
    nameText.title = peer.name;
    name.append(nameText);
    const traffic = document.createElement("td");
    for (const [direction, key, value] of [["↓", "received", peer.received_bytes], ["↑", "sent", peer.sent_bytes]]) {
      const counter = document.createElement("span");
      counter.textContent = `${direction} ${formatBytes(value)}`;
      counter.setAttribute("aria-label", `${t(`dashboard.${key}`, {}, key)}: ${formatBytes(value)}`);
      traffic.append(counter);
    }
    row.append(status, name, traffic);
    return row;
  });
  select("#dashboard-wg-peer-list").replaceChildren(...rows);
  select("#dashboard-wg-more").hidden = peers.length <= shown.length;
  text("#dashboard-wg-more", t("dashboard.more_devices", { count: peers.length - shown.length }, `+ ${peers.length - shown.length} more devices`));
}

function renderLastSuccessfulRefresh(now = Date.now()) {
  const timestamp = getSlice("dashboard").updatedAt;
  text("#dashboard-refreshed", formatRelative(timestamp, now, t));
  select("#dashboard-refreshed").dataset.timestamp = timestamp == null ? "" : String(timestamp);
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
  renderDashboardProvider(data);
  text("#dashboard-vpn-location", dashboardLocation(data.vpn));
  setTechnicalValue(select("#dashboard-vpn-server"), data.vpn.server);
  setTechnicalValue(select("#dashboard-external-ip"), data.vpn.external_ip);
  text("#dashboard-vpn-target", data.vpn.target);
  text("#dashboard-vpn-updated", data.vpn.updated_at ? formatRelativeTime(data.vpn.updated_at) : t("dashboard.unavailable", {}, "Unavailable"));
  text("#dashboard-vpn-error", data.vpn.error ? t("dashboard.vpn_unavailable", {}, "VPN status is unavailable.") : "");
  select("#dashboard-vpn-error").hidden = !data.vpn.error;

  const killswitchKnown = data.killswitch?.available === true;
  const killswitchConfigured = killswitchKnown ? data.killswitch.configured : null;
  const killswitchLabel = killswitchConfigured === true
    ? t("dashboard.killswitch_active", {}, "Active")
    : killswitchConfigured === false
      ? t("dashboard.killswitch_disabled", {}, "Disabled")
      : t("dashboard.killswitch_unknown", {}, "Status unknown");
  text("#dashboard-killswitch-state", killswitchLabel);
  select("#dashboard-killswitch-status").className = `dashboard-inline-status ${data.killswitch?.state === "enabled_protected" ? "status-success" : "status-neutral"}`;
  renderIcon(
    select("#dashboard-killswitch-icon"),
    data.killswitch?.state === "enabled_protected"
      ? "shield-check"
      : killswitchConfigured === false ? "shield" : "shield-alert",
  );
  text(
    "#dashboard-killswitch-description",
    killswitchConfigured === true
      ? t(
        "dashboard.killswitch_active_description",
        {},
        "Traffic is blocked when the VPN connection is lost.",
      )
      : killswitchConfigured === false
        ? t(
          "dashboard.killswitch_disabled_description",
          {},
          "Traffic can continue without an active VPN connection.",
        )
        : t("dashboard.killswitch_unknown", {}, "Status unknown"),
  );

  positionDashboardInfo();
  renderDashboardPeers(data.wireguard);

  setTechnicalValue(select("#dashboard-hostname"), data.system.hostname);
  text("#dashboard-cpu", formatCpuPercent(data.system.cpu_percent));
  text("#dashboard-memory", data.system.memory_percent == null ? "—" : `${bytesOrUnknown(data.system.memory_used_bytes)} / ${bytesOrUnknown(data.system.memory_total_bytes)} · ${data.system.memory_percent}%`);
  text("#dashboard-disk", data.system.disk_percent == null ? "—" : `${bytesOrUnknown(data.system.disk_used_bytes)} / ${bytesOrUnknown(data.system.disk_total_bytes)} · ${data.system.disk_percent}%`);
  text("#dashboard-uptime", data.system.uptime_seconds == null ? "—" : formatDuration(data.system.uptime_seconds));
  text("#dashboard-load", data.system.load_average?.join(" / ") || "—");
  const temperature = select("#dashboard-temperature-fact");
  temperature.hidden = data.system.temperature_celsius == null;
  text("#dashboard-temperature", data.system.temperature_celsius == null ? "—" : `${data.system.temperature_celsius} °C`);
  const systemError = select("#dashboard-system-error");
  systemError.textContent = data.system.available ? "" : t("dashboard.system_unavailable", {}, "System status is unavailable.");
  systemError.hidden = data.system.available;
  setTechnicalValue(select("#dashboard-version"), `v${data.version}`);
  renderLastSuccessfulRefresh();
  if (successfulRefresh) select("#dashboard-refresh-error").hidden = true;

  lastDashboardData = data;
  if (successfulRefresh) refreshState.succeed(data);
}

export async function refreshDashboard({ signal } = {}) {
  const button = select("#dashboard-refresh");
  setBusy(button, true, t("busy.checking", {}, "Checking…"));
  try {
    const data = await refreshDashboardState({ signal });
    renderDashboard(data);
    return data;
  } catch (error) {
    if (error.code === "aborted") throw error;
    refreshState.fail(error.message);
    if (getSlice("dashboard").updatedAt) {
      renderLastSuccessfulRefresh();
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
  initialiseDashboardInfo();
  subscribe("dashboard", (slice) => {
    if (slice.data) renderDashboard(slice.data, { successfulRefresh: !slice.error });
    else { lastDashboardData = null; closeDashboardInfo(); }
  }, { immediate: true });
  subscribe("provider", (slice) => {
    const observedId = providerStatusId(slice.data || {});
    const activeId = lastDashboardData?.active_provider?.id;
    if (observedId && activeId && observedId !== activeId) return;
    if (lastDashboardData && slice.data) renderDashboard({ ...lastDashboardData, vpn: { ...lastDashboardData.vpn, ...slice.data } }, { successfulRefresh: false });
  });
  subscribe("wireguard", (slice) => {
    if (lastDashboardData && slice.data) renderDashboard({ ...lastDashboardData, wireguard: { ...lastDashboardData.wireguard, ...slice.data } }, { successfulRefresh: false });
  });
  subscribe("application", (application) => {
    if (application.mode !== "dashboard" || application.activeView !== "dashboard") closeDashboardInfo();
  });
  window.setInterval(() => {
    const slice = getSlice("dashboard");
    if (slice.updatedAt && !select("#view-dashboard").hidden) {
      renderLastSuccessfulRefresh();
    }
  }, 1000);
  window.addEventListener("exitlane:languagechange", () => {
    if (lastDashboardData) renderDashboard(lastDashboardData, { successfulRefresh: false });
    for (const selector of ["#dashboard-refresh"]) {
      const button = select(selector);
      button.dataset.originalLabel = button.textContent.trim();
    }
  });
}
