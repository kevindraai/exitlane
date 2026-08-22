import { api, postJson } from "./api.js";
import { t } from "./i18n.js";
import { getSlice, subscribe, updateSlice } from "./state.js";
import { renderIcon } from "./icons.js";

const TERMINAL = new Set(["passed", "warning", "failed"]);
const SEVERITY = ["failed", "warning", "running", "pending", "passed"];
let initialised = false;
let pollTimer = null;
let hasRun = false;
let expandedSegment = null;

export function aggregateDiagnosticStatus(probes) {
  if (!probes?.length) return "pending";
  const statuses = new Set(probes.map((probe) => probe.status));
  return SEVERITY.find((status) => statuses.has(status)) || "pending";
}

export function segmentStatuses(run) {
  const bySegment = Object.fromEntries(
    ["device_exitlane", "exitlane_vpn", "vpn_internet"].map((segment) => [
      segment,
      aggregateDiagnosticStatus((run?.probes || []).filter((probe) => probe.segment === segment)),
    ]),
  );
  return {
    segments: bySegment,
    nodes: {
      device: run ? "passed" : "pending",
      exitlane: bySegment.device_exitlane,
      vpn: bySegment.exitlane_vpn,
      internet: bySegment.vpn_internet,
    },
  };
}

function statusText(status) {
  return t(`diagnostics.status.${status}`, {}, status);
}

function statusIcon(status) {
  if (status === "passed") return "✓";
  if (status === "failed") return "×";
  if (status === "warning") return "!";
  return "…";
}

function detailText(probe) {
  const base = t(`diagnostics.codes.${probe.code}`, {}, probe.code.replaceAll("_", " "));
  const detail = probe.detail || {};
  if (detail.address) return `${base}: ${detail.address}`;
  if (detail.latency_ms != null) return `${base} · ${detail.latency_ms} ms`;
  if (detail.interface) return `${base} · ${detail.interface}`;
  if (detail.age_seconds != null) return `${base} · ${detail.age_seconds}s`;
  return base;
}

export function renderDiagnostics(slice = getSlice("diagnostics")) {
  const run = slice.data;
  const statuses = segmentStatuses(run);
  document.querySelectorAll("[data-diagnostic-node]").forEach((node) => {
    const status = statuses.nodes[node.dataset.diagnosticNode];
    node.dataset.status = status;
    node.querySelector(".diagnostics-node-status").textContent = statusText(status);
  });
  document.querySelectorAll("[data-diagnostic-segment]").forEach((link) => {
    const status = statuses.segments[link.dataset.diagnosticSegment];
    link.dataset.status = status;
    link.querySelector(".diagnostics-link-icon").textContent = statusIcon(status);
    link.setAttribute("aria-label", `${statusText(status)}. ${t("diagnostics.details.toggle", {}, "Show troubleshooting details")}`);
    link.setAttribute("aria-expanded", String(expandedSegment === link.dataset.diagnosticSegment));
  });
  const summary = document.querySelector("#connection-diagnostics-summary");
  summary.textContent = slice.error
    ? t("diagnostics.summary.error", {}, "The connection test could not be completed.")
    : run
      ? t(`diagnostics.summary.${run.status}`, {}, statusText(run.status))
      : t("diagnostics.summary.ready", {}, "Ready to test the connection.");
  const details = document.querySelector("#diagnostics-details");
  const probes = (run?.probes || []).filter((probe) => probe.segment === expandedSegment);
  details.hidden = !expandedSegment;
  details.replaceChildren(...probes.map((probe) => {
    const item = document.createElement("article");
    item.className = "diagnostics-detail";
    item.dataset.status = probe.status;
    const heading = document.createElement("strong");
    heading.textContent = t(`diagnostics.probes.${probe.id}`, {}, probe.id.replaceAll("_", " "));
    const status = document.createElement("span");
    status.textContent = statusText(probe.status);
    const description = document.createElement("p");
    description.textContent = detailText(probe);
    item.append(heading, status, description);
    return item;
  }));
  document.querySelector("#diagnostics-run").disabled = Boolean(
    run && !TERMINAL.has(run.status),
  );
}

async function pollRun(runId) {
  window.clearTimeout(pollTimer);
  try {
    const run = await api(`/api/diagnostics/connection-runs/${runId}`, { deduplicate: false });
    updateSlice("diagnostics", { data: run, loading: false, error: null, updatedAt: Date.now() });
    if (!TERMINAL.has(run.status)) {
      pollTimer = window.setTimeout(() => pollRun(runId), 500);
    }
  } catch (error) {
    updateSlice("diagnostics", { loading: false, error: error.code || "request_failed" });
  }
}

export async function runConnectionDiagnostics() {
  window.clearTimeout(pollTimer);
  updateSlice("diagnostics", { data: null, loading: true, error: null });
  try {
    const run = await postJson("/api/diagnostics/connection-runs");
    hasRun = true;
    updateSlice("diagnostics", { data: run, loading: false, error: null });
    await pollRun(run.run_id);
  } catch (error) {
    updateSlice("diagnostics", { loading: false, error: error.code || "request_failed" });
  }
}

async function runAction(button) {
  const action = button.dataset.diagnosticAction;
  const target = ["ping", "dns"].includes(action)
    ? document.querySelector("#diagnostics-target").value.trim()
    : null;
  const resultElement = document.querySelector("#diagnostics-action-result");
  document.querySelectorAll("[data-diagnostic-action]").forEach((item) => { item.disabled = true; });
  resultElement.textContent = t("diagnostics.actions.running", {}, "Running test…");
  try {
    const result = await postJson(
      `/api/diagnostics/actions/${action}`,
      { target },
      { timeoutMilliseconds: action === "speedtest" ? 130000 : 15000 },
    );
    resultElement.dataset.status = result.status;
    resultElement.textContent = detailText(result);
  } catch {
    resultElement.dataset.status = "failed";
    resultElement.textContent = t("diagnostics.actions.failed", {}, "The test could not be completed.");
  } finally {
    document.querySelectorAll("[data-diagnostic-action]").forEach((item) => { item.disabled = false; });
  }
}

export function initialiseDiagnostics() {
  if (initialised) return;
  initialised = true;
  subscribe("diagnostics", renderDiagnostics, { immediate: true });
  subscribe("auth", (auth) => {
    if (auth.data?.authenticated) return;
    hasRun = false;
    expandedSegment = null;
    window.clearTimeout(pollTimer);
  });
  document.querySelector("#diagnostics-run").addEventListener("click", runConnectionDiagnostics);
  document.querySelectorAll("[data-diagnostic-segment]").forEach((link) => {
    link.addEventListener("click", () => {
      expandedSegment = expandedSegment === link.dataset.diagnosticSegment
        ? null
        : link.dataset.diagnosticSegment;
      renderDiagnostics();
    });
  });
  document.querySelectorAll("[data-diagnostic-action]").forEach((button) => {
    button.addEventListener("click", () => runAction(button));
  });
  window.addEventListener("exitlane:viewchange", (event) => {
    if (event.detail.view === "diagnostics" && !hasRun) runConnectionDiagnostics();
  });
  window.addEventListener("exitlane:languagechange", () => renderDiagnostics());
  document.querySelectorAll(".diagnostics-node [data-lucide-icon]").forEach((icon) => {
    renderIcon(icon, icon.dataset.lucideIcon);
  });
}
