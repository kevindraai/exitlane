import { api, postJson } from "./api.js";
import { t } from "./i18n.js";
import { getSlice, subscribe, updateSlice } from "./state.js";
import { renderIcon } from "./icons.js";

const TERMINAL = new Set(["passed", "warning", "failed"]);
const SEVERITY = ["failed", "warning", "running", "pending", "passed"];
const SPEEDTEST_INSTALLATION_PATH = "/api/diagnostics/speedtest/installation";
const SPEEDTEST_PHASES = new Set([
  "checking_system", "downloading_package", "verifying_package", "installing_package",
  "validating_installation", "completed", "unavailable", "unsupported", "failed",
]);
const SPEEDTEST_STEP_STATUSES = new Set(["pending", "active", "completed", "failed"]);
const SPEEDTEST_STATUSES = new Set(["pending", "running", "passed", "warning", "failed"]);
let initialised = false;
let pollTimer = null;
let speedtestPollTimer = null;
let speedtestInstallation = null;
let speedtestSelected = false;
let speedtestInstallationFlight = null;
let speedtestActionFlight = null;
let speedtestDialogTrigger = null;
let hasRun = false;
let expandedSegment = null;

export function speedtestInstallButtonDisabled(snapshot, inFlight = false) {
  const canInstall = Boolean(snapshot?.can_install) && snapshot?.supported_runtime !== false
    && !snapshot?.installation_in_progress && snapshot?.available !== true;
  return Boolean(inFlight) || !canInstall;
}

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

function speedtestStatusText(status) {
  return t(`diagnostics.speedtest.status.${status}`, {}, status);
}

function speedtestPhaseText(phase) {
  if (!SPEEDTEST_PHASES.has(phase)) return t("diagnostics.speedtest.phase.unknown", {}, "Installation status updated.");
  return t(`diagnostics.speedtest.phase.${phase}`, {}, phase);
}

function speedtestErrorText(errorCode) {
  if (!errorCode) return "";
  return t(`diagnostics.speedtest.errors.${errorCode}`, {}, t("diagnostics.speedtest.errors.generic", {}, "The Speedtest installation needs attention."));
}

function speedtestDescription(snapshot) {
  if (!snapshot) return t("diagnostics.speedtest.choose_description", {}, "Choose Speedtest to check whether the official Ookla CLI is available.");
  if (snapshot.status === "passed" && snapshot.available) return t("diagnostics.speedtest.installed_description", {}, "Speedtest is installed. Choose Speedtest again whenever you deliberately want to run it; no test starts automatically.");
  if (!snapshot.supported_runtime) return t("diagnostics.speedtest.unsupported_description", {}, "Managed installation is not supported on this Debian runtime or architecture.");
  if (snapshot.installation_in_progress || snapshot.status === "running") return t("diagnostics.speedtest.running_description", {}, "The official Ookla CLI installation is in progress. This page will keep checking its status.");
  if (snapshot.status === "failed") return speedtestErrorText(snapshot.error_code) || t("diagnostics.speedtest.failed_description", {}, "The official Ookla CLI installation failed. Review the status and try again after local recovery.");
  if (snapshot.error_code) return speedtestErrorText(snapshot.error_code);
  return t("diagnostics.speedtest.unavailable_description", {}, "The official Ookla CLI is not installed. You can explicitly install it after confirming the package and terms below.");
}

function renderSpeedtestInstallation() {
  const management = document.querySelector("#speedtest-management");
  if (!management) return;
  const snapshot = speedtestInstallation;
  const show = speedtestSelected || snapshot?.installation_in_progress === true;
  management.hidden = !show;
  if (!show) return;
  const description = document.querySelector("#speedtest-management-description");
  description.textContent = speedtestDescription(snapshot);
  const status = document.querySelector("#speedtest-install-status");
  const statusValue = SPEEDTEST_STATUSES.has(snapshot?.status) ? snapshot.status : "warning";
  status.hidden = !snapshot;
  status.textContent = speedtestStatusText(statusValue);
  status.dataset.status = statusValue;
  const install = document.querySelector("#speedtest-install");
  const canInstall = !speedtestInstallButtonDisabled(snapshot);
  install.hidden = !canInstall;
  install.disabled = speedtestInstallButtonDisabled(snapshot, speedtestInstallationFlight);
  const steps = document.querySelector("#speedtest-install-steps");
  const safeSteps = Array.isArray(snapshot?.steps) ? snapshot.steps : [];
  steps.hidden = safeSteps.length === 0;
  steps.replaceChildren(...safeSteps.map((item) => {
    const phase = SPEEDTEST_PHASES.has(item?.phase) ? item.phase : "unknown";
    const stepStatus = SPEEDTEST_STEP_STATUSES.has(item?.status) ? item.status : "pending";
    const li = document.createElement("li");
    li.className = "speedtest-install-step";
    li.dataset.status = stepStatus;
    const marker = document.createElement("span");
    marker.className = "speedtest-install-marker";
    marker.setAttribute("aria-hidden", "true");
    const label = document.createElement("strong");
    label.textContent = speedtestPhaseText(phase);
    li.append(marker, label);
    if (item?.error_code) {
      const error = document.createElement("small");
      error.textContent = speedtestErrorText(item.error_code);
      li.append(error);
    }
    return li;
  }));
  const live = document.querySelector("#speedtest-install-live");
  live.textContent = snapshot
    ? `${speedtestStatusText(statusValue)}. ${speedtestPhaseText(snapshot.phase)}${snapshot.error_code ? `: ${speedtestErrorText(snapshot.error_code)}` : ""}`
    : "";
}

function scheduleSpeedtestPoll(snapshot) {
  window.clearTimeout(speedtestPollTimer);
  if (!snapshot?.installation_in_progress && snapshot?.status !== "running") return;
  speedtestPollTimer = window.setTimeout(() => refreshSpeedtestInstallation({ poll: true }), 800);
}

async function refreshSpeedtestInstallation({ poll = false } = {}) {
  if (speedtestInstallationFlight && !poll) return speedtestInstallationFlight;
  const request = api(SPEEDTEST_INSTALLATION_PATH, { deduplicate: false });
  if (!poll) speedtestInstallationFlight = request;
  try {
    speedtestInstallation = await request;
    if (speedtestInstallation?.installation_in_progress || speedtestInstallation?.status === "running") {
      speedtestSelected = true;
    }
    renderSpeedtestInstallation();
    scheduleSpeedtestPoll(speedtestInstallation);
    return speedtestInstallation;
  } catch (error) {
    if (!poll) {
      speedtestInstallation = { status: "warning", error_code: error.code || "request_failed", supported_runtime: true, can_install: false };
      renderSpeedtestInstallation();
    }
    return null;
  } finally {
    if (!poll) {
      speedtestInstallationFlight = null;
      renderSpeedtestInstallation();
    }
  }
}

function closeSpeedtestDialog(dialog) {
  if (dialog?.open) dialog.close();
}

function restoreSpeedtestDialogFocus() {
  const trigger = speedtestDialogTrigger;
  speedtestDialogTrigger = null;
  if (trigger && typeof trigger.focus === "function") trigger.focus();
}

function openSpeedtestDialog(dialog, trigger) {
  speedtestDialogTrigger = trigger;
  const form = dialog.querySelector("form");
  form.reset();
  dialog.querySelectorAll(".inline-error").forEach((error) => { error.hidden = true; error.textContent = ""; });
  dialog.showModal();
}

async function selectSpeedtest(button) {
  if (speedtestActionFlight || speedtestInstallationFlight) return;
  speedtestSelected = true;
  button.disabled = true;
  const snapshot = await refreshSpeedtestInstallation();
  button.disabled = false;
  if (!snapshot) return;
  if (snapshot.available === true) {
    openSpeedtestDialog(document.querySelector("#speedtest-run-dialog"), button);
  }
}

async function installSpeedtest() {
  if (speedtestInstallationFlight) return;
  const form = document.querySelector("#speedtest-install-form");
  if (!form.reportValidity()) return;
  const confirm = document.querySelector("#speedtest-install-confirm");
  const cancel = document.querySelector("#speedtest-install-cancel");
  confirm.disabled = true;
  cancel.disabled = true;
  closeSpeedtestDialog(document.querySelector("#speedtest-install-dialog"));
  const request = postJson(SPEEDTEST_INSTALLATION_PATH, {
    confirm_package_change: true,
    confirm_personal_noncommercial: true,
    accept_license: true,
    accept_gdpr: true,
  });
  speedtestInstallationFlight = request;
  try {
    speedtestInstallation = await request;
    speedtestSelected = true;
    renderSpeedtestInstallation();
    scheduleSpeedtestPoll(speedtestInstallation);
  } catch (error) {
    speedtestInstallation = { status: "failed", error_code: error.code || "installation_failed", supported_runtime: true, can_install: true };
    renderSpeedtestInstallation();
  } finally {
    speedtestInstallationFlight = null;
    renderSpeedtestInstallation();
    confirm.disabled = false;
    cancel.disabled = false;
  }
}

async function runSpeedtest() {
  if (speedtestActionFlight) return;
  const form = document.querySelector("#speedtest-run-form");
  if (!form.reportValidity()) return;
  const confirm = document.querySelector("#speedtest-run-confirm");
  const cancel = document.querySelector("#speedtest-run-cancel");
  confirm.disabled = true;
  cancel.disabled = true;
  closeSpeedtestDialog(document.querySelector("#speedtest-run-dialog"));
  const resultElement = document.querySelector("#diagnostics-action-result");
  document.querySelectorAll("[data-diagnostic-action]").forEach((item) => { item.disabled = true; });
  resultElement.textContent = t("diagnostics.actions.running", {}, "Running test…");
  const request = postJson("/api/diagnostics/actions/speedtest", {
    confirm_personal_noncommercial: true,
    accept_license: true,
    accept_gdpr: true,
    confirm_bandwidth: true,
  }, { timeoutMilliseconds: 130000 });
  speedtestActionFlight = request;
  try {
    const result = await request;
    resultElement.dataset.status = result.status;
    resultElement.textContent = detailText(result);
  } catch {
    resultElement.dataset.status = "failed";
    resultElement.textContent = t("diagnostics.actions.failed", {}, "The test could not be completed.");
  } finally {
    speedtestActionFlight = null;
    confirm.disabled = false;
    cancel.disabled = false;
    document.querySelectorAll("[data-diagnostic-action]").forEach((item) => { item.disabled = false; });
  }
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
  renderSpeedtestInstallation();
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
  if (action === "speedtest") {
    await selectSpeedtest(button);
    return;
  }
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
    if (auth.data?.authenticated) {
      refreshSpeedtestInstallation();
      return;
    }
    hasRun = false;
    expandedSegment = null;
    window.clearTimeout(pollTimer);
    window.clearTimeout(speedtestPollTimer);
    speedtestInstallation = null;
    speedtestSelected = false;
    renderSpeedtestInstallation();
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
  const installDialog = document.querySelector("#speedtest-install-dialog");
  const runDialog = document.querySelector("#speedtest-run-dialog");
  document.querySelector("#speedtest-install").addEventListener("click", (event) => {
    if (speedtestInstallation?.can_install && !speedtestInstallation?.installation_in_progress) {
      openSpeedtestDialog(installDialog, event.currentTarget);
    }
  });
  document.querySelector("#speedtest-install-form").addEventListener("submit", (event) => {
    event.preventDefault();
    installSpeedtest();
  });
  document.querySelector("#speedtest-run-form").addEventListener("submit", (event) => {
    event.preventDefault();
    runSpeedtest();
  });
  document.querySelectorAll("#speedtest-install-cancel, #speedtest-run-cancel").forEach((button) => {
    button.addEventListener("click", () => closeSpeedtestDialog(button.closest("dialog")));
  });
  [installDialog, runDialog].forEach((dialog) => {
    dialog.addEventListener("close", restoreSpeedtestDialogFocus);
  });
  window.addEventListener("exitlane:viewchange", (event) => {
    if (event.detail.view === "diagnostics" && !hasRun) runConnectionDiagnostics();
  });
  window.addEventListener("exitlane:languagechange", () => {
    renderDiagnostics();
    renderSpeedtestInstallation();
  });
  document.querySelectorAll(".diagnostics-node [data-lucide-icon]").forEach((icon) => {
    renderIcon(icon, icon.dataset.lucideIcon);
  });
}
