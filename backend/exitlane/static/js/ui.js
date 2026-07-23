import { createIcon, statusIconName } from "./icons.js";

export const ALERT_TYPES = Object.freeze({
  SUCCESS: "success",
  INFORMATION: "information",
  WARNING: "warning",
  ERROR: "error",
});

const ALERT_ICONS = Object.freeze({
  success: "circle-check",
  information: "info",
  warning: "triangle-alert",
  error: "circle-x",
});

function normalizeAlertType(type) {
  if (type === "info") return ALERT_TYPES.INFORMATION;
  return Object.values(ALERT_TYPES).includes(type) ? type : ALERT_TYPES.INFORMATION;
}

export function renderAlert(element, message, type = ALERT_TYPES.INFORMATION) {
  if (!element) return null;
  const alertType = normalizeAlertType(type);
  const text = document.createElement("span");
  text.className = "alert-message";
  text.textContent = message;
  element.className = `alert alert-${alertType}`;
  element.dataset.alertType = alertType;
  element.setAttribute("role", alertType === ALERT_TYPES.ERROR ? "alert" : "status");
  element.replaceChildren(createIcon(ALERT_ICONS[alertType]), text);
  element.hidden = false;
  return element;
}

export function clearAlert(element) {
  if (!element) return;
  element.replaceChildren();
  element.removeAttribute("data-alert-type");
  element.hidden = true;
}

export function select(selector) {
  return document.querySelector(selector);
}

export function selectAll(selector) {
  return [...document.querySelectorAll(selector)];
}

export function setBusy(
  element,
  busy,
  busyLabel = "Working…",
) {
  if (!element) {
    return;
  }

  if (!element.dataset.originalLabel) {
    element.dataset.originalLabel = element.textContent.trim();
  }

  element.disabled = busy;
  element.textContent = busy
    ? busyLabel
    : element.dataset.originalLabel;
}

export function showMessage(message, type = "info", { id = null, duration = 5000 } = {}) {
  const region = select("#toast-region");
  const toast = id ? region.querySelector(`[data-message-id="${id}"]`) || document.createElement("div") : document.createElement("div");

  renderAlert(toast, message, type);
  toast.classList.add("toast");
  if (id) toast.dataset.messageId = id;
  if (!toast.isConnected) region.appendChild(toast);

  if (duration !== null) window.setTimeout(() => toast.remove(), duration);
  return { close: () => toast.remove() };
}

export function showInlineError(message, selector = "#wizard-error") {
  const element = select(selector);
  element.textContent = message;
  element.hidden = false;
}

export function clearInlineError(selector = "#wizard-error") {
  const element = select(selector);
  element.textContent = "";
  element.hidden = true;
}

export function setStatusPill(element, label, state = "neutral") {
  element.className = `status-pill status-${state}`;
  const text = document.createElement("span");
  text.textContent = label;
  element.replaceChildren(createIcon(statusIconName(state)), text);
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
