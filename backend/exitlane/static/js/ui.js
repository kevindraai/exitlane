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

  toast.className = `toast${type === "error" ? " error" : ""}`;
  toast.textContent = message;
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
  element.textContent = label;
  element.className = `status-pill status-${state}`;
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
