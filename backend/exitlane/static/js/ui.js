export function select(selector) {
  return document.querySelector(selector);
}

export function selectAll(selector) {
  return [...document.querySelectorAll(selector)];
}

export function setBusy(element, busy, busyLabel = "Bezig…") {
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

export function showMessage(message, type = "info") {
  const region = select("#toast-region");
  const toast = document.createElement("div");

  toast.className = `toast${type === "error" ? " error" : ""}`;
  toast.textContent = message;
  region.appendChild(toast);

  window.setTimeout(() => {
    toast.remove();
  }, 5000);
}

export function showInlineError(message) {
  const element = select("#wizard-error");
  element.textContent = message;
  element.hidden = false;
}

export function clearInlineError() {
  const element = select("#wizard-error");
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
