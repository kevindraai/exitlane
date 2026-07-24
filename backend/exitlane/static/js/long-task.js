import { t } from "./i18n.js";

const ALLOWED_STATUSES = new Set(["pending", "active", "completed", "failed"]);

export function initialiseLongTaskDisclosure(details, label, translationPrefix) {
  const update = () => {
    details.setAttribute("aria-expanded", String(details.open));
    label.textContent = details.open
      ? t(`${translationPrefix}.hide_details`, {}, "Hide details")
      : t(`${translationPrefix}.show_details`, {}, "Show details");
  };
  details.addEventListener("toggle", update);
  update();
}

export function renderLongTask({
  details,
  list,
  liveRegion,
  steps,
  translationPrefix,
  completed,
  summary,
}) {
  list.replaceChildren(...steps.map((step) => {
    const status = ALLOWED_STATUSES.has(step.status) ? step.status : "pending";
    const item = document.createElement("li");
    item.className = "long-task-step";
    item.dataset.status = status;

    const icon = document.createElement("span");
    icon.className = "long-task-icon";
    icon.dataset.status = status;
    icon.setAttribute("aria-hidden", "true");

    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = t(`${translationPrefix}.steps.${step.phase}`, {}, step.phase);
    const state = document.createElement("small");
    state.textContent = t(`${translationPrefix}.step_status.${status}`, {}, status);
    content.append(title, state);

    if (status === "failed" && step.errorMessage) {
      const error = document.createElement("p");
      error.className = "long-task-step-error";
      error.textContent = step.errorMessage;
      content.append(error);
    }
    item.append(icon, content);
    return item;
  }));

  const active = steps.find((step) => ["active", "failed"].includes(step.status));
  liveRegion.textContent = completed
    ? summary
    : active
      ? `${t(`${translationPrefix}.steps.${active.phase}`, {}, active.phase)}: ${t(
        `${translationPrefix}.step_status.${active.status}`,
        {},
        active.status,
      )}`
      : "";

  if (completed && details.dataset.completionRendered !== "true") {
    details.open = false;
    details.setAttribute("aria-expanded", "false");
    details.dataset.completionRendered = "true";
  } else if (!completed) {
    delete details.dataset.completionRendered;
    details.open = true;
    details.setAttribute("aria-expanded", "true");
  }
}
