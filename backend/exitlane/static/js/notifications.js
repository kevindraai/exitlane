import { postJson } from "./api.js";
import { select, setBusy, showMessage } from "./ui.js";
import { t } from "./i18n.js";

async function addWebhook(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  setBusy(
  button,
  true,
  t(
    "busy.adding",
    {},
    "Adding…",
  ),
);

  try {
    const result = await postJson("/api/notifications/webhook", {
      name: select("#webhook-name").value.trim(),
      url: select("#webhook-url").value.trim(),
    });

    showMessage(t("settings.notifications.added", { id: result.id }, `Webhook ${result.id} added.`));
    select("#webhook-url").value = "";
  } catch (error) {
    showMessage(error.message, "error");
  } finally {
    setBusy(button, false);
  }
}

export function initialiseNotificationControls() {
  select("#webhook-form").addEventListener("submit", addWebhook);
}
