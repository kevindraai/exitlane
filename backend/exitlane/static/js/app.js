import { api } from "./api.js";
import { initialiseNotificationControls } from "./notifications.js";
import {
  initialiseProviderControls,
  refreshProvider,
} from "./provider.js";
import { select, setStatusPill, showMessage } from "./ui.js";
import {
  initialiseWizardNavigation,
  refreshSetup,
} from "./wizard.js";
import { initialiseWireGuardControls } from "./wireguard.js";

async function refreshApplication() {
  try {
    const health = await api("/api/health");

    setStatusPill(
      select("#api-status"),
      health.ok ? "API online" : "API offline",
      health.ok ? "success" : "danger",
    );

    select("#app-version").textContent = health.version
      ? `v${health.version}`
      : "";

    await Promise.all([
      refreshSetup(),
      refreshProvider(),
    ]);
  } catch (error) {
    setStatusPill(select("#api-status"), "API-fout", "danger");
    showMessage(error.message, "error");
  }
}

function initialise() {
  initialiseWizardNavigation();
  initialiseProviderControls();
  initialiseWireGuardControls();
  initialiseNotificationControls();

  refreshApplication();

  window.setInterval(async () => {
    try {
      await refreshProvider();
    } catch {
      setStatusPill(select("#connection-state"), "Statusfout", "danger");
    }
  }, 5000);
}

initialise();
