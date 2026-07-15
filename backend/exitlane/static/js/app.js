import { api } from "./api.js";
import {
  frontendConfig,
  loadPublicConfig,
} from "./config.js";
import { initialiseNotificationControls } from "./notifications.js";
import {
  initialiseProviderControls,
  refreshProvider,
} from "./provider.js";
import {
  select,
  setStatusPill,
  showMessage,
} from "./ui.js";
import {
  initialiseWizardNavigation,
  refreshSetup,
} from "./wizard.js";
import { initialiseWireGuardControls } from "./wireguard.js";
import { initialiseFinishControls } from "./finish.js";
import { initialiseColorScheme, } from "./theme.js";

async function refreshApplication() {
  const health = await api("/api/health");

  setStatusPill(
    select("#api-status"),
    health.ok ? "API online" : "API offline",
    health.ok ? "success" : "danger",
  );

  select("#app-version").textContent = health.version
    ? `v${health.version}`
    : "";

  await refreshProvider();

  await refreshSetup({
  runAutomaticDiagnostics: true,
  });
}

async function initialise() {
  initialiseColorScheme();
  initialiseWizardNavigation();
  initialiseProviderControls();
  initialiseWireGuardControls();
  initialiseFinishControls();
  initialiseNotificationControls();

  try {
    await loadPublicConfig();
    await refreshApplication();
  } catch (error) {
    setStatusPill(
      select("#api-status"),
      "API-fout",
      "danger",
    );

    showMessage(error.message, "error");
    return;
  }

  window.setInterval(async () => {
    try {
      await refreshProvider();
    } catch {
      setStatusPill(
        select("#connection-state"),
        "Statusfout",
        "danger",
      );
    }
  }, frontendConfig.providerRefreshIntervalSeconds * 1000);
}

initialise();
