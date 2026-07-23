import {
  initialiseI18n,
  t,
} from "./i18n.js";
import { api } from "./api.js";
import {
  frontendConfig,
  loadPublicConfig,
} from "./config.js";
import {
  initialiseNavigation,
  setApplicationMode,
} from "./navigation.js";
import {
  initialiseNotificationControls,
} from "./notifications.js";
import {
  initialiseProviderControls,
  initialiseProviderState,
  activateAuthenticatedProviderData,
  deactivateAuthenticatedProviderData,
  refreshProvider,
  restoreInstallStatus,
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
import {
  initialiseWireGuardControls,
  loadDetectedEndpoint,
} from "./wireguard.js";
import {
  initialiseWireGuardManagement,
} from "./wireguard-management.js";
import {
  initialiseFinishControls,
} from "./finish.js";
import {
  initialiseColorScheme,
} from "./theme.js";
import {
  initialiseAuth,
  refreshSession,
  showLogin,
} from "./auth.js";
import {
  initialiseSettings,
  loadSettings,
} from "./settings.js";
import { initialiseDashboard, refreshDashboard } from "./dashboard.js";
import { createApplicationLifecycle } from "./lifecycle.js";
import { runColdStart } from "./startup.js";
import { getSlice, subscribe } from "./state.js";
import { initialiseActivity } from "./activity.js";

let apiState = "checking";
const dashboardIsActive = () =>
  getSlice("application").mode === "dashboard" &&
  getSlice("application").activeView === "dashboard";

const lifecycle = createApplicationLifecycle({ intervalSeconds: frontendConfig.providerRefreshIntervalSeconds });

function syncDashboardPolling() {
  lifecycle.sync();
}

function renderApiStatus() {
  const states = {
    checking: {
      key: "app.api_checking",
      fallback: "Checking API...",
      style: "neutral",
    },
    online: {
      key: "app.api_online",
      fallback: "API online",
      style: "success",
    },
    offline: {
      key: "app.api_offline",
      fallback: "API unavailable",
      style: "danger",
    },
  };

  const state = states[apiState];

  setStatusPill(
    select("#api-status"),
    t(
      state.key,
      {},
      state.fallback,
    ),
    state.style,
  );
}

function renderProviderStatusError() {
  setStatusPill(
    select("#connection-state"),
    t(
      "common.status_error",
      {},
      "Status error",
    ),
    "danger",
  );
}

async function refreshApplication() {
  lifecycle.stop();
  apiState = "checking";
  renderApiStatus();

  const health = await api("/api/health");

  apiState = health.ok
    ? "online"
    : "offline";

  renderApiStatus();

  select("#app-version").textContent =
    health.version
      ? `v${health.version}`
      : "";

  return runColdStart({
    refreshSession,
    setMode: setApplicationMode,
    showLogin,
    startWizard: async () => {
      await refreshSetup({ runAutomaticDiagnostics: true });
      await loadPublicConfig();
    },
    startDashboard: async () => {
      await loadPublicConfig();
      if (!select("#view-settings").hidden) await loadSettings({ force: true });
      try {
        await refreshProvider();
        await activateAuthenticatedProviderData();
      } catch {
        renderProviderStatusError();
      }
      try {
        if (dashboardIsActive()) await lifecycle.dashboard.refresh();
      } catch {
        // The dashboard exposes this failure locally while the rest of the app remains usable.
      }
      lifecycle.restart(frontendConfig.providerRefreshIntervalSeconds);
    },
  });
}

async function initialise() {
  try {
    initialiseColorScheme();
    await initialiseI18n();

    window.addEventListener(
      "exitlane:languagechange",
      renderApiStatus,
    );

    initialiseWizardNavigation();
    initialiseSettings();
    initialiseDashboard();
    initialiseActivity();
    initialiseNavigation();
    initialiseProviderControls();
    initialiseProviderState();
    initialiseWireGuardControls();
    initialiseWireGuardManagement();
    initialiseFinishControls();
    initialiseNotificationControls();
    initialiseAuth(refreshApplication);

    let activeWizardStep = null;
    subscribe("application", (application) => {
      if (application.mode !== "wizard" || application.wizardStep === activeWizardStep) return;
      activeWizardStep = application.wizardStep;
      if (activeWizardStep === 3) restoreInstallStatus();
      if (activeWizardStep === 4) loadDetectedEndpoint();
    });

    window.addEventListener("exitlane:viewchange", syncDashboardPolling);
    window.addEventListener("exitlane:modechange", syncDashboardPolling);
    window.addEventListener("exitlane:authenticationrequired", () => {
      lifecycle.stop();
      deactivateAuthenticatedProviderData();
    });
    select("#dashboard-refresh").addEventListener("click", () => lifecycle.dashboard.refresh().catch(() => {}));
    select("#dashboard-wg-refresh").addEventListener("click", () => lifecycle.wireguard.refresh().catch(() => {}));

    await refreshApplication();
  } catch (error) {
    console.error(
      "Exitlane initialization failed:",
      error,
    );

    apiState = "offline";
    renderApiStatus();

    showMessage(
      error.message ||
        "Exitlane could not be initialized.",
      "error",
    );

    return;
  }

  window.addEventListener("exitlane:settingschange", (event) => {
    frontendConfig.providerRefreshIntervalSeconds = event.detail.providerRefreshIntervalSeconds;
    lifecycle.restart(event.detail.providerRefreshIntervalSeconds);
  });
}

initialise();
