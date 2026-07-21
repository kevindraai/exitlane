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
} from "./navigation.js";
import {
  initialiseNotificationControls,
} from "./notifications.js";
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
import {
  initialiseWireGuardControls,
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

let apiState = "checking";
let providerRefreshTimer = null;

function scheduleProviderRefresh(intervalSeconds) {
  if (providerRefreshTimer !== null) {
    window.clearInterval(providerRefreshTimer);
  }
  frontendConfig.providerRefreshIntervalSeconds = intervalSeconds;
  providerRefreshTimer = window.setInterval(async () => {
    try {
      await refreshProvider();
    } catch {
      renderProviderStatusError();
    }
  }, intervalSeconds * 1000);
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

  await refreshSession();

  try {
    // Before setup this remains public; afterwards a session is required.
    await refreshSetup({
      runAutomaticDiagnostics: true,
    });
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    throw error;
  }

  await loadPublicConfig();

  if (!select("#view-settings").hidden) {
    await loadSettings({ force: true });
  }

  try {
    await refreshProvider();
  } catch {
    renderProviderStatusError();
  }
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
    initialiseNavigation();
    initialiseProviderControls();
    initialiseWireGuardControls();
    initialiseWireGuardManagement();
    initialiseFinishControls();
    initialiseNotificationControls();
    initialiseAuth(refreshApplication);

    await refreshApplication();
    scheduleProviderRefresh(frontendConfig.providerRefreshIntervalSeconds);
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
    scheduleProviderRefresh(event.detail.providerRefreshIntervalSeconds);
  });
}

initialise();
