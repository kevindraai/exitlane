import { api, postJson } from "./api.js";
import { appState } from "./state.js";
import {
  clearInlineError,
  select,
  setBusy,
  setStatusPill,
  showInlineError,
  showMessage,
} from "./ui.js";
import { refreshSetup } from "./wizard.js";

export function renderProviderStatus(status) {
  appState.provider = status;

  const installed = Boolean(status.installed);
  const authenticated = Boolean(status.authenticated);
  const connected = Boolean(status.connected);

  if (connected) {
    setStatusPill(select("#provider-state"), "Verbonden", "success");
  } else if (authenticated) {
    setStatusPill(select("#provider-state"), "Aangemeld", "success");
  } else if (installed) {
    setStatusPill(select("#provider-state"), "Niet aangemeld", "neutral");
  } else {
    setStatusPill(select("#provider-state"), "Niet geïnstalleerd", "danger");
  }

  select("#provider-description").textContent = installed
    ? authenticated
      ? "De NordVPN Linux-client is geïnstalleerd en aangemeld."
      : "De NordVPN Linux-client is geïnstalleerd, maar nog niet aangemeld."
    : "De NordVPN Linux-client is nog niet geïnstalleerd.";

  select("#provider-install").disabled = installed;
  select("#provider-defaults").disabled = !installed;
  select("#provider-next").disabled = !authenticated;

  renderDashboard(status);
}

function renderDashboard(status) {
  setStatusPill(
    select("#connection-state"),
    status.connected ? "Verbonden" : "Niet verbonden",
    status.connected ? "success" : "neutral",
  );

  select("#metric-country").textContent = status.country || "—";
  select("#metric-city").textContent = status.city || "—";
  select("#metric-server").textContent = status.server || "—";
  select("#metric-ip").textContent = status.external_ip || "—";
}

export async function refreshProvider() {
  const response = await api("/api/providers/nordvpn/status");
  renderProviderStatus(response.status);
  return response.status;
}

let installPollTimer = null;

async function installProvider() {
  const button = select("#provider-install");

  setBusy(button, true, "Installeren…");
  clearInlineError();

  select("#provider-install-progress").hidden = false;
  select("#provider-install-log").textContent = "";
  select("#provider-install-message").textContent =
    "NordVPN-installatie wordt gestart.";

  setStatusPill(
    select("#provider-install-state"),
    "Starten",
    "neutral",
  );

  try {
    const result = await postJson(
      "/api/providers/nordvpn/install",
    );

    if (!result.ok) {
      throw new Error(
        result.message || "Installatie kon niet worden gestart.",
      );
    }

    await pollInstallStatus();
  } catch (error) {
    showInlineError(error.message);
    setBusy(button, false);

    setStatusPill(
      select("#provider-install-state"),
      "Mislukt",
      "danger",
    );
  }
}

async function pollInstallStatus() {
  window.clearTimeout(installPollTimer);

  try {
    const status = await api(
      "/api/providers/nordvpn/install/status",
    );

    select("#provider-install-progress").hidden = false;
    select("#provider-install-message").textContent =
      status.message || "Installatie wordt uitgevoerd.";

    select("#provider-install-log").textContent =
      (status.logs || []).join("\n");

    const logElement = select("#provider-install-log");
    logElement.scrollTop = logElement.scrollHeight;

    if (status.running) {
      setStatusPill(
        select("#provider-install-state"),
        "Bezig",
        "neutral",
      );

      installPollTimer = window.setTimeout(
        pollInstallStatus,
        1000,
      );
      return;
    }

    setBusy(select("#provider-install"), false);

    if (status.finished && status.ok) {
      setStatusPill(
        select("#provider-install-state"),
        "Geslaagd",
        "success",
      );

      showMessage(
        status.message || "NordVPN is geïnstalleerd.",
      );

      await Promise.all([
        refreshProvider(),
        refreshSetup(),
      ]);
      return;
    }

    if (status.finished) {
      setStatusPill(
        select("#provider-install-state"),
        "Mislukt",
        "danger",
      );

      showInlineError(
        status.message || "NordVPN-installatie mislukt.",
      );
    }
  } catch (error) {
    setBusy(select("#provider-install"), false);

    setStatusPill(
      select("#provider-install-state"),
      "Statusfout",
      "danger",
    );

    showInlineError(error.message);
  }
}

async function restoreInstallStatus() {
  try {
    const status = await api(
      "/api/providers/nordvpn/install/status",
    );

    if (status.running || status.finished) {
      select("#provider-install-progress").hidden = false;
      await pollInstallStatus();
    }
  } catch {
    // Er is nog geen installatiejob of de status is niet beschikbaar.
  }
}

async function applyDefaults() {
  const button = select("#provider-defaults");
  const resultPanel = select("#provider-defaults-result");
  const resultList = select("#provider-defaults-list");

  setBusy(button, true, "Toepassen…");
  clearInlineError();

  resultPanel.hidden = false;
  resultList.innerHTML = "";

  setStatusPill(
    select("#provider-defaults-state"),
    "Bezig",
    "neutral",
  );

  try {
    const result = await postJson(
      "/api/providers/nordvpn/configure-defaults",
    );

    const operations = result.operations || [];

    resultList.innerHTML = operations
      .map((operation) => {
        const label = formatSettingName(operation.setting);
        const stateClass = operation.ok
          ? "success"
          : "failure";
        const stateLabel = operation.ok
          ? "Toegepast"
          : "Mislukt";

        return `
          <div class="settings-result-item">
            <span>${label}</span>
            <span class="${stateClass}">
              ${operation.ok ? "✓" : "✕"} ${stateLabel}
            </span>
          </div>
        `;
      })
      .join("");

    if (result.ok) {
      setStatusPill(
        select("#provider-defaults-state"),
        "Toegepast",
        "success",
      );

      showMessage("Gatewayinstellingen zijn toegepast.");
    } else {
      setStatusPill(
        select("#provider-defaults-state"),
        "Deels mislukt",
        "danger",
      );

      showInlineError(
        "Niet alle gatewayinstellingen konden worden toegepast.",
      );
    }

    await refreshProvider();
  } catch (error) {
    setStatusPill(
      select("#provider-defaults-state"),
      "Mislukt",
      "danger",
    );

    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

function formatSettingName(setting) {
  const labels = {
    technology: "Technologie: NordLynx",
    routing: "Routing",
    "lan-discovery": "LAN Discovery",
    firewall: "Firewall",
    killswitch: "Kill Switch",
    ipv6: "IPv6 uitschakelen",
    analytics: "Analytics uitschakelen",
  };

  return labels[setting] || setting;
}

async function loginWithToken(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const input = select("#nord-token");
  setBusy(button, true, "Aanmelden…");
  clearInlineError();

  try {
    const result = await postJson(
      "/api/providers/nordvpn/login/token",
      { token: input.value },
    );

    input.value = "";

    if (!result.ok) {
      throw new Error(
        result.message || result.stderr || "NordVPN-aanmelding mislukt.",
      );
    }

    showMessage(result.stdout || "NordVPN-aanmelding geslaagd.");
    await Promise.all([refreshProvider(), refreshSetup()]);
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

async function loginWithCallback(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setBusy(button, true, "Verwerken…");
  clearInlineError();

  try {
    const result = await postJson(
      "/api/providers/nordvpn/login/callback",
      { callback_url: select("#nord-callback").value.trim() },
    );

    if (!result.ok) {
      throw new Error(
        result.message || result.stderr || "Callback-aanmelding mislukt.",
      );
    }

    showMessage(result.stdout || "NordVPN-aanmelding geslaagd.");
    await Promise.all([refreshProvider(), refreshSetup()]);
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

async function connectProvider(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setBusy(button, true, "Verbinden…");

  try {
    const target = select("#connect-target").value.trim() || null;
    const result = await postJson(
      "/api/providers/nordvpn/connect",
      { target },
    );

    if (!result.ok) {
      throw new Error(result.stderr || result.message || "Verbinden mislukt.");
    }

    showMessage(result.stdout || "Verbonden.");
    await refreshProvider();
  } catch (error) {
    showMessage(error.message, "error");
  } finally {
    setBusy(button, false);
  }
}

async function disconnectProvider() {
  const button = select("#disconnect-button");
  setBusy(button, true, "Verbreken…");

  try {
    const result = await postJson("/api/providers/nordvpn/disconnect");

    if (!result.ok) {
      throw new Error(
        result.stderr || result.message || "Verbinding verbreken mislukt.",
      );
    }

    showMessage(result.stdout || "Verbinding verbroken.");
    await refreshProvider();
  } catch (error) {
    showMessage(error.message, "error");
  } finally {
    setBusy(button, false);
  }
}

export function initialiseProviderControls() {
  select("#provider-install").addEventListener("click", installProvider);
  select("#provider-defaults").addEventListener("click", applyDefaults);
  select("#token-form").addEventListener("submit", loginWithToken);
  select("#callback-form").addEventListener("submit", loginWithCallback);
  select("#connect-form").addEventListener("submit", connectProvider);
  select("#disconnect-button").addEventListener("click", disconnectProvider);
  restoreInstallStatus();
}
