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

async function installProvider() {
  const button = select("#provider-install");
  setBusy(button, true, "Installeren…");
  clearInlineError();

  try {
    const result = await postJson("/api/providers/nordvpn/install");
    showMessage(
      result.message || result.stdout || result.stderr || "Installatie afgerond.",
    );
    await Promise.all([refreshProvider(), refreshSetup()]);
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

async function applyDefaults() {
  const button = select("#provider-defaults");
  setBusy(button, true, "Toepassen…");
  clearInlineError();

  try {
    const result = await postJson(
      "/api/providers/nordvpn/configure-defaults",
    );

    if (result.ok) {
      showMessage("Gatewayinstellingen toegepast.");
    } else {
      const failed = (result.operations || [])
        .filter((operation) => !operation.ok)
        .map((operation) => operation.setting)
        .join(", ");

      showInlineError(
        `Niet alle providerinstellingen zijn toegepast${failed ? `: ${failed}` : "."}`,
      );
    }
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
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
}
