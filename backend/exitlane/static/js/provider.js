import { api, postJson } from "./api.js";
import { appState, getSlice, subscribe, updateSlice } from "./state.js";
import { refreshProviderState } from "./lifecycle.js";
import {
  clearInlineError,
  select,
  setBusy,
  setStatusPill,
  showInlineError,
  showMessage,
} from "./ui.js";
import { refreshSetup } from "./wizard.js";
import { t } from "./i18n.js";

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

  renderVpnView(status);
}

function renderVpnView(status) {
  const runtimeError = select("#vpn-runtime-error");
  runtimeError.hidden = !status.error_code;
  runtimeError.textContent = status.error_code
    ? t(`provider.errors.${status.error_code}`, {}, t("provider.errors.status_unavailable", {}, "VPN status is unavailable."))
    : "";
  setStatusPill(
    select("#connection-state"),
    status.connected
      ? t("provider.status.connected", {}, "Connected")
      : status.available === false
        ? t("provider.status.unavailable", {}, "Unavailable")
        : t("provider.status.disconnected", {}, "Disconnected"),
    status.connected ? "success" : status.available === false ? "danger" : "neutral",
  );

  select("#metric-country").textContent = status.country || "—";
  select("#metric-city").textContent = status.city || "—";
  select("#metric-server").textContent = status.server || "—";
  select("#metric-ip").textContent = status.external_ip || "—";
  select("#metric-latency").textContent = status.latency_ms == null ? "—" : `${status.latency_ms} ms`;
}

let vpnCountries = [];
let quickCountryCodes = [];

function countryCard(country) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `country-card${country.is_connected ? " active" : ""}`;
  button.dataset.countryCode = country.country_code;
  button.setAttribute("aria-pressed", String(country.is_connected));
  button.disabled = appState.provider?.available === false;
  const latency = country.latency_ms == null
    ? t("provider.country_selection.measuring", {}, "Measuring…")
    : t("provider.country_selection.latency_ms", { latency: country.latency_ms }, `${country.latency_ms} ms`);
  const state = country.is_connected
    ? t("provider.country_selection.connected_latency", { latency }, `Connected · ${latency}`)
    : latency;
  const flag = document.createElement("span");
  flag.textContent = country.flag;
  const name = document.createElement("strong");
  name.className = "country-name";
  name.textContent = country.name;
  const detail = document.createElement("span");
  detail.className = "country-latency";
  detail.textContent = state;
  button.append(flag, name, detail);
  button.addEventListener("click", () => connectCountry(country.country_code, button));
  return button;
}

function renderCountries() {
  const quick = select("#quick-countries");
  const all = select("#country-list");
  const query = select("#country-search").value.trim().toLocaleLowerCase("nl");
  quick.replaceChildren(...quickCountryCodes.map((code) => vpnCountries.find((country) => country.country_code === code)).filter(Boolean).map(countryCard));
  all.replaceChildren(...vpnCountries.filter((country) => country.name.toLocaleLowerCase("nl").includes(query)).map(countryCard));
}

async function refreshCountries() {
  const result = await api("/api/vpn/countries", { deduplicate: false });
  vpnCountries = result.countries || [];
  quickCountryCodes = result.quick_country_codes || [];
  renderCountries();
}

async function connectCountry(countryCode, button) {
  if (["connecting", "disconnecting"].includes(getSlice("providerAction").state)) return;
  setBusy(button, true, t("provider.action.connecting", {}, "Connecting…"));
  updateSlice("providerAction", { state: "connecting", target: countryCode, error: null });
  try {
    const result = await postJson("/api/vpn/connect", { country_code: countryCode });
    if (!result.success) throw new Error("connect_failed");
    await refreshProviderState({ deduplicate: false });
    await refreshCountries();
    showMessage(t("provider.notifications.country_connected", { server: result.server || countryCode }, `Connected to ${result.server || countryCode}.`), "success");
  } catch {
    showMessage(t("provider.notifications.connect_failed", { target: countryCode }, `Could not connect to ${countryCode}.`), "error");
  } finally {
    updateSlice("providerAction", { state: "idle" });
    setBusy(button, false);
  }
}

async function remeasureCountries() {
  const button = select("#remeasure-countries");
  setBusy(button, true, t("provider.country_selection.measuring", {}, "Measuring…"));
  try {
    await Promise.all(quickCountryCodes.map((code) => postJson(`/api/vpn/countries/${code}/measure`)));
    await refreshCountries();
  } catch {
    showMessage(t("provider.country_selection.measure_failed", {}, "Not all latency values could be measured."), "error");
  } finally {
    setBusy(button, false);
  }
}

async function measureMissingCountries() {
  const missing = quickCountryCodes.filter((code) => {
    const country = vpnCountries.find((item) => item.country_code === code);
    return country && country.latency_measured_at == null;
  });
  if (!missing.length) return;
  await Promise.allSettled(missing.map((code) => postJson(`/api/vpn/countries/${code}/measure`)));
  await refreshCountries();
}

async function reconnectCountry() {
  const current = vpnCountries.find((country) => country.is_connected)
    || vpnCountries.find((country) => country.is_recent);
  if (current) await connectCountry(current.country_code, select("#reconnect-button"));
}

function setProviderInstallLogExpanded(expanded) {
  const log = select("#provider-install-log");
  const button = select("#provider-install-log-toggle");

  log.hidden = !expanded;
  button.hidden = false;

  button.setAttribute(
    "aria-expanded",
    String(expanded),
  );

  button.textContent = expanded
    ? "Installatielog verbergen"
    : "Installatielog tonen";
}

function toggleProviderInstallLog() {
  const log = select("#provider-install-log");

  setProviderInstallLogExpanded(log.hidden);
}

export async function refreshProvider() {
  return refreshProviderState();
}

export function initialiseProviderState() {
  const render = (slice) => {
    if (slice.data) renderProviderStatus(slice.data);
  };
  const unsubscribe = subscribe("provider", render, { immediate: true });
  window.addEventListener("exitlane:languagechange", () => render(getSlice("provider")));
  return unsubscribe;
}

let installPollTimer = null;
let controlsInitialised = false;

async function installProvider() {
  const button = select("#provider-install");

  setBusy(
  button,
  true,
  t("busy.installing", {}, "Installing…"),
);
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

export async function restoreInstallStatus() {
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

  setBusy(
  button,
  true,
  t("busy.applying", {}, "Applying…"),
);
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

      showMessage(
  t(
    "messages.gateway_settings_applied",
    {},
    "Gateway settings applied.",
  ),
);
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

function selectLoginMethod(method) {
  document
    .querySelectorAll("[data-login-method]")
    .forEach((button) => {
      const selected = button.dataset.loginMethod === method;

      button.classList.toggle("active", selected);
      button.setAttribute("aria-selected", String(selected));
    });

  select("#login-panel-token").hidden = method !== "token";
  select("#login-panel-browser").hidden = method !== "browser";
}

async function startBrowserLogin() {
  const button = select("#browser-login-start");

  setBusy(
  button,
  true,
  t(
    "busy.loading_login_link",
    {},
    "Loading login link…",
  ),
);
  clearInlineError();

  try {
    const result = await postJson(
      "/api/providers/nordvpn/login/browser/start",
    );

    if (!result.ok || !result.login_url) {
      throw new Error(
        result.message ||
          result.stderr ||
          "Aanmeldlink kon niet worden opgehaald.",
      );
    }

    select("#browser-login-url").value = result.login_url;
    select("#browser-login-open").href = result.login_url;
    select("#browser-login-instruction").hidden = false;

    showMessage(
  t(
    "messages.login_link_ready",
    {},
    "The NordVPN login link is ready.",
  ),
);
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

async function copyBrowserLoginUrl() {
  const url = select("#browser-login-url").value;

  try {
    await navigator.clipboard.writeText(url);
    showMessage(
  t(
    "messages.login_link_copied",
    {},
    "Login link copied.",
  ),
);
  } catch {
    showMessage(
  t(
    "messages.copy_link_manually",
    {},
    "Select and copy the link manually.",
  ),
  "error",
);
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
  setBusy(
  button,
  true,
  t("busy.signing_in", {}, "Signing in…"),
);
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
  setBusy(
  button,
  true,
  t("busy.connecting", {}, "Connecting…"),
);
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

async function disconnectProvider() {
  if (["connecting", "disconnecting"].includes(getSlice("providerAction").state)) return;
  const button = select("#disconnect-button");
  updateSlice("providerAction", { state: "disconnecting", target: null, error: null });
  setBusy(button, true, t("provider.action.disconnecting", {}, "Disconnecting…"));
  const progress = showMessage(t("provider.notifications.disconnecting", {}, "Disconnecting…"), "info", { id: "provider-action", duration: null });
  try {
    const result = await postJson("/api/vpn/disconnect");
    if (!result.ok) throw new Error("disconnect_failed");
    const status = await refreshProviderState({ deduplicate: false });
    if (status.connected) throw new Error("disconnect_failed");
    updateSlice("providerAction", { state: "idle", error: null });
    progress.close();
    showMessage(t("provider.notifications.disconnected", {}, "Disconnected."), "success");
  } catch {
    updateSlice("providerAction", { state: "failed", error: "disconnect_failed" });
    progress.close();
    showMessage(t("provider.notifications.disconnect_failed", {}, "Could not disconnect."), "error");
  } finally {
    setBusy(button, false);
    if (getSlice("providerAction").state === "failed") updateSlice("providerAction", { state: "idle" });
  }
}
export function initialiseProviderControls() {
  if (controlsInitialised) return;
  controlsInitialised = true;
  select("#provider-install").addEventListener(
    "click",
    installProvider,
  );

  select("#provider-defaults").addEventListener(
    "click",
    applyDefaults,
  );

  select("#token-form").addEventListener(
    "submit",
    loginWithToken,
  );

  select("#callback-form").addEventListener(
    "submit",
    loginWithCallback,
  );

  select("#disconnect-button").addEventListener(
    "click",
    disconnectProvider,
  );
  select("#reconnect-button").addEventListener("click", reconnectCountry);
  select("#remeasure-countries").addEventListener("click", remeasureCountries);
  select("#country-search").addEventListener("input", renderCountries);
  refreshCountries()
    .then(measureMissingCountries)
    .catch(() => showMessage(t("provider.country_selection.load_failed", {}, "Countries could not be loaded."), "error"));

  document
    .querySelectorAll("[data-login-method]")
    .forEach((button) => {
      button.addEventListener("click", () => {
        selectLoginMethod(button.dataset.loginMethod);
      });
    });

  select("#browser-login-start").addEventListener(
    "click",
    startBrowserLogin,
  );

  select("#browser-login-copy").addEventListener(
    "click",
    copyBrowserLoginUrl,
  );

select("#provider-install-log-toggle").addEventListener(
  "click",
  toggleProviderInstallLog,
);
}
