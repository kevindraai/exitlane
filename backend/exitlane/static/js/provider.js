import { api, postJson } from "./api.js";
import { appState, getSlice, subscribe, succeedRefresh, updateSlice } from "./state.js";
import { refreshProviderState } from "./lifecycle.js";
import { showView } from "./navigation.js";
import { vpnProviderAccess } from "./provider-management.js";
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
    setStatusPill(select("#provider-state"), t("provider.status.connected", {}, "Connected"), "success");
  } else if (authenticated) {
    setStatusPill(select("#provider-state"), t("provider.status.authenticated", {}, "Signed in"), "success");
  } else if (installed) {
    setStatusPill(select("#provider-state"), t("provider.status.signed_out", {}, "Signed out"), "neutral");
  } else {
    setStatusPill(select("#provider-state"), t("provider.status.not_installed", {}, "Not installed"), "danger");
  }

  select("#provider-description").textContent = installed
    ? authenticated
      ? t("provider.description.ready", {}, "The NordVPN Linux client is installed and signed in.")
      : t("provider.description.signed_out", {}, "The NordVPN Linux client is installed but signed out.")
    : t("provider.description.not_installed", {}, "The NordVPN Linux client is not installed yet.");

  select("#provider-install").disabled = installed;
  select("#provider-defaults").disabled = !installed;
  select("#provider-next").disabled = !authenticated;

  renderVpnView(status);
  renderVpnProviderAccess(status);
  reconcileCountries(status);
  const operation = status.operation || { state: status.connected ? "connected" : "idle" };
  updateSlice("providerAction", {
    state: operation.state,
    target: operation.requested_country_code || null,
    error: operation.last_error_code || null,
  });
  renderProviderControls(status, operation);
  if (shouldLoadAuthenticatedProviderData(
    getSlice("application"),
    getSlice("auth"),
    getSlice("provider"),
  )) {
    void activateAuthenticatedProviderData();
  }
}

function renderVpnProviderAccess(status) {
  const access = vpnProviderAccess(status);
  const blocker = select("#vpn-provider-blocker");
  const controls = select("#vpn-provider-controls");
  const openSettings = select("#vpn-provider-open-settings");
  const retry = select("#vpn-provider-retry");
  blocker.hidden = !access.blocked;
  blocker.dataset.state = access.state;
  controls.inert = access.blocked;
  controls.setAttribute("aria-disabled", String(access.blocked));
  openSettings.hidden = access.state !== "signed_out";
  retry.hidden = access.state !== "unavailable";

  const content = {
    signed_out: [
      t("provider.access.sign_in_required_title", {}, "NordVPN sign-in required"),
      t("provider.access.sign_in_required_description", {}, "Sign in to the local NordVPN client before selecting a country or managing the VPN connection."),
    ],
    unavailable: [
      t("provider.access.unavailable_title", {}, "NordVPN is unavailable"),
      t("provider.access.unavailable_description", {}, "Check the local NordVPN service and try again."),
    ],
    signing_in: [
      t("provider.access.signing_in_title", {}, "Signing in to NordVPN"),
      t("provider.access.busy_description", {}, "Provider management will become available when this action finishes."),
    ],
    signing_out: [
      t("provider.access.signing_out_title", {}, "Signing out of NordVPN"),
      t("provider.access.busy_description", {}, "Provider management will become available when this action finishes."),
    ],
    unknown: [
      t("provider.access.checking_title", {}, "Checking NordVPN status"),
      t("provider.access.checking_description", {}, "Provider management remains unavailable until authentication is confirmed."),
    ],
  }[access.state];
  if (content) {
    select("#vpn-provider-blocker-title").textContent = content[0];
    select("#vpn-provider-blocker-description").textContent = content[1];
  }
  if (access.blocked) suspendProviderData();
}

function renderVpnView(status) {
  const runtimeError = select("#vpn-runtime-error");
  runtimeError.hidden = !status.error_code;
  runtimeError.textContent = status.error_code
    ? t(`provider.errors.${status.error_code}`, {}, t("provider.errors.status_unavailable", {}, "VPN status is unavailable."))
    : "";
  const operation = status.operation || {};
  const operationActive = ["connecting", "disconnecting", "recovering", "measuring"].includes(operation.state);
  const operationLabel = operation.state === "recovering"
    ? t("provider.operation.recovering", {}, "Recovering NordVPN…")
    : operation.state === "measuring"
      ? t("provider.country_selection.measuring", {}, "Measuring…")
    : operation.state === "connecting"
      ? t("provider.operation.connecting_country", { country: operation.requested_country_code || "" }, "Connecting…")
      : operation.state === "disconnecting"
        ? t("provider.action.disconnecting", {}, "Disconnecting…")
        : null;
  setStatusPill(
    select("#connection-state"),
    operationActive
      ? operationLabel
      : status.connected
      ? t("provider.status.connected", {}, "Connected")
      : status.available === false
        ? t("provider.status.unavailable", {}, "Unavailable")
        : t("provider.status.disconnected", {}, "Disconnected"),
    operationActive ? "neutral" : status.connected ? "success" : status.available === false ? "danger" : "neutral",
  );

  select("#metric-country").textContent = status.country || "—";
  select("#metric-city").textContent = status.city || "—";
  select("#metric-server").textContent = status.server || "—";
  select("#metric-ip").textContent = status.external_ip || "—";
  select("#metric-latency").textContent = status.latency_ms == null ? "—" : `${status.latency_ms} ms`;
}

let vpnCountries = [];
let quickCountryCodes = [];
let countryLoadPromise = null;
let countryLoadController = null;
let countryLoadGeneration = 0;
let countriesLoaded = false;

export function shouldLoadAuthenticatedProviderData(application, auth, providerSlice) {
  return application.mode === "dashboard"
    && application.activeView === "vpn"
    && auth.data?.authenticated === true
    && vpnProviderAccess(providerSlice?.data || {}).state === "signed_in"
    && vpnProviderAccess(providerSlice?.data || {}).canSelectLocation;
}

function reconcileCountries(status) {
  const operation = status.operation || {};
  vpnCountries = vpnCountries.map((country) => ({
    ...country,
    is_connected: isCountryConnected(country.country_code, status, operation),
  }));
  if (vpnCountries.length) renderCountries();
}

export function isCountryConnected(countryCode, status, operation = status.operation || {}) {
  const active = ["connecting", "disconnecting", "recovering", "measuring"].includes(operation.state);
  return !active && status.connected === true && status.country_code === countryCode;
}

function renderProviderControls(status = getSlice("provider").data || {}, operation = status.operation || {}) {
  const controls = providerControlState(status, operation);
  select("#reconnect-button").disabled = controls.reconnectDisabled;
  select("#disconnect-button").disabled = controls.disconnectDisabled;
  select("#remeasure-countries").disabled = controls.measureDisabled;
}

export function providerControlState(status, operation = status.operation || {}) {
  const active = ["connecting", "disconnecting", "recovering", "measuring"].includes(operation.state);
  const access = vpnProviderAccess(status);
  return {
    reconnectDisabled: active || !access.canSelectLocation,
    disconnectDisabled: active || !access.canDisconnect,
    measureDisabled: active || !access.canSelectLocation,
  };
}

function countryCard(country) {
  const button = document.createElement("button");
  button.type = "button";
  const action = getSlice("providerAction");
  const active = ["connecting", "disconnecting", "recovering", "measuring"].includes(action.state);
  const requested = action.target === country.country_code;
  button.className = `country-card${country.is_connected ? " country-card--active" : ""}${requested && active ? " country-card--connecting" : ""}`;
  button.dataset.countryCode = country.country_code;
  button.setAttribute("aria-pressed", String(country.is_connected));
  button.disabled = active || !vpnProviderAccess(appState.provider || {}).canSelectLocation;
  const latency = country.latency_ms == null
    ? t("provider.country_selection.measuring", {}, "Measuring…")
    : t("provider.country_selection.latency_ms", { latency: country.latency_ms }, `${country.latency_ms} ms`);
  const flag = document.createElement("span");
  flag.className = "country-card__flag";
  flag.setAttribute("aria-hidden", "true");
  flag.textContent = country.flag;
  const name = document.createElement("span");
  name.className = "country-card__name";
  name.textContent = country.name;
  const detail = document.createElement("span");
  detail.className = "country-card__latency";
  detail.textContent = latency;
  const status = document.createElement("span");
  status.className = "country-card__status";
  status.textContent = requested && action.state === "recovering"
    ? t("provider.operation.recovering", {}, "Recovering NordVPN…")
    : requested && action.state === "connecting"
      ? t("provider.action.connecting", {}, "Connecting…")
      : country.is_connected
        ? t("provider.status.connected", {}, "Connected")
        : country.is_recent
          ? t("provider.country_selection.last_used", {}, "Last used")
          : "";
  button.append(flag, name, detail, status);
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

async function refreshCountries({ signal } = {}) {
  const result = await api("/api/vpn/countries", { deduplicate: false, signal });
  vpnCountries = result.countries || [];
  quickCountryCodes = result.quick_country_codes || [];
  if (result.vpn) succeedRefresh("provider", result.vpn);
  renderCountries();
}

export function activateAuthenticatedProviderData() {
  if (!shouldLoadAuthenticatedProviderData(
    getSlice("application"),
    getSlice("auth"),
    getSlice("provider"),
  )) {
    return Promise.resolve(false);
  }
  if (countriesLoaded) return Promise.resolve(true);
  if (!countryLoadPromise) {
    const generation = countryLoadGeneration;
    const controller = new AbortController();
    countryLoadController = controller;
    countryLoadPromise = refreshCountries({ signal: controller.signal })
      .then(() => measureMissingCountries({ signal: controller.signal }))
      .then(() => {
        if (
          generation !== countryLoadGeneration
          || !shouldLoadAuthenticatedProviderData(
            getSlice("application"),
            getSlice("auth"),
            getSlice("provider"),
          )
        ) return false;
        countriesLoaded = true;
        return true;
      })
      .catch((error) => {
        if (
          error.code === "aborted"
          || generation !== countryLoadGeneration
          || !shouldLoadAuthenticatedProviderData(
          getSlice("application"),
          getSlice("auth"),
          getSlice("provider"),
          )
        ) return false;
        showMessage(
          t("provider.country_selection.load_failed", {}, "Countries could not be loaded."),
          "error",
        );
        throw error;
      })
      .finally(() => {
        if (generation === countryLoadGeneration) {
          countryLoadPromise = null;
          countryLoadController = null;
        }
      });
  }
  return countryLoadPromise;
}

function suspendProviderData() {
  if (!countriesLoaded && !countryLoadPromise && !vpnCountries.length) return;
  countryLoadGeneration += 1;
  countryLoadController?.abort("provider-authentication-ended");
  stopActionPolling();
  vpnCountries = [];
  quickCountryCodes = [];
  countryLoadPromise = null;
  countryLoadController = null;
  countriesLoaded = false;
  select("#quick-countries")?.replaceChildren();
  select("#country-list")?.replaceChildren();
}

export function deactivateAuthenticatedProviderData() {
  countryLoadGeneration += 1;
  countryLoadController?.abort("authentication-ended");
  stopActionPolling();
  vpnCountries = [];
  quickCountryCodes = [];
  countryLoadPromise = null;
  countryLoadController = null;
  countriesLoaded = false;
}

function applyVpnSnapshot(vpn) {
  if (vpn) succeedRefresh("provider", vpn);
}

function connectionErrorMessage(errorCode, countryCode) {
  if (errorCode === "provider_authentication_required") {
    return t(
      "provider.errors.provider_authentication_required",
      {},
      "Sign in to NordVPN before managing the VPN connection.",
    );
  }
  if (errorCode === "vpn_connect_timeout") {
    const country = vpnCountries.find((item) => item.country_code === countryCode)?.name || countryCode;
    return t("provider.errors.vpn_connect_timeout", { country }, `Connection to ${country} took too long.`);
  }
  if (errorCode === "provider_recovery_rate_limited") {
    return t("provider.errors.provider_recovery_rate_limited", {}, "NordVPN recovery is temporarily rate limited.");
  }
  return t("provider.notifications.connect_failed", { target: countryCode }, `Could not connect to ${countryCode}.`);
}

let actionPollTimer = null;
let actionPollInFlight = false;

function stopActionPolling() {
  window.clearTimeout(actionPollTimer);
  actionPollTimer = null;
}

function startActionPolling() {
  stopActionPolling();
  const poll = async () => {
    if (actionPollInFlight) return;
    actionPollInFlight = true;
    try {
      await refreshProviderState({ deduplicate: false });
    } catch {
      // The last confirmed provider snapshot remains visible.
    } finally {
      actionPollInFlight = false;
      if (["connecting", "disconnecting", "recovering", "measuring"].includes(getSlice("providerAction").state)) {
        actionPollTimer = window.setTimeout(poll, 2000);
      }
    }
  };
  actionPollTimer = window.setTimeout(poll, 2000);
}

async function connectCountry(countryCode, button) {
  if (!vpnProviderAccess(getSlice("provider").data || {}).canSelectLocation) return;
  if (["connecting", "disconnecting", "recovering", "measuring"].includes(getSlice("providerAction").state)) return;
  const statusLabel = button.querySelector(".country-card__status");
  button.disabled = true;
  button.classList.add("country-card--connecting");
  statusLabel.textContent = t("provider.action.connecting", {}, "Connecting…");
  updateSlice("providerAction", { state: "connecting", target: countryCode, error: null });
  startActionPolling();
  try {
    const result = await postJson("/api/vpn/connect", { country_code: countryCode }, { timeoutMilliseconds: 130000 });
    applyVpnSnapshot(result.vpn);
    if (!result.success) {
      const error = new Error(result.error || "connect_failed");
      error.code = result.error || "connect_failed";
      throw error;
    }
    await refreshCountries();
    showMessage(t("provider.notifications.country_connected", { server: result.server || countryCode }, `Connected to ${result.server || countryCode}.`), "success");
  } catch (error) {
    applyVpnSnapshot(error.payload?.vpn);
    const message = connectionErrorMessage(error.code || error.payload?.error, countryCode);
    statusLabel.textContent = message;
    showMessage(message, "error");
  } finally {
    stopActionPolling();
    const providerStatus = getSlice("provider").data || {};
    updateSlice("providerAction", { state: providerStatus.connected ? "connected" : "idle", target: null });
    button.classList.remove("country-card--connecting");
    reconcileCountries(providerStatus);
    renderProviderControls(providerStatus, { state: getSlice("providerAction").state });
  }
}

async function remeasureCountries() {
  if (!vpnProviderAccess(getSlice("provider").data || {}).canSelectLocation) return;
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

async function measureMissingCountries({ signal } = {}) {
  const missing = quickCountryCodes.filter((code) => {
    const country = vpnCountries.find((item) => item.country_code === code);
    return country && country.latency_measured_at == null;
  });
  if (!missing.length) return;
  await Promise.allSettled(
    missing.map((code) => postJson(
      `/api/vpn/countries/${code}/measure`,
      undefined,
      { signal },
    )),
  );
  if (signal?.aborted) return;
  await refreshCountries({ signal });
}

async function reconnectCountry() {
  if (!vpnProviderAccess(getSlice("provider").data || {}).canSelectLocation) return;
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
  if (!vpnProviderAccess(getSlice("provider").data || {}).canDisconnect) return;
  if (["connecting", "disconnecting", "recovering", "measuring"].includes(getSlice("providerAction").state)) return;
  const button = select("#disconnect-button");
  updateSlice("providerAction", { state: "disconnecting", target: null, error: null });
  startActionPolling();
  setBusy(button, true, t("provider.action.disconnecting", {}, "Disconnecting…"));
  const progress = showMessage(t("provider.notifications.disconnecting", {}, "Disconnecting…"), "info", { id: "provider-action", duration: null });
  try {
    const result = await postJson("/api/vpn/disconnect", undefined, { timeoutMilliseconds: 30000 });
    applyVpnSnapshot(result.vpn);
    if (!result.success || result.vpn?.connected) throw new Error("disconnect_failed");
    updateSlice("providerAction", { state: "idle", error: null });
    progress.close();
    showMessage(t("provider.notifications.disconnected", {}, "Disconnected."), "success");
  } catch (error) {
    applyVpnSnapshot(error.payload?.vpn);
    updateSlice("providerAction", { state: "failed", error: "disconnect_failed" });
    progress.close();
    showMessage(t("provider.notifications.disconnect_failed", {}, "Could not disconnect."), "error");
  } finally {
    stopActionPolling();
    const providerStatus = getSlice("provider").data || {};
    setBusy(button, false);
    updateSlice("providerAction", { state: providerStatus.connected ? "connected" : "idle", target: null });
    reconcileCountries(providerStatus);
    renderProviderControls(providerStatus, { state: getSlice("providerAction").state });
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
  select("#vpn-provider-open-settings").addEventListener("click", () => {
    showView("settings", { section: "vpn" });
  });
  select("#vpn-provider-retry").addEventListener("click", () => {
    refreshProviderState({ deduplicate: false }).catch(() => {});
  });
  select("#country-search").addEventListener("input", renderCountries);
  window.addEventListener("focus", () => {
    if (
      shouldLoadAuthenticatedProviderData(
        getSlice("application"),
        getSlice("auth"),
        getSlice("provider"),
      )
    ) {
      refreshProviderState({ deduplicate: false }).catch(() => {});
    }
  });
  window.addEventListener("exitlane:viewchange", (event) => {
    if (event.detail?.view === "vpn") void activateAuthenticatedProviderData();
  });

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
