import { api, postJson } from "./api.js";
import { localisedCountryName } from "./country-format.js";
import { appState, getSlice, subscribe, succeedRefresh, updateSlice } from "./state.js";
import { refreshProviderState } from "./lifecycle.js";
import { initialiseLongTaskDisclosure, renderLongTask } from "./long-task.js";
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

let wizardInstallationCompleted = false;

export function renderProviderStatus(status) {
  appState.provider = status;

  const installation = status.management?.provider?.installation_state
    || (status.installed ? status.daemon_active === false ? "daemon_inactive" : "available" : "not_installed");
  const installed = ["available", "daemon_inactive"].includes(installation);
  const available = installation === "available";
  const installable = ["not_installed", "daemon_missing", "daemon_inactive"].includes(installation);
  const authenticated = Boolean(status.authenticated);
  const connected = Boolean(status.connected);

  if (connected) {
    setStatusPill(select("#provider-state"), t("provider.status.connected", {}, "Connected"), "success");
  } else if (authenticated) {
    setStatusPill(select("#provider-state"), t("provider.status.authenticated", {}, "Signed in"), "success");
  } else if (installation === "installing") {
    setStatusPill(select("#provider-state"), t("provider.installation.status.installing", {}, "Installing"), "neutral");
  } else if (installation === "unsupported") {
    setStatusPill(select("#provider-state"), t("provider.installation.status.unsupported", {}, "Unsupported"), "danger");
  } else if (installation === "failed") {
    setStatusPill(select("#provider-state"), t("provider.installation.status.failed", {}, "Installation failed"), "danger");
  } else if (installation === "daemon_inactive") {
    setStatusPill(select("#provider-state"), t("provider.installation.status.daemon_inactive", {}, "Daemon inactive"), "danger");
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

  select("#provider-install").disabled = !installable
    || !status.management?.capabilities?.can_install;
  select("#provider-next").disabled = !authenticated;
  select("#provider-login-methods").hidden = !available || !wizardInstallationCompleted;
  if (available) {
    clearInlineError();
    setBusy(select("#provider-install"), false);
  }

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

function providerApiPath(suffix = "") {
  const providerId = getSlice("application").providerId
    || getSlice("providers").data?.activeProviderId
    || "nordvpn";
  return `/api/vpn/providers/${encodeURIComponent(providerId)}${suffix}`;
}

function renderVpnProviderAccess(status) {
  const access = vpnProviderAccess(status);
  const blocker = select("#vpn-provider-blocker");
  const controls = select("#vpn-provider-controls");
  const goToSignIn = select("#vpn-provider-go-to-sign-in");
  const retry = select("#vpn-provider-retry");
  blocker.hidden = !access.blocked;
  blocker.dataset.state = access.state;
  controls.inert = access.blocked;
  controls.setAttribute("aria-disabled", String(access.blocked));
  goToSignIn.hidden = access.state !== "signed_out";
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

  select("#metric-country").textContent = localisedCountryName(status.country_code, status.country) || "—";
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
    && application.activeView === "vpn-provider"
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
  const measuring = country.measuring === true;
  const latency = measuring
    ? t("provider.country_selection.measuring", {}, "Measuring…")
    : country.latency_ms == null
      ? "—"
    : t("provider.country_selection.latency_ms", { latency: country.latency_ms }, `${country.latency_ms} ms`);
  const flag = document.createElement("span");
  flag.className = "country-card__flag";
  flag.setAttribute("aria-hidden", "true");
  flag.textContent = country.flag;
  const name = document.createElement("span");
  name.className = "country-card__name";
  name.textContent = localisedCountryName(country.country_code, country.name);
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
  const query = select("#country-search").value.trim().toLocaleLowerCase();
  quick.replaceChildren(...quickCountryCodes.map((code) => vpnCountries.find((country) => country.country_code === code)).filter(Boolean).map(countryCard));
  all.replaceChildren(...vpnCountries.filter((country) => (
    localisedCountryName(country.country_code, country.name).toLocaleLowerCase().includes(query)
  )).map(countryCard));
}

async function refreshCountries({ signal } = {}) {
  const result = await api(providerApiPath("/locations"), { deduplicate: false, signal });
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
    const item = vpnCountries.find((candidate) => candidate.country_code === countryCode);
    const country = localisedCountryName(countryCode, item?.name);
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
    const result = await postJson(providerApiPath("/location"), { country_code: countryCode }, { timeoutMilliseconds: 130000 });
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
    for (const code of quickCountryCodes) {
      await postJson(providerApiPath(`/locations/${code}/measure`));
    }
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
  vpnCountries = vpnCountries.map((country) => (
    missing.includes(country.country_code) ? { ...country, measuring: true } : country
  ));
  renderCountries();
  for (const code of missing) {
    try {
      const result = await postJson(
        providerApiPath(`/locations/${code}/measure`),
        undefined,
        { signal },
      );
      if (signal?.aborted) return;
      vpnCountries = vpnCountries.map((country) => (
        country.country_code === code
          ? {
            ...country,
            latency_ms: result.latency_ms,
            latency_measured_at: result.latency_measured_at,
            measuring: false,
          }
          : country
      ));
      renderCountries();
    } catch (error) {
      if (signal?.aborted || error.code === "aborted") return;
      vpnCountries = vpnCountries.map((country) => (
        country.country_code === code ? { ...country, measuring: false } : country
      ));
      renderCountries();
    }
  }
  if (signal?.aborted) return;
  await refreshCountries({ signal });
}

async function reconnectCountry() {
  if (!vpnProviderAccess(getSlice("provider").data || {}).canSelectLocation) return;
  const current = vpnCountries.find((country) => country.is_connected)
    || vpnCountries.find((country) => country.is_recent);
  if (current) await connectCountry(current.country_code, select("#reconnect-button"));
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
const INSTALL_POLL_INTERVAL_MS = 1500;

function installationErrorMessage(error) {
  const code = error.payload?.detail || error.code || "installation_failed";
  const message = t(
    `provider.installation.errors.${code}`,
    {},
    t("provider.installation.errors.installation_failed", {}, "The provider installation failed."),
  );
  return `${message} ${t(
    "provider.installation.diagnosis",
    {},
    "Local diagnosis: journalctl -u exitlane-provider-install-nordvpn.service -n 100 --no-pager",
  )}`;
}

function renderInstallationStatus(status, { focusSignIn = false } = {}) {
  const completed = status.phase === "completed";
  const failed = status.phase === "failed";
  const inProgress = status.installation_in_progress === true;
  const started = inProgress || completed || failed;
  const disclosure = select("#provider-install-disclosure");
  const startPanel = select("#provider-install-start");
  disclosure.hidden = !started;
  startPanel.hidden = started;
  if (!started) {
    wizardInstallationCompleted = false;
    select("#provider-login-methods").hidden = true;
    return;
  }
  const summary = completed
    ? t("provider.installation.completed_summary", {}, "NordVPN installed")
    : t("provider.installation.title", {}, "Install NordVPN");
  const summaryIcon = select("#provider-install-disclosure > summary .long-task-icon");
  summaryIcon.dataset.status = completed ? "completed" : failed ? "failed" : "active";
  select("#provider-install-summary").textContent = summary;
  wizardInstallationCompleted = completed;

  renderLongTask({
    details: disclosure,
    list: select("#provider-install-steps"),
    liveRegion: select("#provider-install-live"),
    steps: (status.steps || []).map((step) => ({
      ...step,
      errorMessage: step.status === "failed"
        ? installationErrorMessage({ payload: { detail: step.error_code } })
        : null,
    })),
    translationPrefix: "provider.installation",
    completed,
    summary,
  });

  const context = select("#provider-install-context");
  const longRunning = ["installing_client", "starting_daemon", "waiting_for_provider"].includes(status.phase);
  context.hidden = !longRunning;
  context.textContent = longRunning
    ? t(
      "provider.installation.long_running",
      {},
      "NordVPN installs system packages and initializes the daemon. This may take a while.",
    )
    : "";

  select("#provider-install").hidden = inProgress || completed || failed;
  const retryButton = select("#provider-install-retry");
  retryButton.hidden = !failed;
  const retryTranslations = {
    restart_installation: ["provider.installation.retry_installation", "Retry installation"],
    recheck_provider: ["provider.installation.retry_provider", "Check NordVPN again"],
    reapply_gateway_settings: ["provider.installation.retry_gateway", "Reapply gateway settings"],
    revalidate_installation: ["provider.installation.retry_validation", "Check installation again"],
  };
  const [retryKey, retryFallback] = retryTranslations[status.retry_action]
    || ["provider.installation.retry", "Try again"];
  retryButton.textContent = t(retryKey, {}, retryFallback);
  setBusy(select("#provider-install"), inProgress, t("busy.installing", {}, "Installing…"));

  if (completed) {
    clearInlineError();
    select("#provider-login-methods").hidden = false;
    if (focusSignIn) {
      window.requestAnimationFrame(() => select("#nord-token")?.focus());
    }
  }
}

async function installProvider({ confirm = true } = {}) {
  const button = confirm
    ? select("#provider-install")
    : select("#provider-install-retry");
  const providerId = getSlice("application").providerId
    || appState.setup?.selected_provider_id;
  if (!providerId) return;
  if (confirm && !window.confirm(t(
    "provider.installation.confirm",
    {},
    "Install this VPN provider on this Debian 13 system?",
  ))) return;

  setBusy(button, true, t("busy.installing", {}, "Installing…"));
  clearInlineError();

  try {
    const result = await postJson(
      `/api/vpn/providers/${encodeURIComponent(providerId)}/installation`,
    );

    if (!result.ok) {
      throw new Error(
        result.message || "Installatie kon niet worden gestart.",
      );
    }

    renderInstallationStatus(result);
    await pollInstallStatus(providerId);
  } catch (error) {
    setBusy(button, false);
    if (error.payload?.detail === "installation_in_progress") {
      await pollInstallStatus(providerId);
      return;
    }
    showInlineError(installationErrorMessage(error));
  }
}

async function pollInstallStatus(providerId) {
  window.clearTimeout(installPollTimer);

  try {
    const status = await api(
      `/api/vpn/providers/${encodeURIComponent(providerId)}/installation`,
      { deduplicate: false },
    );

    renderInstallationStatus(status);

    if (status.installation_in_progress) {
      installPollTimer = window.setTimeout(
        () => pollInstallStatus(providerId),
        INSTALL_POLL_INTERVAL_MS,
      );
      return;
    }

    setBusy(select("#provider-install"), false);

    if (status.phase === "completed") {
      showMessage(
        t("provider.installation.success", {}, "The VPN provider is installed and available."),
      );
      await Promise.all([
        refreshProvider(),
        refreshSetup(),
      ]);
      renderInstallationStatus(status, { focusSignIn: true });
      return;
    }

    if (status.phase === "failed") renderInstallationStatus(status);
  } catch (error) {
    // A transient request failure is not a terminal installation failure.
    // Keep following the authoritative server-side operation.
    installPollTimer = window.setTimeout(
      () => pollInstallStatus(providerId),
      INSTALL_POLL_INTERVAL_MS,
    );
  }
}

export async function restoreInstallStatus() {
  const providerId = appState.setup?.selected_provider_id;
  if (!providerId) return;
  try {
    const status = await api(
      `/api/vpn/providers/${encodeURIComponent(providerId)}/installation`,
      { deduplicate: false },
    );

    renderInstallationStatus(status);
    await refreshProviderState({ deduplicate: false });
    if (status.installation_in_progress) await pollInstallStatus(providerId);
  } catch {
    // Er is nog geen installatiejob of de status is niet beschikbaar.
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
      providerApiPath("/authenticate"),
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
    const code = error.payload?.detail || error.code || "provider_error";
    showInlineError(t(
      `provider.authentication.errors.${code}`,
      {},
      t("provider.authentication.errors.provider_error", {}, "The provider could not complete sign-in."),
    ));
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
    const result = await postJson(providerApiPath("/disconnect"), undefined, { timeoutMilliseconds: 30000 });
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

  select("#provider-install-retry").addEventListener(
    "click",
    () => installProvider({ confirm: false }),
  );
  initialiseLongTaskDisclosure(
    select("#provider-install-disclosure"),
    select("#provider-install-detail-label"),
    "provider.installation",
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
  select("#vpn-provider-go-to-sign-in").addEventListener("click", () => {
    select("#provider-authentication-card").scrollIntoView({ block: "start" });
    select("#provider-token")?.focus();
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
    if (event.detail?.view === "vpn-provider") {
      void activateAuthenticatedProviderData();
    } else {
      suspendProviderData();
    }
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

}
