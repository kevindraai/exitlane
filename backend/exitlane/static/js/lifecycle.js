import { api } from "./api.js";
import { beginRefresh, failRefresh, getSlice, succeedRefresh } from "./state.js";
import { refreshActivity } from "./activity.js";
import { providerRequestIsCurrent, providerStatusId } from "./provider-management.js";

export function createDomainPoller({ refresh, isActive, key = () => null, intervalSeconds = 15, setTimer = setTimeout, clearTimer = clearTimeout }) {
  let timer = null;
  let running = false;
  let inFlight = null;
  let inFlightKey = null;
  let generation = 0;
  let interval = intervalSeconds;
  let controller = null;
  let activeKey = null;

  const cancelTimer = () => {
    if (timer !== null) clearTimer(timer);
    timer = null;
  };
  const run = () => {
    const requestedKey = key();
    if (inFlight && requestedKey !== inFlightKey) {
      controller?.abort("poller_key_changed");
      inFlight = null;
      inFlightKey = null;
      controller = null;
    }
    if (!inFlight) {
      const requestController = new AbortController();
      const refreshOptions = { signal: requestController.signal };
      if (requestedKey !== null && requestedKey !== undefined) {
        refreshOptions.providerId = requestedKey;
      }
      controller = requestController;
      inFlightKey = requestedKey;
      const request = Promise.resolve(refresh(refreshOptions)).finally(() => {
        if (inFlight === request) {
          inFlight = null;
          inFlightKey = null;
        }
        if (controller === requestController) controller = null;
      });
      inFlight = request;
    }
    return inFlight;
  };
  const schedule = (expected, expectedKey) => {
    if (
      !running
      || !isActive()
      || expected !== generation
      || expectedKey !== key()
    ) return;
    cancelTimer();
    timer = setTimer(async () => {
      timer = null;
      try { await run(); } catch { /* Slice retains the last confirmed data. */ }
      schedule(expected, expectedKey);
    }, interval * 1000);
  };
  const start = ({ immediate = true } = {}) => {
    if (!isActive()) return stop();
    const requestedKey = key();
    if (running && requestedKey !== activeKey) stop();
    if (running) return immediate ? run() : undefined;
    running = true;
    activeKey = requestedKey;
    generation += 1;
    const current = generation;
    if (immediate) {
      run().catch(() => {}).finally(() => schedule(current, requestedKey));
    } else {
      schedule(current, requestedKey);
    }
  };
  const stop = () => {
    running = false;
    activeKey = null;
    generation += 1;
    cancelTimer();
    controller?.abort("lifecycle_stopped");
    controller = null;
    inFlight = null;
    inFlightKey = null;
  };
  const restart = (seconds = interval) => { interval = seconds; stop(); start(); };
  return { refresh: run, start, stop, restart, isRunning: () => running, hasRequestInFlight: () => inFlight !== null };
}

async function refreshSlice(name, path, selectData = (value) => value, options = {}) {
  beginRefresh(name);
  try {
    const response = await api(path, options);
    const data = selectData(response);
    succeedRefresh(name, data);
    return data;
  } catch (error) {
    if (error.code !== "aborted") failRefresh(name, error.code || "request_failed");
    throw error;
  }
}

export const refreshProviderState = async (options = {}) => {
  const providerId = options.providerId
    || getSlice("application").providerId
    || getSlice("providers").data?.activeProviderId;
  const path = providerId
    ? `/api/vpn/providers/${encodeURIComponent(providerId)}/status`
    : "/api/vpn/status";
  const requestOptions = { ...options };
  delete requestOptions.providerId;
  beginRefresh("provider");
  try {
    const response = await api(path, requestOptions);
    const data = response.status || response;
    if (providerId) {
      const application = getSlice("application");
      const providerViewActive = application.mode === "dashboard"
        && application.activeView === "vpn-provider";
      if (
        providerStatusId(data) !== providerId
        || (providerViewActive && !providerRequestIsCurrent(providerId, application, data))
      ) return null;
    }
    succeedRefresh("provider", data);
    return data;
  } catch (error) {
    if (
      error.code !== "aborted"
      && (
        !providerId
        || getSlice("application").activeView !== "vpn-provider"
        || getSlice("application").providerId === providerId
      )
    ) failRefresh("provider", error.code || "request_failed");
    throw error;
  }
};
export const refreshProvidersState = (options) => refreshSlice(
  "providers",
  "/api/vpn/providers",
  (response) => ({
    activeProviderId: response.active_provider_id,
    items: response.providers || [],
  }),
  options,
);
export const refreshWireGuardState = (options) => refreshSlice("wireguard", "/api/ingress/wireguard/status", undefined, options);
export async function refreshDashboardState(options) {
  const data = await refreshSlice("dashboard", "/api/dashboard", undefined, options);
  succeedRefresh("system", data.system);
  succeedRefresh("provider", { ...(getSlice("provider").data || {}), ...data.vpn });
  succeedRefresh("wireguard", { ...(getSlice("wireguard").data || {}), ...data.wireguard });
  return data;
}

export function createApplicationLifecycle({ intervalSeconds, application = () => getSlice("application") } = {}) {
  const active = (...views) => application().mode === "dashboard" && views.includes(application().activeView);
  const provider = createDomainPoller({
    refresh: refreshProviderState,
    isActive: () => active("vpn-provider"),
    key: () => application().providerId || getSlice("providers").data?.activeProviderId || null,
    intervalSeconds,
  });
  const providers = createDomainPoller({ refresh: refreshProvidersState, isActive: () => active("vpn"), intervalSeconds });
  const wireguard = createDomainPoller({ refresh: refreshWireGuardState, isActive: () => active("wireguard"), intervalSeconds });
  const dashboard = createDomainPoller({ refresh: refreshDashboardState, isActive: () => active("dashboard"), intervalSeconds });
  const activity = createDomainPoller({ refresh: refreshActivity, isActive: () => active("activity"), intervalSeconds: Math.max(intervalSeconds || 15, 15) });
  const sync = () => {
    for (const poller of [provider, providers, wireguard, dashboard, activity]) poller.start({ immediate: true });
    if (!active("vpn-provider")) provider.stop();
    if (!active("vpn")) providers.stop();
    if (!active("wireguard")) wireguard.stop();
    if (!active("dashboard")) dashboard.stop();
    if (!active("activity")) activity.stop();
  };
  const stop = () => [provider, providers, wireguard, dashboard, activity].forEach((poller) => poller.stop());
  const restart = (seconds) => { intervalSeconds = seconds; [provider, providers, wireguard, dashboard].forEach((poller) => poller.restart(seconds)); activity.restart(Math.max(seconds, 15)); sync(); };
  return { provider, providers, wireguard, dashboard, activity, sync, stop, restart };
}
