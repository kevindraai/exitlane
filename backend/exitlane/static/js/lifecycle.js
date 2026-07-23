import { api } from "./api.js";
import { beginRefresh, failRefresh, getSlice, succeedRefresh } from "./state.js";
import { refreshActivity } from "./activity.js";

export function createDomainPoller({ refresh, isActive, intervalSeconds = 15, setTimer = setTimeout, clearTimer = clearTimeout }) {
  let timer = null;
  let running = false;
  let inFlight = null;
  let generation = 0;
  let interval = intervalSeconds;
  let controller = null;

  const cancelTimer = () => {
    if (timer !== null) clearTimer(timer);
    timer = null;
  };
  const run = () => {
    if (!inFlight) {
      controller = new AbortController();
      inFlight = Promise.resolve(refresh({ signal: controller.signal })).finally(() => {
        inFlight = null;
        controller = null;
      });
    }
    return inFlight;
  };
  const schedule = (expected) => {
    if (!running || !isActive() || expected !== generation) return;
    cancelTimer();
    timer = setTimer(async () => {
      timer = null;
      try { await run(); } catch { /* Slice retains the last confirmed data. */ }
      schedule(expected);
    }, interval * 1000);
  };
  const start = ({ immediate = true } = {}) => {
    if (!isActive()) return stop();
    if (running) return immediate ? run() : undefined;
    running = true;
    generation += 1;
    const current = generation;
    if (immediate) run().catch(() => {}).finally(() => schedule(current)); else schedule(current);
  };
  const stop = () => {
    running = false;
    generation += 1;
    cancelTimer();
    controller?.abort("lifecycle_stopped");
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

export const refreshProviderState = (options) => {
  const providerId = getSlice("application").providerId
    || getSlice("providers").data?.activeProviderId;
  const path = providerId
    ? `/api/vpn/providers/${encodeURIComponent(providerId)}/status`
    : "/api/vpn/status";
  return refreshSlice("provider", path, (response) => response.status || response, options);
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
  const provider = createDomainPoller({ refresh: refreshProviderState, isActive: () => active("vpn-provider"), intervalSeconds });
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
