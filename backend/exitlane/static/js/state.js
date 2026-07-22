export const appState = {
  session: null,
  setup: null,
  provider: null,
  diagnostics: null,
  visibleStep: 1,
  generatedClientName: null,
  generatedClientConfig: null
};

const statusSlice = () => ({
  data: null,
  loading: false,
  error: null,
  updatedAt: null,
  stale: false,
});

const state = {
  auth: { ...statusSlice(), data: { authenticated: false, user: null } },
  application: { mode: "login", activeView: "dashboard" },
  api: statusSlice(),
  provider: statusSlice(),
  wireguard: statusSlice(),
  dashboard: statusSlice(),
  system: statusSlice(),
  providerAction: { state: "idle", target: null, error: null },
};

const subscriptions = new Map();

export function getState() {
  return state;
}

export function getSlice(name) {
  if (!(name in state)) throw new Error(`Unknown state slice: ${name}`);
  return state[name];
}

function notify(name) {
  for (const callback of subscriptions.get(name) || []) callback(state[name], state);
}

export function updateSlice(name, patch) {
  state[name] = { ...getSlice(name), ...patch };
  notify(name);
  return state[name];
}

export function replaceSlice(name, value) {
  getSlice(name);
  state[name] = value;
  notify(name);
  return value;
}

export function subscribe(name, callback, { immediate = false } = {}) {
  getSlice(name);
  if (!subscriptions.has(name)) subscriptions.set(name, new Set());
  subscriptions.get(name).add(callback);
  if (immediate) callback(state[name], state);
  return () => subscriptions.get(name)?.delete(callback);
}

export function resetAuthenticatedState() {
  for (const name of ["provider", "wireguard", "dashboard", "system"]) {
    state[name] = statusSlice();
    notify(name);
  }
  state.providerAction = { state: "idle", target: null, error: null };
  notify("providerAction");
}

export function beginRefresh(name) {
  const current = getSlice(name);
  return updateSlice(name, {
    loading: current.data === null,
    stale: current.data !== null,
    error: null,
  });
}

export function succeedRefresh(name, data, updatedAt = Date.now()) {
  return updateSlice(name, { data, loading: false, error: null, updatedAt, stale: false });
}

export function failRefresh(name, error) {
  return updateSlice(name, {
    loading: false,
    error,
    stale: getSlice(name).data !== null,
  });
}

export const stepNames = {
  1: "system",
  2: "admin",
  3: "provider",
  4: "wireguard",
  5: "complete",
};
