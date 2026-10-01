import { api } from "./api.js";
// One public-safe capability projection, shared by setup and authenticated settings.
let capabilities = null;
let capabilityFlight = null;
let generation = 0;
export function runtimeAllows(name) {
  return capabilities?.[name] === true;
}
export function runtimeAllowsAction(action) {
  return Array.isArray(capabilities?.system_actions) && capabilities.system_actions.includes(action);
}
export function applyRuntimeCapabilities(projection) {
  capabilities = projection || null;
  for (const button of document.querySelectorAll("[data-system-action]")) {
    button.hidden = !runtimeAllowsAction(button.dataset.systemAction);
  }
  for (const button of document.querySelectorAll("[data-diagnostic-action]")) {
    button.hidden = !runtimeAllows("diagnostics")
      || (button.dataset.diagnosticAction === "speedtest" && !runtimeAllows("speedtest"));
  }
  const diagnosticRun = document.querySelector("#diagnostics-run");
  if (diagnosticRun && !runtimeAllows("diagnostics")) diagnosticRun.disabled = true;
  const timezone = document.querySelector("#settings-timezone");
  if (timezone) timezone.disabled = !runtimeAllows("timezone_configuration");
  const speedtest = document.querySelector("#speedtest-management");
  if (speedtest && !runtimeAllows("speedtest")) speedtest.hidden = true;
}

export async function loadRuntimeCapabilities({ force = false } = {}, fetchProjection = () => api("/api/runtime/capabilities")) {
  if (!force && capabilities) return capabilities;
  if (capabilityFlight) return capabilityFlight;
  const currentGeneration = generation;
  const request = (async () => {
    try {
      const projection = await fetchProjection();
      if (currentGeneration !== generation) return null;
      applyRuntimeCapabilities(projection);
      return projection;
    } catch {
      if (currentGeneration === generation) applyRuntimeCapabilities(null);
      return null;
    }
  })();
  capabilityFlight = request;
  try { return await request; }
  finally { if (capabilityFlight === request) capabilityFlight = null; }
}
export function clearRuntimeCapabilities() {
  generation += 1;
  capabilityFlight = null;
  applyRuntimeCapabilities(null);
}
