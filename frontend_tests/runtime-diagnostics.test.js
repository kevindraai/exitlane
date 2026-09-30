import { updateSlice } from "../backend/exitlane/static/js/state.js";
import assert from "node:assert/strict";
import test from "node:test";
import {
  applyRuntimeCapabilities, clearRuntimeCapabilities, loadRuntimeCapabilities, runtimeAllows,
} from "../backend/exitlane/static/js/runtime.js";
import {
  renderSpeedtestInstallation, speedtestPanelVisible, speedtestInstallButtonDisabled,
  refreshDiagnosticCapabilities, renderDiagnostics,
  selectSpeedtest, installSpeedtest, runSpeedtest, runAction, runConnectionDiagnostics,
} from "../backend/exitlane/static/js/diagnostics.js";

test("diagnostics rerender and action handlers cannot bypass unavailable capabilities", async () => {
  const management = { hidden: false };
  let requests = 0;
  globalThis.document = { querySelectorAll: () => [], querySelector: () => management };
  globalThis.fetch = () => { requests += 1; throw new Error("unexpected request"); };
  try {
    applyRuntimeCapabilities({ diagnostics: false, speedtest: false, package_installation: false });
    renderSpeedtestInstallation({ installation_in_progress: true, can_install: true }, true);
    assert.equal(management.hidden, true);
    assert.equal(speedtestInstallButtonDisabled({ can_install: true }, false, false), true);
    await selectSpeedtest(null);
    await installSpeedtest();
    await runSpeedtest();
    await runAction(null);
    await runConnectionDiagnostics();
    assert.equal(requests, 0);
    applyRuntimeCapabilities({ diagnostics: true, speedtest: true, package_installation: true });
    renderSpeedtestInstallation({ installation_in_progress: false }, false);
    assert.equal(management.hidden, true); // native availability does not imply operator selection
    assert.equal(speedtestPanelVisible({}, true), true);
    assert.equal(speedtestPanelVisible({ installation_in_progress: true }, false), true);
    assert.equal(speedtestInstallButtonDisabled({ can_install: true }, false, true), false);
  } finally { delete globalThis.document; delete globalThis.fetch; }
});

test("direct authenticated diagnostics loads capabilities and errors fail closed", async () => {
  globalThis.document = { querySelectorAll: () => [], querySelector: () => null };
  try {
    clearRuntimeCapabilities();
    let requests = 0;
    await loadRuntimeCapabilities({}, async () => { requests += 1; return { diagnostics: true, speedtest: false }; });
    assert.equal(runtimeAllows("diagnostics"), true);
    assert.equal(runtimeAllows("speedtest"), false);
    await loadRuntimeCapabilities({}, async () => { throw new Error("cache should avoid request"); });
    assert.equal(requests, 1);
    await loadRuntimeCapabilities({ force: true }, async () => { throw new Error("unavailable"); });
    assert.equal(runtimeAllows("diagnostics"), false);
    await loadRuntimeCapabilities({}, async () => ({ diagnostics: true, speedtest: true }));
    assert.equal(runtimeAllows("speedtest"), true);
    clearRuntimeCapabilities();
  } finally { delete globalThis.document; }
});

test("late authenticated capability reply cannot restore permissions after logout", async () => {
  globalThis.document = { querySelectorAll: () => [], querySelector: () => null };
  try {
    clearRuntimeCapabilities();
    let resolve;
    const pending = loadRuntimeCapabilities({}, () => new Promise((done) => { resolve = done; }));
    clearRuntimeCapabilities();
    resolve({ diagnostics: true, speedtest: true });
    assert.equal(await pending, null);
    assert.equal(runtimeAllows("speedtest"), false);
  } finally { delete globalThis.document; }
});


test("delayed login capabilities rerender Run checks without reopening an active run", async () => {
  const runButton = { disabled: false };
  const summary = {};
  const details = { replaceChildren() {} };
  const management = { hidden: true };
  globalThis.document = {
    querySelectorAll: () => [],
    querySelector: (id) => ({
      "#diagnostics-run": runButton, "#connection-diagnostics-summary": summary,
      "#diagnostics-details": details, "#speedtest-management": management,
    })[id] || null,
  };
  try {
    clearRuntimeCapabilities();
    updateSlice("diagnostics", { data: null, loading: false, error: null });
    renderDiagnostics();
    assert.equal(runButton.disabled, true);
    let resolve;
    const pending = refreshDiagnosticCapabilities(() => new Promise((done) => { resolve = done; }));
    assert.equal(runButton.disabled, true);
    resolve({ diagnostics: true, speedtest: false });
    await pending;
    assert.equal(runButton.disabled, false);
    updateSlice("diagnostics", { data: { status: "running", probes: [] } });
    await refreshDiagnosticCapabilities(async () => ({ diagnostics: true, speedtest: false }));
    assert.equal(runButton.disabled, true);
    updateSlice("diagnostics", { data: null });
    await refreshDiagnosticCapabilities(async () => { throw new Error("failed"); });
    assert.equal(runButton.disabled, true);
  } finally { delete globalThis.document; }
});
