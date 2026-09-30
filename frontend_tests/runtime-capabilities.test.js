import assert from "node:assert/strict";
import test from "node:test";
import { applyRuntimeCapabilities, runtimeAllows, runtimeAllowsAction } from "../backend/exitlane/static/js/runtime.js";

test("unavailable runtime actions fail closed and native projection is truthful", () => {
  const reboot = { dataset: { systemAction: "reboot" }, hidden: false };
  const timezone = { disabled: false };
  const speedtest = { hidden: false };
  globalThis.document = {
    querySelectorAll: (selector) => selector === "[data-system-action]" ? [reboot] : [],
    querySelector: (id) => id === "#settings-timezone" ? timezone : speedtest,
  };
  try {
    applyRuntimeCapabilities(null);
    assert.equal(runtimeAllowsAction("reboot"), false);
    assert.equal(runtimeAllows("timezone_configuration"), false);
    assert.equal(reboot.hidden, true);
    assert.equal(timezone.disabled, true);
    assert.equal(speedtest.hidden, true);
    applyRuntimeCapabilities({ system_actions: ["reboot"], timezone_configuration: true, speedtest: true });
    assert.equal(reboot.hidden, false);
    assert.equal(timezone.disabled, false);
    assert.equal(runtimeAllows("speedtest"), true);
  } finally { delete globalThis.document; }
});
