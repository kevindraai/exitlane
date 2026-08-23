import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  aggregateDiagnosticStatus,
  segmentStatuses,
  speedtestInstallButtonDisabled,
} from "../backend/exitlane/static/js/diagnostics.js";

test("diagnostic segment aggregation preserves the most actionable state", () => {
  assert.equal(aggregateDiagnosticStatus([]), "pending");
  assert.equal(aggregateDiagnosticStatus([{ status: "passed" }]), "passed");
  assert.equal(
    aggregateDiagnosticStatus([{ status: "passed" }, { status: "warning" }]),
    "warning",
  );
  assert.equal(
    aggregateDiagnosticStatus([{ status: "running" }, { status: "failed" }]),
    "failed",
  );
});

test("Device to Exitlane to VPN to Internet maps backend probes onto links and nodes", () => {
  const view = segmentStatuses({
    probes: [
      { segment: "device_exitlane", status: "passed" },
      { segment: "exitlane_vpn", status: "passed" },
      { segment: "exitlane_vpn", status: "warning" },
      { segment: "vpn_internet", status: "failed" },
    ],
  });
  assert.deepEqual(view.segments, {
    device_exitlane: "passed",
    exitlane_vpn: "warning",
    vpn_internet: "failed",
  });
  assert.deepEqual(view.nodes, {
    device: "passed",
    exitlane: "passed",
    vpn: "warning",
    internet: "failed",
  });
});

test("speed test is POST-only and only bound to an explicit button action", async () => {
  const source = await readFile(
    new URL("../backend/exitlane/static/js/diagnostics.js", import.meta.url),
    "utf8",
  );
  assert.match(source, /dataDiagnosticAction|dataset\.diagnosticAction/);
  assert.match(source, /postJson\(\s*`\/api\/diagnostics\/actions\/\$\{action\}`/);
  assert.doesNotMatch(source.slice(0, source.indexOf("async function runAction")), /speedtest\(/);
});

test("Speedtest installation UI is explicit, translated, and safe for external links", async () => {
  const [markup, english, dutch] = await Promise.all([
    readFile(new URL("../backend/exitlane/static/partials/views/diagnostics.html", import.meta.url), "utf8"),
    readFile(new URL("../backend/exitlane/static/locales/en.json", import.meta.url), "utf8"),
    readFile(new URL("../backend/exitlane/static/locales/nl.json", import.meta.url), "utf8"),
  ]);
  const en = JSON.parse(english);
  const nl = JSON.parse(dutch);
  assert.match(markup, /class="speedtest-management"[^>]+hidden[^>]+id="speedtest-management"/);
  assert.match(markup, /id="speedtest-install-dialog"/);
  assert.match(markup, /id="speedtest-run-dialog"/);
  assert.match(markup, /official Ookla/);
  assert.match(markup, /repository or signing key/);
  assert.match(markup, /rel="noopener noreferrer" target="_blank"/);
  for (const key of ["install", "install_description", "confirm_package_change", "accept_license", "accept_gdpr", "run_description", "confirm_bandwidth"]) {
    assert.equal(typeof en.diagnostics.speedtest[key], "string");
    assert.equal(typeof nl.diagnostics.speedtest[key], "string");
  }
});

test("installation and action contracts require every explicit confirmation", async () => {
  const source = await readFile(new URL("../backend/exitlane/static/js/diagnostics.js", import.meta.url), "utf8");
  assert.match(source, /postJson\(SPEEDTEST_INSTALLATION_PATH, \{[\s\S]*confirm_package_change: true,[\s\S]*confirm_personal_noncommercial: true,[\s\S]*accept_license: true,[\s\S]*accept_gdpr: true/);
  assert.match(source, /postJson\("\/api\/diagnostics\/actions\/speedtest", \{[\s\S]*confirm_personal_noncommercial: true,[\s\S]*accept_license: true,[\s\S]*accept_gdpr: true,[\s\S]*confirm_bandwidth: true/);
  assert.match(source, /if \(speedtestActionFlight\) return/);
  assert.match(source, /if \(speedtestInstallationFlight\) return/);
  assert.match(source, /speedtestSelected = true/);
  assert.doesNotMatch(source, /runSpeedtest\(\);\s*\/\/ automatic/);
});

test("installation status rendering allowlists phase and step text", async () => {
  const source = await readFile(new URL("../backend/exitlane/static/js/diagnostics.js", import.meta.url), "utf8");
  assert.match(source, /SPEEDTEST_PHASES = new Set/);
  assert.match(source, /SPEEDTEST_STEP_STATUSES = new Set/);
  assert.match(source, /textContent = speedtestErrorText/);
  assert.match(source, /speedtestPollTimer/);
  assert.match(source, /refreshSpeedtestInstallation\(\{ poll: true \}\)/);
  assert.match(source, /supported_runtime !== false/);
});

test("installable Speedtest can be opened again after the status GET settles", () => {
  const unavailable = {
    status: "warning",
    available: false,
    supported_runtime: true,
    can_install: true,
    installation_in_progress: false,
  };
  assert.equal(speedtestInstallButtonDisabled(unavailable, true), true);
  assert.equal(speedtestInstallButtonDisabled(unavailable, false), false);
  assert.equal(speedtestInstallButtonDisabled({ ...unavailable, supported_runtime: false }, false), true);
});

test("validated CLI stays runnable on an unsupported managed-install runtime and pending is rendered", async () => {
  const source = await readFile(new URL("../backend/exitlane/static/js/diagnostics.js", import.meta.url), "utf8");
  assert.match(source, /SPEEDTEST_STATUSES = new Set\(\["pending"/);
  assert.match(source, /if \(snapshot\.available === true\) \{/);
  assert.doesNotMatch(source, /snapshot\.available === true && snapshot\.supported_runtime !== false/);
});

test("reduced motion disables the diagnostics installation pulse", async () => {
  const css = await readFile(new URL("../backend/exitlane/static/style.css", import.meta.url), "utf8");
  assert.match(css, /prefers-reduced-motion: reduce/);
  assert.match(css, /diagnostics-link\[data-status="running"\][^}]+animation: none/);
});
