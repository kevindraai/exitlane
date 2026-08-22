import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  aggregateDiagnosticStatus,
  segmentStatuses,
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
