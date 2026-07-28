import assert from "node:assert/strict";
import test from "node:test";

import {
  formatActiveLatency,
} from "../backend/exitlane/static/js/provider.js";

test("active VPN latency changes from unavailable to a measured value", () => {
  assert.equal(formatActiveLatency({ latency_ms: null }), "—");
  assert.equal(formatActiveLatency({ latency_ms: 27 }), "27 ms");
});
