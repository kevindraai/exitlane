import assert from "node:assert/strict";
import test from "node:test";
import { refreshProviderState } from "../backend/exitlane/static/js/lifecycle.js";
import { getSlice, replaceSlice, updateSlice } from "../backend/exitlane/static/js/state.js";

for (const [previous, current] of [["nordvpn", "mullvad"], ["mullvad", "nordvpn"]]) {
  test(`wizard ignores late ${previous} status after selecting ${current}`, async () => {
    const savedFetch = globalThis.fetch;
    const savedApplication = getSlice("application");
    const savedProvider = getSlice("provider");
    let finish;
    globalThis.fetch = () => new Promise((resolve) => { finish = resolve; });
    try {
      updateSlice("application", { mode: "wizard", providerId: previous });
      const pending = refreshProviderState({ providerId: previous, deduplicate: false });
      updateSlice("application", { providerId: current });
      const selectedStatus = { management: { provider: { id: current } } };
      updateSlice("provider", { data: selectedStatus, stale: false });
      finish(new Response(JSON.stringify({ status: { management: { provider: { id: previous } } } }), {
        status: 200, headers: { "content-type": "application/json" },
      }));
      assert.equal(await pending, null);
      assert.equal(getSlice("provider").data, selectedStatus);
    } finally {
      globalThis.fetch = savedFetch;
      replaceSlice("application", savedApplication);
      replaceSlice("provider", savedProvider);
    }
  });
}
