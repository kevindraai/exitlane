import assert from "node:assert/strict";
import test from "node:test";
import { api } from "../backend/exitlane/static/js/api.js";

test("identical concurrent GET requests share one fetch", async () => {
  let calls = 0;
  let release;
  globalThis.fetch = async () => {
    calls += 1;
    await new Promise((resolve) => { release = resolve; });
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const first = api("/same");
  const second = api("/same");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(calls, 1);
  release();
  assert.deepEqual(await first, await second);
});

test("mutating requests are never deduplicated", async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  await Promise.all([api("/write", { method: "POST" }), api("/write", { method: "POST" })]);
  assert.equal(calls, 2);
});
