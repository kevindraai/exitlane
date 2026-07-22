import assert from "node:assert/strict";
import test from "node:test";
import { createDomainPoller } from "../backend/exitlane/static/js/lifecycle.js";

test("poller shares in-flight refresh and prevents duplicate timers", async () => {
  let resolve;
  let calls = 0;
  const timers = new Map();
  let timerId = 0;
  const poller = createDomainPoller({
    refresh: () => { calls += 1; return new Promise((done) => { resolve = done; }); },
    isActive: () => true,
    intervalSeconds: 10,
    setTimer: (callback) => { timers.set(++timerId, callback); return timerId; },
    clearTimer: (id) => timers.delete(id),
  });
  const first = poller.refresh();
  const second = poller.refresh();
  assert.equal(first, second);
  assert.equal(calls, 1);
  resolve();
  await first;
  poller.start({ immediate: false });
  poller.start({ immediate: false });
  assert.equal(timers.size, 1);
  poller.stop();
  assert.equal(timers.size, 0);
});
