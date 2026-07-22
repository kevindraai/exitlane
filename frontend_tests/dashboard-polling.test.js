import assert from "node:assert/strict";
import test from "node:test";

import { createDashboardPolling } from "../backend/exitlane/static/js/dashboard-polling.js";
import { createDashboardRefreshState } from "../backend/exitlane/static/js/dashboard-refresh-state.js";

function timers() {
  let next = 1;
  const pending = new Map();
  return {
    set(callback, delay) {
      const id = next++;
      pending.set(id, { callback, delay });
      return id;
    },
    clear(id) { pending.delete(id); },
    pending,
  };
}

test("double start creates exactly one dashboard timer", () => {
  const clock = timers();
  const polling = createDashboardPolling({
    request: async () => ({}), isActive: () => true, intervalSeconds: 5,
    setTimer: clock.set, clearTimer: clock.clear,
  });
  polling.start();
  polling.start();
  assert.equal(clock.pending.size, 1);
});

test("polling stops outside dashboard and restarts with one timer", () => {
  const clock = timers();
  let active = true;
  const polling = createDashboardPolling({
    request: async () => ({}), isActive: () => active, intervalSeconds: 5,
    setTimer: clock.set, clearTimer: clock.clear,
  });
  polling.start();
  active = false;
  polling.stop();
  assert.equal(clock.pending.size, 0);
  active = true;
  polling.restart(9);
  assert.deepEqual([...clock.pending.values()].map(({ delay }) => delay), [9000]);
});

test("manual and automatic refresh share one in-flight request", async () => {
  const clock = timers();
  let resolveRequest;
  let calls = 0;
  const request = () => {
    calls += 1;
    return new Promise((resolve) => { resolveRequest = resolve; });
  };
  const polling = createDashboardPolling({
    request, isActive: () => true, intervalSeconds: 5,
    setTimer: clock.set, clearTimer: clock.clear,
  });
  polling.start();
  const automatic = [...clock.pending.entries()].find(([, value]) => value.delay === 5000);
  clock.pending.delete(automatic[0]);
  const automaticPromise = automatic[1].callback();
  const manualPromise = polling.refresh();
  assert.equal(calls, 1);
  assert.equal(polling.hasRequestInFlight(), true);
  resolveRequest({ ok: true });
  await Promise.all([automaticPromise, manualPromise]);
  assert.equal(calls, 1);
  assert.equal([...clock.pending.values()].filter(({ delay }) => delay === 5000).length, 1);
});

test("refresh error preserves the previous successful dashboard data", () => {
  const state = createDashboardRefreshState();
  const successful = { generated_at: "2026-07-22T10:00:00+00:00" };
  state.succeed(successful);
  state.fail("temporary failure");
  assert.deepEqual(state.snapshot(), {
    lastSuccessfulData: successful,
    error: "temporary failure",
  });
});

test("a stuck request is aborted at the configured timeout", async () => {
  const clock = timers();
  const polling = createDashboardPolling({
    request: ({ signal }) => new Promise((resolve, reject) => {
      signal.addEventListener("abort", () => reject(new Error("aborted")));
    }),
    isActive: () => true,
    intervalSeconds: 5,
    requestTimeoutMilliseconds: 100,
    setTimer: clock.set,
    clearTimer: clock.clear,
  });
  const request = polling.refresh();
  const timeout = [...clock.pending.entries()].find(([, value]) => value.delay === 100);
  clock.pending.delete(timeout[0]);
  timeout[1].callback();
  await assert.rejects(request, /aborted/);
  assert.equal(polling.hasRequestInFlight(), false);
});
