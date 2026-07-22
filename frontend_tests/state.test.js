import assert from "node:assert/strict";
import test from "node:test";
import { beginRefresh, failRefresh, getSlice, resetAuthenticatedState, subscribe, succeedRefresh, updateSlice } from "../backend/exitlane/static/js/state.js";

test("store updates subscribers once and unsubscribe is safe", () => {
  let calls = 0;
  const callback = () => { calls += 1; };
  const unsubscribe = subscribe("provider", callback);
  subscribe("provider", callback);
  updateSlice("provider", { loading: true });
  assert.equal(calls, 1);
  unsubscribe();
  updateSlice("provider", { loading: false });
  assert.equal(calls, 1);
});

test("refresh failures preserve confirmed data and timestamp", () => {
  succeedRefresh("provider", { connected: true }, 1234);
  beginRefresh("provider");
  failRefresh("provider", "timeout");
  assert.deepEqual(getSlice("provider").data, { connected: true });
  assert.equal(getSlice("provider").updatedAt, 1234);
  assert.equal(getSlice("provider").stale, true);
});

test("authenticated reset clears sensitive status", () => {
  succeedRefresh("wireguard", { peers: ["secret"] }, 1);
  resetAuthenticatedState();
  assert.equal(getSlice("wireguard").data, null);
});
