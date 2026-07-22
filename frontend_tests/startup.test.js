import assert from "node:assert/strict";
import test from "node:test";
import { runColdStart } from "../backend/exitlane/static/js/startup.js";

function scenario(session) {
  const calls = [];
  return {
    calls,
    dependencies: {
      refreshSession: async () => { calls.push("auth/session"); return session; },
      setMode: (mode) => { calls.push(`mode:${mode}`); },
      startWizard: async () => { calls.push("wizard"); },
      showLogin: () => { calls.push("login"); },
      startDashboard: async () => { calls.push("dashboard"); },
    },
  };
}

test("cold start before setup starts only the wizard path", async () => {
  const { calls, dependencies } = scenario({ setup_complete: false, authenticated: false });
  assert.equal(await runColdStart(dependencies), "wizard");
  assert.deepEqual(calls, ["auth/session", "mode:wizard", "wizard"]);
});

test("cold start after setup without a session performs no protected setup work", async () => {
  const { calls, dependencies } = scenario({ setup_complete: true, authenticated: false });
  assert.equal(await runColdStart(dependencies), "login");
  assert.deepEqual(calls, ["auth/session", "mode:login", "login"]);
});

test("cold start after setup with a session starts dashboard lifecycle", async () => {
  const { calls, dependencies } = scenario({ setup_complete: true, authenticated: true });
  assert.equal(await runColdStart(dependencies), "dashboard");
  assert.deepEqual(calls, ["auth/session", "mode:dashboard", "dashboard"]);
});

test("failed session check cannot start a setup refresh", async () => {
  const calls = [];
  await assert.rejects(runColdStart({
    refreshSession: async () => { throw new Error("401"); },
    setMode: (mode) => { calls.push(`mode:${mode}`); },
    startWizard: async () => { calls.push("wizard"); },
    showLogin: () => { calls.push("login"); },
    startDashboard: async () => { calls.push("dashboard"); },
  }));
  assert.deepEqual(calls, []);
});

test("authenticated loading failure applies dashboard mode before rejecting", async () => {
  const calls = [];
  await assert.rejects(runColdStart({
    refreshSession: async () => ({ setup_complete: true, authenticated: true }),
    setMode: (mode) => { calls.push(`mode:${mode}`); },
    startWizard: async () => {},
    showLogin: () => {},
    startDashboard: async () => { calls.push("dashboard-load"); throw new Error("load failed"); },
  }));
  assert.deepEqual(calls, ["mode:dashboard", "dashboard-load"]);
});
