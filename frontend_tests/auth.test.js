import assert from "node:assert/strict";
import test from "node:test";
import { applyLogoutVisibility, isLogoutVisible } from "../backend/exitlane/static/js/auth.js";

const auth = (authenticated) => ({ data: { authenticated } });

test("logout is visible only for an authenticated dashboard", () => {
  assert.equal(isLogoutVisible({ mode: "wizard" }, auth(true)), false);
  assert.equal(isLogoutVisible({ mode: "wizard" }, auth(false)), false);
  assert.equal(isLogoutVisible({ mode: "login" }, auth(true)), false);
  assert.equal(isLogoutVisible({ mode: "login" }, auth(false)), false);
  assert.equal(isLogoutVisible({ mode: "dashboard" }, auth(false)), false);
  assert.equal(isLogoutVisible({ mode: "dashboard" }, auth(true)), true);
});

test("wizard refresh remains hidden and first authenticated dashboard shows logout", () => {
  const refreshedSession = auth(true);
  assert.equal(isLogoutVisible({ mode: "wizard" }, refreshedSession), false);
  assert.equal(isLogoutVisible({ mode: "dashboard" }, refreshedSession), true);
  assert.equal(isLogoutVisible({ mode: "login" }, auth(false)), false);
});

test("mode-derived visibility writes the hidden property", () => {
  const button = { hidden: false };
  applyLogoutVisibility(button, { mode: "wizard" }, auth(true));
  assert.equal(button.hidden, true);
  applyLogoutVisibility(button, { mode: "login" }, auth(true));
  assert.equal(button.hidden, true);
  applyLogoutVisibility(button, { mode: "dashboard" }, auth(true));
  assert.equal(button.hidden, false);
});
