import assert from "node:assert/strict";
import test from "node:test";
import {
  applyLogoutVisibility,
  isLogoutVisible,
  loginErrorTranslationKey,
} from "../backend/exitlane/static/js/auth.js";
import { readFile } from "node:fs/promises";

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

test("login preserves credential, deployment, validation, rate, and service errors", () => {
  assert.equal(
    loginErrorTranslationKey({ status: 401, payload: { detail: "invalid_credentials" } }),
    "auth.invalid_credentials",
  );
  for (const detail of ["invalid_origin", "csrf_failed", "deployment_origin_mismatch"]) {
    assert.equal(
      loginErrorTranslationKey({ status: 403, payload: { detail } }),
      "auth.deployment_security",
    );
  }
  assert.equal(loginErrorTranslationKey({ status: 429, payload: {} }), "auth.rate_limited");
  assert.equal(loginErrorTranslationKey({ status: 422, payload: {} }), "auth.invalid_request");
  assert.equal(loginErrorTranslationKey({ status: 503, payload: {} }), "auth.service_unavailable");
  assert.equal(loginErrorTranslationKey({ status: 0, code: "network_error" }), "auth.service_unavailable");
});

test("login status is outside the stable field grid", async () => {
  const markup = await readFile(
    new URL("../backend/exitlane/static/partials/login.html", import.meta.url),
    "utf8",
  );
  const status = markup.indexOf('id="login-error"');
  const gridStart = markup.indexOf('id="login-fields"');
  const gridEnd = markup.indexOf("</div>", gridStart);
  assert.ok(status > -1 && status < gridStart);
  assert.ok(status < gridStart || status > gridEnd);
  assert.match(markup, /id="login-error"[^>]+role="alert"/);
  assert.match(markup, /class="form-grid login-fields"/);
});
