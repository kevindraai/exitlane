import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  providerAuthenticationErrorCode,
} from "../backend/exitlane/static/js/provider.js";

const providerUrl = new URL(
  "../backend/exitlane/static/js/provider.js",
  import.meta.url,
);
const englishUrl = new URL(
  "../backend/exitlane/static/locales/en.json",
  import.meta.url,
);
const dutchUrl = new URL(
  "../backend/exitlane/static/locales/nl.json",
  import.meta.url,
);

test("provider authentication normalizes supported safe API error shapes", () => {
  assert.equal(
    providerAuthenticationErrorCode({ error: "invalid_token" }),
    "invalid_token",
  );
  assert.equal(
    providerAuthenticationErrorCode({ payload: { detail: "invalid_token" } }),
    "invalid_token",
  );
  assert.equal(
    providerAuthenticationErrorCode({ payload: { error: "token_expired" } }),
    "token_expired",
  );
  assert.equal(
    providerAuthenticationErrorCode({ payload: { detail: "token_revoked" } }),
    "token_revoked",
  );
  assert.equal(
    providerAuthenticationErrorCode({ payload: { detail: { code: "timeout" } } }),
    "timeout",
  );
  assert.equal(
    providerAuthenticationErrorCode({ code: "daemon_unavailable" }),
    "daemon_unavailable",
  );
  assert.equal(
    providerAuthenticationErrorCode({ error: "uncontrolled_provider_output" }),
    "provider_error",
  );
});

test("invalid, expired, revoked, generic, and success messages exist in EN and NL", async () => {
  const [english, dutch] = await Promise.all([
    readFile(englishUrl, "utf8").then(JSON.parse),
    readFile(dutchUrl, "utf8").then(JSON.parse),
  ]);
  assert.equal(
    english.provider.authentication.errors.invalid_token,
    "The supplied access token is invalid. Generate a new access token in your Nord Account and try again.",
  );
  assert.equal(
    dutch.provider.authentication.errors.invalid_token,
    "De opgegeven toegangstoken is ongeldig. Maak in je Nord Account een nieuwe toegangstoken aan en probeer het opnieuw.",
  );
  for (const code of ["token_expired", "token_revoked"]) {
    assert.notEqual(
      english.provider.authentication.errors[code],
      english.provider.authentication.errors.invalid_token,
    );
    assert.notEqual(
      dutch.provider.authentication.errors[code],
      dutch.provider.authentication.errors.invalid_token,
    );
  }
  assert.equal(
    english.provider.authentication.errors.provider_error,
    "NordVPN could not complete sign-in.",
  );
  assert.equal(
    dutch.provider.authentication.errors.provider_error,
    "NordVPN kon de aanmelding niet voltooien.",
  );
  assert.equal(
    english.provider.authentication.success,
    "Signed in to {provider} successfully.",
  );
  assert.equal(
    dutch.provider.authentication.success,
    "Aanmelden bij {provider} is geslaagd.",
  );
});

test("token and callback flows never render provider output and use fixed feedback", async () => {
  const source = await readFile(providerUrl, "utf8");
  const tokenStart = source.indexOf("async function loginWithCredential");
  const callbackStart = source.indexOf("async function loginWithCallback");
  const disconnectStart = source.indexOf("async function disconnectProvider");
  const tokenFlow = source.slice(tokenStart, callbackStart);
  const callbackFlow = source.slice(callbackStart, disconnectStart);

  assert.doesNotMatch(tokenFlow, /result\.(?:stdout|stderr|message)/);
  assert.doesNotMatch(callbackFlow, /result\.(?:stdout|stderr|message)/);
  assert.match(tokenFlow, /showInlineError\(providerAuthenticationErrorMessage\(error, metadata\)\)/);
  assert.match(tokenFlow, /provider\.authentication\.success[\s\S]+?,\s*"success"/);
  assert.match(callbackFlow, /provider\.authentication\.success[\s\S]+?,\s*"success"/);

  const failureCheck = tokenFlow.indexOf("if (!result.ok)");
  const clearInput = tokenFlow.indexOf('input.value = ""');
  assert.ok(clearInput >= 0 && failureCheck > clearInput);
});
