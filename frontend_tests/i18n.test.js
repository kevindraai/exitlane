import assert from "node:assert/strict";
import test from "node:test";

import {
  detectBrowserLanguage,
  resolveLanguage,
} from "../backend/exitlane/static/js/i18n.js";

test("resolves nl-NL to Dutch", () => {
  assert.equal(resolveLanguage(null, ["nl-NL"], "en-US"), "nl");
});

test("resolves nl-BE to Dutch", () => {
  assert.equal(resolveLanguage(null, ["nl-BE"], "en-US"), "nl");
});

test("resolves an English browser variant", () => {
  assert.equal(resolveLanguage(null, ["en-GB"], "nl-NL"), "en");
});

test("falls back to English for an unsupported browser language", () => {
  assert.equal(resolveLanguage(null, ["de-DE"], "de-DE"), "en");
});

test("prefers a stored English language over the browser language", () => {
  assert.equal(resolveLanguage("en", ["nl-NL"], "nl-NL"), "en");
});

test("prefers a stored Dutch language over the browser language", () => {
  assert.equal(resolveLanguage("nl", ["en-US"], "en-US"), "nl");
});

test("ignores an invalid stored language", () => {
  assert.equal(resolveLanguage("de", ["nl-NL"], "nl-NL"), "nl");
});

test("uses navigator.language when navigator.languages is empty", () => {
  assert.equal(detectBrowserLanguage([], "nl-NL"), "nl");
  assert.equal(resolveLanguage(null, [], "nl-NL"), "nl");
});
