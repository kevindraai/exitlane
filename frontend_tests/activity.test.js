import assert from "node:assert/strict";
import test from "node:test";
import { eventTranslation, mergeEventPages, normaliseFilters, safeDetails } from "../backend/exitlane/static/js/activity-format.js";

test("event translations use stable codes and safe parameters", () => {
  assert.deepEqual(eventTranslation({ code: "settings.updated", metadata: { fields: ["timezone"] } }), {
    key: "events.settings.updated", variables: { fields: "timezone" }, fallback: "settings.updated",
  });
  assert.equal(eventTranslation({ code: "future.event", metadata: null }).fallback, "future.event");
});

test("pages merge without duplicates newest first", () => {
  assert.deepEqual(mergeEventPages([{ id: 3 }, { id: 2 }], [{ id: 2 }, { id: 1 }]).map(({ id }) => id), [3, 2, 1]);
});

test("filters and details reject unsupported shapes", () => {
  assert.deepEqual(normaliseFilters({ category: "secret", level: "fatal" }), { category: "", level: "" });
  assert.deepEqual(safeDetails({ metadata: { value: "x", nested: { password: "no" }, empty: null } }), [["value", "x"]]);
  assert.deepEqual(safeDetails({ metadata: null }), []);
});
