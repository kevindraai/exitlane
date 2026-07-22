import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("country card keeps stable child markup while connecting", async () => {
  const source = await readFile(new URL("../backend/exitlane/static/js/provider.js", import.meta.url), "utf8");
  assert.match(source, /button\.append\(flag, name, detail, status\)/);
  assert.match(source, /country-card__flag/);
  assert.match(source, /country-card__name/);
  assert.match(source, /country-card__latency/);
  assert.match(source, /country-card__status/);
  assert.match(source, /country-card--connecting/);
  assert.doesNotMatch(source, /setBusy\(button, true, t\("provider\.action\.connecting/);
});
