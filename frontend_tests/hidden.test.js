import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("global hidden rule overrides explicit component display styles", async () => {
  const css = await readFile(new URL("../backend/exitlane/static/style.css", import.meta.url), "utf8");
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none\s*!important;/);
});
