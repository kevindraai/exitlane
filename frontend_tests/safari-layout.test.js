import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const css = fs.readFileSync(
  new URL("../backend/exitlane/static/style.css", import.meta.url),
  "utf8",
);

function rule(selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return css.match(new RegExp(`${escaped}\\s*\\{([^}]+)\\}`))?.[1] || "";
}

test("sticky sidebar avoids the Safari rounded-shadow compositing combination", () => {
  const sidebar = rule(".sidebar");

  assert.match(sidebar, /position:\s*sticky/);
  assert.match(sidebar, /border:\s*1px solid var\(--border\)/);
  assert.match(sidebar, /background:\s*var\(--panel\)/);
  assert.doesNotMatch(sidebar, /box-shadow|backdrop-filter|transform|will-change/);
});

test("application layout keeps scrolling and responsive sidebar behavior intact", () => {
  assert.doesNotMatch(rule("body"), /overflow:\s*hidden/);
  assert.doesNotMatch(rule(".app-shell"), /overflow|transform|will-change|backdrop-filter/);
  assert.doesNotMatch(rule(".app-content"), /overflow|transform|will-change|backdrop-filter/);
  assert.match(
    css,
    /@media \(max-width: 900px\)[\s\S]*?\.sidebar\s*\{[\s\S]*?position:\s*static;[\s\S]*?overflow:\s*visible;/,
  );
  assert.match(rule(".toast-region"), /position:\s*fixed/);
});
