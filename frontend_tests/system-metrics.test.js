import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("System metrics markup includes CPU, load average, memory, and disk placeholders", async () => {
  const markup = await read("../backend/exitlane/static/partials/views/dashboard.html");
  for (const id of ["dashboard-cpu", "dashboard-load", "dashboard-memory", "dashboard-disk"]) {
    assert.match(markup, new RegExp(`<strong id="${id}">—</strong>`));
  }
});

test("System CPU rendering uses the shared deterministic formatter", async () => {
  const dashboard = await read("../backend/exitlane/static/js/dashboard.js");
  assert.match(
    dashboard,
    /text\("#dashboard-cpu", formatCpuPercent\(data\.system\.cpu_percent\)\)/,
  );
});
