import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("technical values use single-line truncation with keyboard and touch disclosure", async () => {
  const [css, ui] = await Promise.all([
    read("../backend/exitlane/static/style.css"),
    read("../backend/exitlane/static/js/ui.js"),
  ]);
  assert.match(css, /\.technical-value\s*\{[\s\S]*?text-overflow:\s*ellipsis;[\s\S]*?white-space:\s*nowrap;/);
  assert.match(css, /\.technical-value:focus\s*\{[\s\S]*?white-space:\s*normal;/);
  assert.match(ui, /document\.createElement\("wbr"\)/);
  assert.match(ui, /setAttribute\("aria-label", displayed\)/);
  assert.match(ui, /element\.tabIndex = 0/);
});

test("dashboard sizing does not apply arbitrary wrapping to normal technical values", async () => {
  const [css, dashboard, dashboardHtml, wireguard, provider] = await Promise.all([
    read("../backend/exitlane/static/style.css"),
    read("../backend/exitlane/static/js/dashboard.js"),
    read("../backend/exitlane/static/partials/views/dashboard.html"),
    read("../backend/exitlane/static/js/wireguard-management.js"),
    read("../backend/exitlane/static/js/provider.js"),
  ]);
  const dashboardRule = css.match(/\.dashboard-card \.metric strong\s*\{([^}]+)\}/)?.[1] || "";
  assert.match(dashboardRule, /overflow-wrap:\s*normal/);
  assert.match(dashboardRule, /word-break:\s*normal/);
  assert.doesNotMatch(dashboardRule, /anywhere|break-all/);
  assert.match(css, /\.dashboard-metrics\s*\{[\s\S]*?minmax\(min\(100%, 10rem\), 1fr\)/);
  assert.match(css, /\.metric-technical-wide\s*\{[\s\S]*?grid-column:\s*span 2/);
  assert.match(css, /\.metric strong\.technical-value\s*\{[\s\S]*?overflow-wrap:\s*normal;[\s\S]*?word-break:\s*normal;/);
  assert.match(dashboardHtml, /metric metric-technical-wide[^>]*>[\s\S]*?dashboard-vpn-server/);
  assert.match(dashboardHtml, /metric metric-technical-wide[^>]*>[\s\S]*?dashboard-wg-endpoint/);
  assert.match(dashboard, /setTechnicalValue\(select\("#dashboard-vpn-server"\)/);
  assert.match(dashboard, /setTechnicalValue\(select\("#dashboard-wg-endpoint"\)/);
  assert.match(wireguard, /setTechnicalValue\(select\("#management-wireguard-endpoint"\)/);
  assert.match(provider, /setTechnicalValue\(select\("#metric-server"\)/);
});
