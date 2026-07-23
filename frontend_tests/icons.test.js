import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  LUCIDE_ICON_NAMES,
  LUCIDE_VERSION,
  resolveIconName,
  statusIconName,
} from "../backend/exitlane/static/js/icons.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("local Lucide subset is pinned and icon identifiers use a safe allowlist", () => {
  assert.equal(LUCIDE_VERSION, "1.26.0");
  assert.ok(LUCIDE_ICON_NAMES.includes("shield-check"));
  assert.equal(resolveIconName("server"), "server");
  assert.equal(resolveIconName("provider-unknown"), "shield-check");
  assert.equal(resolveIconName("<svg onload=alert(1)>"), "shield-check");
  assert.equal(resolveIconName("https://example.test/icon.svg"), "shield-check");
});

test("sidebar uses the expected Lucide mapping without legacy emoji or inline SVG", async () => {
  const sidebar = await read("../backend/exitlane/static/partials/sidebar.html");
  const expected = [
    "layout-dashboard",
    "shield",
    "chart-no-axes-column",
    "key-round",
    "history",
    "shield-check",
    "settings",
  ];
  for (const icon of expected) {
    assert.match(sidebar, new RegExp(`data-lucide-icon="${icon}"`));
  }
  assert.doesNotMatch(sidebar, /🏠|🌍|🔑|🔒|⚙|⌄/u);
  assert.doesNotMatch(sidebar, /<svg/i);
});

test("SVG helper uses currentColor, decorative accessibility, and no HTML injection", async () => {
  const source = await read("../backend/exitlane/static/js/icons.js");
  assert.match(source, /setAttribute\("stroke", "currentColor"\)/);
  assert.match(source, /setAttribute\("aria-hidden", "true"\)/);
  assert.match(source, /setAttribute\("aria-label", label\)/);
  assert.match(source, /document\.createElementNS/);
  assert.doesNotMatch(source, /innerHTML|outerHTML|fetch\(|setAttribute\("(?:src|href)"/);
});

test("VPN group switches allowlisted chevrons while retaining aria-expanded", async () => {
  const [markup, providers] = await Promise.all([
    read("../backend/exitlane/static/partials/sidebar.html"),
    read("../backend/exitlane/static/js/providers.js"),
  ]);
  assert.match(markup, /aria-expanded="false"[^>]+id="vpn-navigation-toggle"/);
  assert.match(markup, /data-lucide-icon="chevron-right"/);
  assert.match(providers, /toggle\.setAttribute\("aria-expanded", String\(expanded\)\)/);
  assert.match(providers, /expanded \? "chevron-down" : "chevron-right"/);
});

test("status icons supplement visible status text and map every semantic state", async () => {
  assert.equal(statusIconName("connected"), "circle-check");
  assert.equal(statusIconName("disconnected"), "circle");
  assert.equal(statusIconName("connecting"), "loader-circle");
  assert.equal(statusIconName("error"), "circle-alert");
  assert.equal(statusIconName("unknown"), "circle-question-mark");
  const providers = await read("../backend/exitlane/static/js/providers.js");
  assert.match(providers, /badge\.append\(badgeIcon, badgeText\)/);
  assert.match(providers, /badgeText\.textContent = overviewStatusLabel/);
});

test("spinner animation respects reduced motion and icons inherit both themes", async () => {
  const styles = await read("../backend/exitlane/static/style.css");
  assert.match(styles, /\.lucide-icon[\s\S]+color: currentColor/);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)[\s\S]+animation: none/);
  assert.doesNotMatch(styles, /\\.provider-overview-status--busy::before/);
});

test("provider page decorates authentication and metrics without replacing labels", async () => {
  const markup = await read("../backend/exitlane/static/partials/views/vpn.html");
  for (const icon of ["user-round-check", "map-pinned", "server", "globe", "gauge", "log-in", "log-out"]) {
    assert.match(markup, new RegExp(`data-lucide-icon="${icon}"`));
  }
  assert.match(markup, /data-i18n="provider\.management\.authentication_title"/);
  assert.match(markup, /data-i18n="provider\.access\.go_to_sign_in"/);
  assert.doesNotMatch(markup, /<svg/i);
});
