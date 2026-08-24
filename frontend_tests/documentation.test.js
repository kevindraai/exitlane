import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { safeDocumentationHref } from "../backend/exitlane/static/js/documentation.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("documentation links accept only local help routes and credential-free HTTPS URLs", () => {
  assert.equal(safeDocumentationHref("#help/diagnostics"), "#help/diagnostics");
  assert.equal(
    safeDocumentationHref("#help/authentication#session-model"),
    "#help/authentication#session-model",
  );
  assert.equal(safeDocumentationHref("https://example.com/guide"), "https://example.com/guide");
  for (const unsafe of [
    "javascript:alert(1)",
    "data:text/html,boom",
    "http://example.com",
    "https://user:secret@example.com",
    "//example.com",
  ]) {
    assert.equal(safeDocumentationHref(unsafe), null);
  }
});

test("documentation rendering constructs text-only DOM without an HTML parsing sink", async () => {
  const source = await read("../backend/exitlane/static/js/documentation.js");
  assert.doesNotMatch(source, /\.innerHTML\s*=|insertAdjacentHTML|DOMParser|document\.write/);
  assert.match(source, /document\.createElement/);
  assert.match(source, /\.textContent\s*=/);
  assert.match(source, /list\.start = Number\(block\.start\)/);
  assert.match(source, /rel = "noopener noreferrer"/);
});

test("help navigation and required contextual guides are integrated in the application shell", async () => {
  const [sidebar, help, diagnostics, wireguard, vpn, settings] = await Promise.all([
    read("../backend/exitlane/static/partials/sidebar.html"),
    read("../backend/exitlane/static/partials/views/help.html"),
    read("../backend/exitlane/static/partials/views/diagnostics.html"),
    read("../backend/exitlane/static/partials/views/wireguard.html"),
    read("../backend/exitlane/static/partials/views/vpn-overview.html"),
    read("../backend/exitlane/static/partials/views/settings.html"),
  ]);
  assert.match(sidebar, /data-view="help"/);
  assert.match(help, /data-view-panel="help"/);
  assert.match(help, /data-i18n="help\.developer_note"/);
  assert.match(diagnostics, /data-help-document="diagnostics"/);
  assert.match(wireguard, /data-help-document="wireguard-configuration"/);
  assert.match(vpn, /data-help-document="killswitch"/);
  for (const slug of [
    "authentication",
    "mfa",
    "reverse-proxy",
    "backup-and-restore",
    "upgrade-and-recovery",
  ]) {
    assert.match(settings, new RegExp(`data-help-document="${slug}"`));
  }
});

test("opening the help navigation resets an active document route to the index", async () => {
  const source = await read("../backend/exitlane/static/js/documentation.js");
  assert.match(source, /querySelector\('\[data-view="help"\]'\)/);
  assert.match(source, /window\.location\.hash !== "#help"/);
  assert.match(source, /pushState\(null, "", "#help"\)/);
});

test("Cobalt Slate semantics replace self-referential dark-mode component tokens", async () => {
  const [index, styles] = await Promise.all([
    read("../backend/exitlane/static/index.html"),
    read("../backend/exitlane/static/style.css"),
  ]);
  assert.match(index, /data-nlf-theme="cobalt-slate"/);
  assert.match(styles, /--nlf-background: #1a1a1d/);
  assert.match(styles, /--nlf-primary: #657fad/);
  assert.doesNotMatch(styles, /--(code-background|track-background|toast-background): var\(--\1\)/);
  assert.match(styles, /--code-background: #101114/);
  assert.match(styles, /--track-background: var\(--nlf-surface-elevated\)/);
  assert.match(styles, /--toast-background: var\(--nlf-surface-elevated\)/);
});

test("dark elevated panels retain normal-text contrast for muted copy and links", async () => {
  const styles = await read("../backend/exitlane/static/style.css");
  const dark = styles.match(/html\[data-color-scheme="dark"\] \{([\s\S]*?)\n\}/)?.[1] || "";
  const value = (name) => {
    const match = dark.match(new RegExp(`--${name}:\\s*(#[0-9a-f]{6})`, "i"));
    assert.ok(match, `missing dark color ${name}`);
    return match[1];
  };
  const luminance = (hex) => {
    const channels = [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
    return channels.reduce((sum, channel, index) => {
      const linear = channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
      return sum + linear * [0.2126, 0.7152, 0.0722][index];
    }, 0);
  };
  const contrast = (foreground, background) => {
    const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
    return (values[0] + 0.05) / (values[1] + 0.05);
  };
  const elevated = value("nlf-surface-elevated");
  assert.ok(contrast(value("nlf-text-muted-elevated"), elevated) >= 4.5);
  assert.ok(contrast(value("nlf-info"), elevated) >= 4.5);
  assert.match(dark, /--muted: var\(--nlf-text-muted-elevated\)/);
  assert.match(dark, /--accent-text: var\(--nlf-info\)/);
});
