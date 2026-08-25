import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => readFile(path.join(repositoryRoot, relativePath), "utf8");

test("README image references exist and use the curated RC asset set", async () => {
  const readme = await read("README.md");
  const references = [...readme.matchAll(/!\[[^\]]*\]\((docs\/images\/[^)]+)\)/g)]
    .map((match) => match[1]);
  const expected = [
    "docs/images/promo/exitlane-dashboard-hero.png",
    "docs/images/exitlane-dashboard.png",
    "docs/images/exitlane-vpn-selection.png",
    "docs/images/exitlane-diagnostics.png",
    "docs/images/exitlane-wireguard.png",
    "docs/images/exitlane-documentation.png",
  ];
  assert.deepEqual(references, expected);
  await Promise.all(references.map((reference) => access(path.join(repositoryRoot, reference))));
});

test("screenshot workflow covers current routes and declares every output", async () => {
  const [automation, manifest] = await Promise.all([
    read("tests/screenshots/capture.mjs"),
    read("docs/images/screenshot-manifest.json").then(JSON.parse),
  ]);
  for (const route of ["#dashboard", "#vpn/provider/nordvpn", "#diagnostics", "#wireguard", "#help"]) {
    assert.match(automation, new RegExp(`route: \\"${route.replaceAll("/", "\\/")}\\"`));
  }
  assert.equal(manifest.network_mocking, false);
  assert.equal(manifest.speedtest_started, false);
  assert.match(manifest.source_commit, /^[0-9a-f]{40}$/);
  assert.match(manifest.source_tree, /^[0-9a-f]{40}$/);
  assert.equal(manifest.source_worktree_clean, true);
  assert.equal(
    execFileSync("git", ["rev-parse", `${manifest.source_commit}^{tree}`], {
      cwd: repositoryRoot,
      encoding: "utf8",
    }).trim(),
    manifest.source_tree,
  );
  execFileSync("git", ["merge-base", "--is-ancestor", manifest.source_commit, "HEAD"], {
    cwd: repositoryRoot,
  });
  assert.equal(manifest.screenshots.length, 9);
  const redacted = manifest.screenshots.filter((screenshot) => screenshot.redactions.length);
  assert.deepEqual(
    redacted.map(({ id, profile, state }) => ({ id, profile, state })),
    [
      { id: "dashboard", profile: "readme", state: "live-runtime-controlled-redaction" },
      { id: "vpn", profile: "readme", state: "live-runtime-controlled-redaction" },
      { id: "dashboard", profile: "promo", state: "live-runtime-controlled-redaction" },
      { id: "vpn", profile: "promo", state: "live-runtime-controlled-redaction" },
    ],
  );
  assert.ok(redacted.every((screenshot) => (
    screenshot.redactions.length === 1
    && screenshot.redactions[0].field === "external IP"
  )));
  assert.match(automation, /visible content contains an unredacted public IP address/);
  assert.doesNotMatch(automation, /(?:page|context)\.route\s*\(/);
  await Promise.all(manifest.screenshots.map((screenshot) => (
    access(path.join(repositoryRoot, screenshot.file))
  )));
});
