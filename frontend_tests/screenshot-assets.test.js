import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createSyntheticFixture, fixtureTime, sourceVersion } from "../tests/screenshots/synthetic-fixture.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => readFile(path.join(root, relative), "utf8");
const expected = [
  "docs/images/promo/exitlane-dashboard-hero.png",
  "docs/images/exitlane-dashboard.png",
  "docs/images/exitlane-vpn-selection.png",
  "docs/images/exitlane-diagnostics.png",
  "docs/images/exitlane-wireguard.png",
  "docs/images/exitlane-documentation.png",
];

test("README uses the six curated current-product images", async () => {
  const references = [...(await read("README.md")).matchAll(/!\[[^\]]*\]\((docs\/images\/[^)]+)\)/g)].map((match) => match[1]);
  assert.deepEqual(references, expected);
  await Promise.all(expected.map((file) => access(path.join(root, file))));
});

test("each published image records source and synthetic presentation provenance", async () => {
  const manifest = JSON.parse(await read("docs/images/screenshot-manifest.json"));
  const fixture = createSyntheticFixture();
  assert.equal(manifest.source_version, sourceVersion);
  assert.match(manifest.source_commit, /^[0-9a-f]{40}$/);
  assert.match(manifest.source_tree, /^[0-9a-f]{40}$/);
  assert.equal(manifest.source_worktree_clean_at_start, true);
  assert.equal(manifest.mode, "synthetic");
  assert.equal(manifest.api_interception, true);
  assert.equal(manifest.speedtest_started, false);
  assert.equal(manifest.publication_status, "public-product-illustration");
  assert.equal(manifest.runtime_qualification_evidence, false);
  assert.deepEqual(manifest.screenshots.map(({ file }) => file).sort(), [...expected].sort());
  for (const shot of manifest.screenshots) {
    assert.equal(shot.source_commit, manifest.source_commit);
    assert.equal(shot.source_tree, manifest.source_tree);
    assert.equal(shot.source_worktree_clean_at_start, true);
    assert.equal(shot.language, manifest.language);
    assert.equal(shot.appearance, manifest.appearance);
    assert.equal(shot.mode, "synthetic");
    assert.equal(shot.api_interception, true);
    assert.equal(shot.state, "synthetic-presentation");
    assert.equal(shot.fixture_id, fixture.fixtureId);
    assert.equal(shot.fixture_sha256, fixture.fixtureHash);
    assert.equal(shot.fixture_time, fixtureTime);
    assert.equal(shot.publication_status, "public-product-illustration");
    assert.deepEqual(shot.redactions, []);
    assert.match(shot.sensitive_ui, /closed/);
    const bytes = await readFile(path.join(root, shot.file));
    assert.equal(bytes.toString("ascii", 1, 4), "PNG");
    assert.equal(bytes.readUInt32BE(16), shot.viewport.width);
    assert.equal(bytes.readUInt32BE(20), shot.viewport.height);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), shot.png_sha256);
  }
});
