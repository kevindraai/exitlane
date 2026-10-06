import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { chromium } from "playwright";
import { installSyntheticBrowser, syntheticOrigin } from "./synthetic-browser.mjs";
import { fixtureTime, sourceVersion } from "./synthetic-fixture.mjs";
import { assertSafeVisibleState, redactLiveIp } from "./privacy.mjs";
import { prepareCaptureDirectory, resolveCaptureOutput, writeCaptureFile } from "./output-policy.mjs";

const root = path.resolve(import.meta.dirname, "../..");
const publicOutput = path.join(root, "docs/images");
const mode = process.env.EXITLANE_SCREENSHOT_MODE || "synthetic";
if (!["live", "synthetic"].includes(mode)) throw new Error("EXITLANE_SCREENSHOT_MODE must be live or synthetic");
const output = resolveCaptureOutput({ mode, requestedOutput: process.env.EXITLANE_SCREENSHOT_OUTPUT, repositoryRoot: root });
const baseUrl = mode === "synthetic" ? syntheticOrigin : process.env.EXITLANE_SCREENSHOT_BASE_URL;
if (mode === "live" && (!baseUrl || !process.env.EXITLANE_SCREENSHOT_PASSWORD)) {
  throw new Error("Live capture requires EXITLANE_SCREENSHOT_BASE_URL and EXITLANE_SCREENSHOT_PASSWORD");
}
if (mode === "live" && !/^https?:\/\//.test(baseUrl)) throw new Error("Live base URL must be HTTP(S)");
const git = (args) => {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr || result.error?.message}`);
  return result.stdout.trim();
};
const sourceCommit = git(["rev-parse", "HEAD"]);
const sourceTree = git(["rev-parse", `${sourceCommit}^{tree}`]);
const clean = !git(["status", "--porcelain", "--untracked-files=normal"]);
if (output === publicOutput && !clean) throw new Error("Public screenshot capture requires committed, clean source");
if (mode === "live" && process.env.EXITLANE_SCREENSHOT_DEPLOYED_COMMIT !== sourceCommit) {
  throw new Error("Live capture requires EXITLANE_SCREENSHOT_DEPLOYED_COMMIT matching the local source commit");
}
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const profiles = {
  readme: { width: 1440, height: 1200, directory: output },
  promo: { width: 1600, height: 1080, directory: path.join(output, "promo") },
};
const captures = [
  { id: "dashboard", route: "#dashboard", files: { readme: "exitlane-dashboard.png", promo: "exitlane-dashboard-hero.png" }, ready: async (page) => {
    await page.locator("#dashboard-health-state").getByText(/Healthy/i).waitFor();
    await page.locator("#dashboard-vpn-pill").getByText(/Connected/i).waitFor();
    await page.locator("#dashboard-wg-peer-list tr").first().waitFor();
    if (mode === "synthetic" && await page.locator("#dashboard-wg-peer-list tr").count() !== 3) throw new Error("Synthetic dashboard needs three current device rows");
  } },
  { id: "vpn", route: "#vpn/provider/nordvpn", files: { readme: "exitlane-vpn-selection.png" }, ready: async (page) => {
    await page.locator("#connection-state").getByText(/Connected/i).waitFor();
    if (mode === "synthetic") {
      await page.locator("#quick-countries .country-card").first().waitFor();
      await page.waitForFunction(() => [...document.querySelectorAll("#quick-countries .country-card")].every((card) => !/Measuring|Meten/i.test(card.innerText)));
    }
  } },
  { id: "diagnostics", route: "#diagnostics", height: 720, files: { readme: "exitlane-diagnostics.png" }, ready: async (page) => {
    await page.waitForFunction(() => /passed|geslaagd/i.test(document.querySelector("#connection-diagnostics-summary")?.textContent || ""));
    if (await page.locator("[data-diagnostic-node][data-status='failed']").count()) throw new Error("Diagnostics has failed nodes");
  } },
  { id: "wireguard", route: "#wireguard", height: 1120, files: { readme: "exitlane-wireguard.png" }, ready: async (page) => {
    await page.locator("#management-wireguard-state").getByText(/Active|Actief/i).waitFor();
    if (mode === "synthetic") {
      await page.locator("#wireguard-peer-list tr").first().waitFor();
      if (await page.locator("#wireguard-peer-list tr").count() !== 3) throw new Error("Synthetic WireGuard needs three current device rows");
    } else {
      await page.locator("#wireguard-peers-loading").waitFor({ state: "hidden" });
    }
  } },
  { id: "documentation", route: "#help", height: 1080, files: { readme: "exitlane-documentation.png" }, ready: async (page) => {
    await page.locator("#help-loading").waitFor({ state: "hidden" });
    if (await page.locator(".help-category-card").count() < 4) throw new Error("Help catalog is incomplete");
  } },
];

async function navigate(page, route) {
  await page.evaluate((next) => { window.location.hash = next; window.dispatchEvent(new PopStateEvent("popstate")); }, route);
  const view = route.startsWith("#vpn/provider/") ? "vpn-provider" : route.slice(1).split("/")[0];
  await page.locator(`[data-view-panel="${view}"]`).waitFor({ state: "visible" });
}

async function startPage(page) {
  await page.goto(`${baseUrl}/#dashboard`, { waitUntil: "domcontentloaded" });
  if (mode === "live") {
    await page.locator("#login-panel").waitFor({ state: "visible" });
    await page.locator("#login-username").fill(process.env.EXITLANE_SCREENSHOT_USERNAME || "admin");
    await page.locator("#login-password").fill(process.env.EXITLANE_SCREENSHOT_PASSWORD);
    await page.locator('#login-form button[type="submit"]').click();
  }
  await page.locator("#dashboard-panel").waitFor({ state: "visible" });
  await page.locator("#dashboard-version").getByText(`v${sourceVersion}`).waitFor();
}

async function verifyLiveAssets(page) {
  if (mode !== "live") return { basis: "local source files loaded through the synthetic browser" };
  const digests = {};
  for (const asset of ["js/app.js", "style.css"]) {
    const response = await page.request.get(`${baseUrl}/assets/${asset}`);
    if (!response.ok()) throw new Error(`Live source asset unavailable: ${asset}`);
    const observed = sha256(await response.body());
    const local = sha256(await readFile(path.join(root, "backend/exitlane/static", asset)));
    if (observed !== local) throw new Error(`Live source asset differs from checkout: ${asset}`);
    digests[asset] = local;
  }
  return { basis: "operator-declared deployed commit; served JavaScript and CSS digests matched local source; rendered version matched", deployed_commit_assertion: sourceCommit, matched_asset_sha256: digests };
}

async function activeLiveProvider(page) {
  if (mode !== "live") return "nordvpn";
  const response = await page.request.get(`${baseUrl}/api/vpn/providers`);
  if (!response.ok()) throw new Error("Cannot read the active provider on the reference appliance");
  const { active_provider_id: id } = await response.json();
  if (!/^[a-z0-9-]+$/.test(id || "")) throw new Error("Reference appliance has no valid active provider");
  return id;
}

async function assertWireGuardActionsVisible(page) {
  const visible = await page.evaluate(() => {
    const wrapper = document.querySelector("#wireguard-peers-content").getBoundingClientRect();
    return [...document.querySelectorAll(".wireguard-peer-menu-trigger")].every((button) => {
      const bounds = button.getBoundingClientRect();
      return bounds.left >= wrapper.left - 1 && bounds.right <= wrapper.right + 1 && bounds.right <= innerWidth + 1;
    });
  });
  if (!visible) throw new Error("WireGuard action buttons are clipped in the captured viewport");
}

for (const { directory } of Object.values(profiles)) {
  await prepareCaptureDirectory(directory, { mode, repositoryRoot: root });
}
const manifest = {
  generated_at: new Date().toISOString(), source_version: sourceVersion, source_commit: sourceCommit,
  source_tree: sourceTree, source_worktree_clean_at_start: clean, source_appliance: mode === "live" ? "designated-reference-appliance" : null,
  language: "en", appearance: "dark", mode, api_interception: mode === "synthetic", speedtest_started: false,
  publication_status: mode === "live" ? "private-candidate-requires-operator-privacy-review" : "public-product-illustration",
  runtime_qualification_evidence: false,
  screenshots: [],
};
const browser = await chromium.launch({ headless: true });
try {
  for (const [profile, dimensions] of Object.entries(profiles)) {
    const context = await browser.newContext({ viewport: { width: dimensions.width, height: dimensions.height }, colorScheme: "dark", locale: "en-GB", reducedMotion: "reduce", deviceScaleFactor: 1 });
    await context.addInitScript(() => {
      localStorage.setItem("exitlane-language", "en");
      localStorage.setItem("exitlane-color-scheme", "dark");
      localStorage.setItem("exitlane-active-view", "dashboard");
    });
    const synthetic = mode === "synthetic" ? await installSyntheticBrowser(context) : null;
    const page = await context.newPage();
    if (synthetic) await page.clock.setFixedTime(new Date(fixtureTime));
    page.setDefaultTimeout(30_000);
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.origin === new URL(baseUrl).origin && url.pathname.startsWith("/api/") && response.status() >= 400) {
        errors.push(`API ${url.pathname} returned ${response.status()}`);
      }
    });
    await startPage(page);
    const sourceVerification = await verifyLiveAssets(page);
    const providerId = await activeLiveProvider(page);
    for (const capture of captures.filter((item) => item.files[profile])) {
      const viewport = { width: dimensions.width, height: capture.height || dimensions.height };
      await page.setViewportSize(viewport);
      await navigate(page, capture.id === "vpn" ? `#vpn/provider/${providerId}` : capture.route);
      await capture.ready(page);
      if (capture.id === "wireguard") await assertWireGuardActionsVisible(page);
      await page.evaluate(() => { document.activeElement?.blur(); scrollTo(0, 0); });
      const redactions = await redactLiveIp(page, capture.id, mode);
      await assertSafeVisibleState(page, capture.id);
      if (synthetic?.failures.length || errors.length) throw new Error(`${capture.id}: browser errors ${JSON.stringify([...(synthetic?.failures || []), ...errors])}`);
      const destination = path.join(dimensions.directory, capture.files[profile]);
      const png = await page.screenshot({ animations: "disabled" });
      await writeCaptureFile(destination, png, { mode });
      manifest.screenshots.push({
        id: capture.id, profile, file: path.relative(root, destination), viewport, png_sha256: sha256(png),
        source_commit: sourceCommit, source_tree: sourceTree, source_worktree_clean_at_start: clean,
        language: "en", appearance: "dark", mode, api_interception: mode === "synthetic",
        presentation_provenance: mode === "synthetic" ? "current source UI with deterministic local fixture" : "observed appliance UI",
        source_verification: sourceVerification,
        state: mode === "synthetic" ? "synthetic-presentation" : redactions.length ? "live-runtime-controlled-redaction" : "live-runtime",
        fixture_id: synthetic?.fixture.fixtureId || null, fixture_sha256: synthetic?.fixture.fixtureHash || null,
        fixture_hash_scope: synthetic ? "fixture source file" : null,
        fixture_time: synthetic ? fixtureTime : null,
        redactions, sensitive_ui: "configuration, QR, credentials and MFA controls closed",
        publication_status: mode === "live" ? "private-candidate-requires-operator-privacy-review" : "public-product-illustration",
      });
    }
    await context.close();
  }
} finally { await browser.close(); }
await writeCaptureFile(path.join(output, "screenshot-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { mode });
console.log(`Captured ${manifest.screenshots.length} ${mode} screenshots to ${output}`);
