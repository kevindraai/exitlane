import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { chromium } from "playwright";

// Dedicated disposable appliance only: incomplete setup, administrator created,
// Mullvad prerequisites available and NordVPN absent. No VPN credentials are used.
const base = process.env.EXITLANE_QA_BASE_URL || "http://127.0.0.1:8787";
const adminFile = process.env.EXITLANE_QA_ADMIN_FILE;
const output = process.env.EXITLANE_QA_OUTPUT;
assert.ok(adminFile && output, "Set EXITLANE_QA_ADMIN_FILE and EXITLANE_QA_OUTPUT");
const browser = await chromium.launch({
  headless: true,
  ...(process.env.EXITLANE_QA_CHROMIUM ? { executablePath: process.env.EXITLANE_QA_CHROMIUM } : {}),
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const context = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
await context.addInitScript(() => localStorage.setItem("exitlane-language", "en"));
await mkdir(output, { recursive: true, mode: 0o700 });
const page = await context.newPage();
page.setDefaultTimeout(30000);
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
let installationPosts = 0;
let authenticationPosts = 0;
page.on("request", (request) => {
  if (request.method() === "POST" && request.url().endsWith("/installation")) installationPosts++;
  if (request.method() === "POST" && /\/api\/(?:vpn\/providers\/[^/]+\/authenticate|providers\/nordvpn\/(?:token|login|callback|browser))/.test(request.url())) authenticationPosts++;
});
const result = { real_appliance_api: true, real_installation: false };
async function providerReady(id) {
  await page.evaluate(async () => {
    window.__wizardQaGetSlice = (await import("/assets/js/state.js")).getSlice;
  });
  await page.waitForFunction((providerId) => {
    const slice = window.__wizardQaGetSlice("provider");
    return slice.data?.management?.provider?.id === providerId && !slice.stale;
  }, id);
}
async function tab(id) {
  await page.locator(`#wizard-provider-tab-${id}`).click();
  await page.waitForFunction((providerId) => document.querySelector(`#wizard-provider-tab-${providerId}`).getAttribute("aria-selected") === "true", id);
  await providerReady(id);
}
async function visible(selector) { await page.locator(selector).waitFor({ state: "visible" }); }
try {
  const admin = JSON.parse(await readFile(adminFile, "utf8"));
  assert.equal((await context.request.post(`${base}/api/auth/login`, { data: admin })).status(), 200);
  admin.password = "";
  const state = await (await context.request.get(`${base}/api/setup/state`)).json();
  assert.equal(state.complete, false);
  assert.equal(state.providers.find((p) => p.id === "nordvpn").status.installed, false);
  assert.equal((await context.request.post(`${base}/api/setup/providers`, { data: { provider_ids: ["nordvpn"] } })).status(), 200);
  await page.goto(base, { waitUntil: "networkidle" });
  await visible("#step-3");
  await visible("#provider-install");
  const selectionPattern = "**/api/setup/providers";
  await page.route(selectionPattern, (route) => route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ detail: "provider_selection_conflict" }) }));
  await page.locator('input[data-provider-id="mullvad"]').check();
  await page.waitForFunction(() => !document.querySelector('input[data-provider-id="mullvad"]').checked);
  await page.unroute(selectionPattern);
  result.rejected_selection_restored = true;
  await page.locator('input[data-provider-id="mullvad"]').check();
  await page.waitForLoadState("networkidle");
  await providerReady("mullvad");
  await visible("#mullvad-account-number");
  assert.equal(await page.locator("#provider-install").isVisible(), false);
  for (let i = 0; i < 3; i++) {
    await tab("nordvpn"); await visible("#provider-install");
    assert.equal(await page.locator("#provider-install").isEnabled(), true);
    await tab("mullvad"); await visible("#mullvad-account-number");
  }
  result.repeated_provider_switches = 6;
  await page.locator("#wizard-provider-tab-mullvad").press("ArrowRight");
  await providerReady("nordvpn");
  assert.equal(await page.locator("#wizard-provider-tab-nordvpn").evaluate((e) => e === document.activeElement), true);
  await visible("#provider-install");
  assert.equal(await page.locator('#wizard-provider-tabs [tabindex="0"]').count(), 1);
  result.provider_tabs_keyboard = true;
  await page.locator("#step-3").screenshot({ path: `${output}/after-nordvpn.png` });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.locator("#step-3").screenshot({ path: `${output}/after-mobile.png` });
  result.mobile_no_horizontal_overflow = true;
  await page.setViewportSize({ width: 1280, height: 1100 });

  // Hold a real Mullvad installation response until NordVPN is selected.
  // This tests response ordering; the response body is not fabricated.
  let releaseResponse, responseHeld;
  const held = new Promise((resolve) => { responseHeld = resolve; });
  const release = new Promise((resolve) => { releaseResponse = resolve; });
  const pattern = "**/api/vpn/providers/mullvad/installation";
  await page.route(pattern, async (route) => {
    const response = await route.fetch(); responseHeld(); await release;
    await route.fulfill({ response });
  });
  await page.locator("#wizard-provider-tab-mullvad").click();
  await held;
  await page.locator("#wizard-provider-tab-nordvpn").click();
  await providerReady("nordvpn");
  const oldResponse = page.waitForResponse((r) => r.url().endsWith("/mullvad/installation"));
  releaseResponse();
  await (await oldResponse).finished();
  await page.evaluate(() => new Promise(requestAnimationFrame));
  await page.unroute(pattern);
  await visible("#provider-install");
  assert.equal(await page.locator("#provider-install-disclosure").isVisible(), false);
  result.delayed_previous_provider_response_ignored = true;

  page.once("dialog", (dialog) => dialog.dismiss());
  await page.locator("#provider-install").click();
  assert.equal(installationPosts, 0);
  result.install_cancel_no_mutation = true;
  assert.equal(process.env.EXITLANE_QA_ALLOW_INSTALL, "1", "Real installation requires explicit invocation opt-in");
  page.once("dialog", (dialog) => dialog.accept());
  const installStarted = page.waitForResponse((r) => r.url().endsWith("/nordvpn/installation") && r.request().method() === "POST");
  await page.locator("#provider-install").click();
  assert.equal((await installStarted).status(), 202);
  await tab("mullvad"); await visible("#mullvad-account-number");
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator("#wizard-provider-tabs").waitFor({ state: "visible" });
  await tab("nordvpn");
  await page.locator("#nord-token").waitFor({ state: "visible", timeout: 300000 });
  assert.equal(installationPosts, 1);
  result.real_installation = true;
  result.reload_resumes_installation = true;
  result.installation_posts = installationPosts;
  await page.locator("#login-method-browser").click(); await visible("#login-panel-browser");
  await page.locator("#login-method-browser").press("ArrowLeft"); await visible("#login-panel-token");
  assert.equal(await page.locator("#login-method-token").evaluate((e) => e === document.activeElement), true);
  result.sign_in_tabs_keyboard = true;
  await page.locator("#provider-install-disclosure").screenshot({ path: `${output}/installed.png` });
  const catalog = await (await context.request.get(`${base}/api/help/documents`)).json();
  assert.ok(catalog.documents.some((d) => d.slug === "nordvpn"));
  result.nordvpn_guide_in_catalogue = true;
  assert.equal(authenticationPosts, 0);
  result.provider_authentication_attempts = authenticationPosts;
  result.javascript_errors = errors;
  assert.deepEqual(errors, []);
  await writeFile(`${output}/wizard-results.json`, JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
} catch (error) {
  const diagnosis = await page.evaluate(async () => {
    const { getSlice } = await import("/assets/js/state.js");
    return { application: getSlice("application"), management: getSlice("provider").data?.management,
      installDisabled: document.querySelector("#provider-install").disabled,
      installHidden: document.querySelector("#provider-install").hidden };
  });
  console.log(JSON.stringify({ failed_assertion: error.message, diagnosis }));
  throw error;
} finally {
  await context.request.post(`${base}/api/auth/logout`);
  await context.close(); await browser.close();
}
