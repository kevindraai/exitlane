import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { chromium } from "playwright";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");
const outputRoot = path.resolve(
  process.env.EXITLANE_SCREENSHOT_OUTPUT || path.join(repositoryRoot, "docs/images"),
);
const baseUrl = process.env.EXITLANE_SCREENSHOT_BASE_URL || "http://172.16.130.81:8787";
const username = process.env.EXITLANE_SCREENSHOT_USERNAME || "admin";
const password = process.env.EXITLANE_SCREENSHOT_PASSWORD;

if (!password) {
  throw new Error("EXITLANE_SCREENSHOT_PASSWORD is required");
}

const profiles = Object.freeze({
  readme: { width: 1440, height: 1200, directory: outputRoot },
  promo: { width: 1600, height: 1000, directory: path.join(outputRoot, "promo") },
});

const captures = Object.freeze([
  {
    id: "dashboard",
    route: "#dashboard",
    wait: async (page) => {
      await expectText(page, "#dashboard-health-state", /Healthy/);
      await expectText(page, "#dashboard-vpn-pill", /Connected/);
      await expectText(page, "#dashboard-wg-pill", /Connected/);
      await expectText(page, "#dashboard-vpn-server", /\S/);
      await expectText(page, "#dashboard-wg-endpoint", /\S/);
    },
    files: {
      readme: "exitlane-dashboard.png",
      promo: "exitlane-dashboard-hero.png",
    },
    state: "live-runtime",
  },
  {
    id: "vpn",
    route: "#vpn/provider/nordvpn",
    wait: async (page) => {
      await expectText(page, "#connection-state", /Connected/);
      await expectText(page, "#metric-server", /\S/);
      await page.waitForFunction(() => {
        const cards = [...document.querySelectorAll("#quick-countries .country-card")];
        return cards.length > 0 && cards.every((card) => !/Measuring|Meten/i.test(card.innerText));
      });
    },
    files: {
      readme: "exitlane-vpn-selection.png",
      promo: "exitlane-vpn-selection.png",
    },
    state: "live-runtime",
  },
  {
    id: "diagnostics",
    route: "#diagnostics",
    wait: async (page) => {
      await page.locator("#diagnostics-run").click();
      await page.waitForFunction(() => {
        const summary = document.querySelector("#connection-diagnostics-summary");
        const nodes = [...document.querySelectorAll("[data-diagnostic-node]")];
        return summary?.textContent.trim()
          && nodes.length === 4
          && nodes.every((node) => !/Pending|Running|Wachten|Bezig/i.test(node.innerText));
      });
      const summary = await page.locator("#connection-diagnostics-summary").innerText();
      if (/failed|mislukt/i.test(summary)) {
        throw new Error(`Connection diagnostics did not pass: ${summary}`);
      }
    },
    files: {
      readme: "exitlane-diagnostics.png",
      promo: "exitlane-diagnostics.png",
    },
    state: "live-runtime",
  },
  {
    id: "wireguard",
    route: "#wireguard",
    wait: async (page) => {
      await expectText(page, "#management-wireguard-state", /Connected/);
      await expectText(page, "#management-wireguard-endpoint", /\S/);
      await page.waitForFunction(() => {
        const loading = document.querySelector("#wireguard-config-loading");
        return loading?.hidden === true;
      });
    },
    files: { readme: "exitlane-wireguard.png" },
    state: "live-runtime-sensitive-ui-hidden",
  },
  {
    id: "documentation",
    route: "#help",
    wait: async (page) => {
      await page.waitForFunction(() => {
        const loading = document.querySelector("#help-loading");
        return loading?.hidden === true && document.querySelectorAll(".help-category-card").length >= 4;
      });
    },
    files: {
      readme: "exitlane-documentation.png",
      promo: "exitlane-documentation.png",
    },
    state: "live-application-content",
  },
]);

async function expectText(page, selector, pattern) {
  await page.waitForFunction(
    ({ selector, source, flags }) => {
      const value = document.querySelector(selector)?.textContent.trim() || "";
      return new RegExp(source, flags).test(value) && value !== "—";
    },
    { selector, source: pattern.source, flags: pattern.flags },
  );
}

async function assertSafeVisibleState(page, captureId) {
  const state = await page.evaluate(() => {
    const config = document.querySelector("#management-wireguard-config");
    const qrDialog = document.querySelector("#wireguard-qr-dialog");
    return {
      visibleText: document.body.innerText,
      configHidden: !config || config.hidden,
      configTextEmpty: !config || config.textContent === "",
      qrClosed: !qrDialog || !qrDialog.open,
      openDialogs: [...document.querySelectorAll("dialog[open]")].map((dialog) => dialog.id),
    };
  });
  const sensitivePatterns = [
    /\bPrivateKey\s*=/i,
    /\bPresharedKey\s*=/i,
    /\brecovery code\s*:/i,
    /\bbearer\s+[A-Za-z0-9._~-]{12,}/i,
  ];
  if (!state.configHidden || !state.configTextEmpty || !state.qrClosed || state.openDialogs.length) {
    throw new Error(`${captureId}: secret-bearing UI or a dialog is open`);
  }
  if (sensitivePatterns.some((pattern) => pattern.test(state.visibleText))) {
    throw new Error(`${captureId}: visible content matched a sensitive-data marker`);
  }
}

async function assertTechnicalValueLayout(page) {
  return page.evaluate(() => {
    const selectors = ["#dashboard-vpn-server", "#dashboard-wg-endpoint"];
    return Object.fromEntries(selectors.map((selector) => {
      const element = document.querySelector(selector);
      const bounds = element.getBoundingClientRect();
      const parent = element.closest(".metric").getBoundingClientRect();
      const range = document.createRange();
      range.selectNodeContents(element);
      const lineTops = new Set([...range.getClientRects()]
        .filter((rectangle) => rectangle.width > 0)
        .map((rectangle) => Math.round(rectangle.top)));
      const lineText = new Map();
      const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (!node.nodeValue) continue;
        const nodeRange = document.createRange();
        nodeRange.selectNodeContents(node);
        const rectangle = [...nodeRange.getClientRects()].find((item) => item.width > 0);
        if (!rectangle) continue;
        const top = Math.round(rectangle.top);
        lineText.set(top, `${lineText.get(top) || ""}${node.nodeValue}`);
      }
      return [selector, {
        text: element.getAttribute("aria-label") || element.textContent,
        lines: lineTops.size,
        lineLengths: [...lineText.entries()].sort(([left], [right]) => left - right)
          .map(([, text]) => text.length),
        withinCard: bounds.right <= parent.right + 1 && bounds.left >= parent.left - 1,
        titleMatches: element.title === (element.getAttribute("aria-label") || element.textContent),
      }];
    }));
  });
}

async function login(page) {
  await page.goto(`${baseUrl}/#dashboard`, { waitUntil: "domcontentloaded" });
  await page.locator("#login-panel").waitFor({ state: "visible" });
  await page.locator("#login-username").fill(username);
  await page.locator("#login-password").fill(password);
  await page.locator('#login-form button[type="submit"]').click();
  await page.locator("#dashboard-panel").waitFor({ state: "visible" });
  await expectText(page, "#dashboard-version", /0\.2\.0-rc\.1/);
}

async function navigate(page, route) {
  await page.evaluate((nextRoute) => {
    window.location.hash = nextRoute;
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, route);
  const view = route.startsWith("#vpn/provider/")
    ? "vpn-provider"
    : route.slice(1).split("/", 1)[0];
  await page.locator(`[data-view-panel="${view}"]`).waitFor({ state: "visible" });
}

await Promise.all(Object.values(profiles).map((profile) => mkdir(profile.directory, { recursive: true })));

const browser = await chromium.launch({ headless: true });
const manifest = {
  generated_at: new Date().toISOString(),
  source_appliance: "172.16.130.81",
  source_version: null,
  language: "en",
  appearance: "dark",
  network_mocking: false,
  speedtest_started: false,
  screenshots: [],
  responsive_qa: [],
};

try {
  for (const [profileName, profile] of Object.entries(profiles)) {
    const context = await browser.newContext({
      viewport: { width: profile.width, height: profile.height },
      colorScheme: "dark",
      locale: "en-GB",
      reducedMotion: "reduce",
      deviceScaleFactor: 1,
    });
    await context.addInitScript(() => {
      localStorage.setItem("exitlane-language", "en");
      localStorage.setItem("exitlane-color-scheme", "dark");
      localStorage.setItem("exitlane-active-view", "dashboard");
    });
    const page = await context.newPage();
    page.setDefaultTimeout(30_000);
    const failedResponses = [];
    let authenticated = false;
    page.on("response", (response) => {
      if (authenticated && response.status() >= 400) {
        failedResponses.push({ status: response.status(), url: response.url() });
      }
    });
    await login(page);
    authenticated = true;
    manifest.source_version ||= (await page.locator("#dashboard-version").getAttribute("aria-label"))
      ?.replace(/^v/, "");
    for (const capture of captures.filter((item) => item.files[profileName])) {
      await navigate(page, capture.route);
      await capture.wait(page);
      await page.waitForTimeout(1_000);
      await page.evaluate(() => document.activeElement?.blur());
      await assertSafeVisibleState(page, capture.id);
      const filename = capture.files[profileName];
      const output = path.join(profile.directory, filename);
      await page.screenshot({ path: output, fullPage: false, animations: "disabled" });
      manifest.screenshots.push({
        id: capture.id,
        profile: profileName,
        file: path.relative(repositoryRoot, output),
        dimensions: `${profile.width}x${profile.height}`,
        state: capture.state,
        sensitive_ui: capture.id === "wireguard" ? "configuration and QR kept closed" : "not present",
      });
    }

    if (profileName === "readme") {
      for (const viewport of [
        { name: "desktop", width: 1440, height: 1000 },
        { name: "small-desktop", width: 900, height: 1000 },
        { name: "mobile", width: 390, height: 844 },
      ]) {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await navigate(page, "#dashboard");
        await captures[0].wait(page);
        const values = await assertTechnicalValueLayout(page);
        if (Object.values(values).some((value) => (
          value.lines < 1
          || value.lines > 2
          || (viewport.name === "desktop" && value.lines !== 1)
          || value.lineLengths.at(-1) < 4
          || !value.withinCard
          || !value.titleMatches
        ))) {
          throw new Error(`${viewport.name}: technical-value layout contract failed: ${JSON.stringify(values)}`);
        }
        manifest.responsive_qa.push({ viewport, values, card_overlap: false });
      }
    }

    const relevantFailures = failedResponses.filter(({ url }) => url.startsWith(baseUrl));
    if (relevantFailures.length) {
      throw new Error(`${profileName}: application responses failed: ${JSON.stringify(relevantFailures)}`);
    }
    await context.close();
  }
} finally {
  await browser.close();
}

await writeFile(
  path.join(outputRoot, "screenshot-manifest.json"),
  `${JSON.stringify(manifest, null, 2)}\n`,
  "utf8",
);

console.log(`Captured ${manifest.screenshots.length} screenshots from ${baseUrl}.`);
