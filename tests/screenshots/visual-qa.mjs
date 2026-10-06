import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { chromium } from "playwright";
import { installSyntheticBrowser, syntheticOrigin } from "./synthetic-browser.mjs";
import { assertSafeVisibleState } from "./privacy.mjs";
import { fixtureTime, sourceVersion } from "./synthetic-fixture.mjs";

const root = path.resolve(import.meta.dirname, "../..");
const requestedOutput = process.env.EXITLANE_SCREENSHOT_QA_OUTPUT;
const qaPrefix = requestedOutput
  ? path.resolve(requestedOutput === "1" ? "/tmp/exitlane-visual-qa" : requestedOutput)
  : null;
if (qaPrefix && (path.dirname(qaPrefix) !== "/tmp" || !/^[a-zA-Z0-9._-]+$/.test(path.basename(qaPrefix)))) {
  throw new Error("EXITLANE_SCREENSHOT_QA_OUTPUT must be a simple prefix directly under /tmp");
}
const qaOutput = qaPrefix ? await mkdtemp(`${qaPrefix}-`) : null;
if (qaOutput) await chmod(qaOutput, 0o700);
const writeQaFile = (name, contents) => writeFile(path.join(qaOutput, name), contents, { flag: "wx", mode: 0o600 });
const git = (args) => {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr || result.error?.message}`);
  return result.stdout.trim();
};
const source = qaOutput ? {
  commit: git(["rev-parse", "HEAD"]),
  tree: git(["rev-parse", "HEAD^{tree}"]),
  worktree_dirty_at_start: Boolean(git(["status", "--porcelain", "--untracked-files=normal"])),
} : null;

const viewports = [
  { name: "desktop", width: 1440, height: 1000 },
  { name: "tablet", width: 900, height: 1000 },
  { name: "mobile", width: 390, height: 844 },
  { name: "narrow", width: 320, height: 700 },
];
const routes = [
  ["Dashboard", "#dashboard", "dashboard"],
  ["VPN", "#vpn/provider/nordvpn", "vpn-provider"],
  ["Diagnostics", "#diagnostics", "diagnostics"],
  ["WireGuard", "#wireguard", "wireguard"],
  ["Settings", "#settings/general", "settings"],
  ["Activity", "#activity", "activity"],
  ["Help", "#help", "help"],
];
const browser = await chromium.launch({ headless: true });
const findings = [];
const screenshots = [];
const coverage = { authenticated_views: 0, initial_states: 0, overflows: 0, console_errors: 0 };
const selected = new Set([
  "desktop/dark/en", "tablet/light/nl",
  "mobile/dark/en", "mobile/light/nl", "narrow/dark/en", "narrow/light/nl",
]);
let fatalError = null;
try {
  for (const viewport of viewports) for (const color of ["light", "dark"]) for (const language of ["en", "nl"]) {
    const context = await browser.newContext({ viewport, colorScheme: color, locale: language === "nl" ? "nl-NL" : "en-GB", reducedMotion: "reduce" });
    await context.addInitScript(({ language, color }) => {
      localStorage.setItem("exitlane-language", language);
      localStorage.setItem("exitlane-color-scheme", color);
    }, { language, color });
    const intercepted = await installSyntheticBrowser(context);
    const page = await context.newPage();
    await page.clock.setFixedTime(new Date(fixtureTime));
    page.setDefaultTimeout(15_000);
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    await page.goto(`${syntheticOrigin}/#dashboard`);
    await page.locator("#dashboard-panel").waitFor({ state: "visible" });
    for (const [name, route, panel] of routes) {
      await page.evaluate((hash) => { location.hash = hash; dispatchEvent(new PopStateEvent("popstate")); }, route);
      await page.locator(`[data-view-panel="${panel}"]`).waitFor({ state: "visible" });
      if (panel === "dashboard") {
        await page.locator("#dashboard-health-state").getByText(/Healthy|Gezond/i).waitFor();
        await page.locator("#dashboard-wg-peer-list tr").first().waitFor();
      }
      if (panel === "vpn-provider") {
        await page.locator("#connection-state").getByText(/Connected|Verbonden/i).waitFor();
        await page.locator("#quick-countries .country-card").first().waitFor();
      }
      if (panel === "diagnostics") await page.waitForFunction(() => /passed|geslaagd/i.test(document.querySelector("#connection-diagnostics-summary")?.textContent || ""));
      if (panel === "wireguard") await page.locator("#wireguard-peer-list tr").first().waitFor();
      if (panel === "help") await page.locator(".help-category-card").first().waitFor();
      if (panel === "settings") await page.locator("#settings-hostname").getByText(/exitlane\.example/).waitFor();
      const overflow = await page.evaluate(() => Math.max(document.body.scrollWidth, document.documentElement.scrollWidth) - innerWidth);
      coverage.authenticated_views += 1;
      if (overflow > 1) {
        coverage.overflows += 1;
        findings.push(`${viewport.name}/${color}/${language}/${name}: page overflow ${overflow}px`);
      }
      try { await assertSafeVisibleState(page, name); } catch (error) { findings.push(`${viewport.name}/${color}/${language}/${name}: ${error.message}`); }
      if (qaOutput && selected.has(`${viewport.name}/${color}/${language}`) && ["Dashboard", "VPN", "WireGuard"].includes(name)) {
        const file = `${viewport.name}-${color}-${language}-${name.toLowerCase()}.png`;
        await page.evaluate(() => scrollTo(0, 0));
        await writeQaFile(file, await page.screenshot({ fullPage: true, animations: "disabled" }));
        screenshots.push(file);
      }
      if (panel === "wireguard") {
        if (viewport.width <= 480) {
          const cardFindings = await page.evaluate(() => {
            const issues = [];
            const within = (inner, outer) => inner.left >= outer.left - 1 && inner.right <= outer.right + 1
              && inner.top >= outer.top - 1 && inner.bottom <= outer.bottom + 1;
            const rows = [...document.querySelectorAll("#wireguard-peer-list tr")];
            if (rows.length !== 3) issues.push(`expected three device cards, found ${rows.length}`);
            for (const [rowIndex, row] of rows.entries()) {
              const cells = [...row.querySelectorAll(":scope > td")];
              if (cells.length !== 7) issues.push(`card ${rowIndex + 1}: expected seven fields, found ${cells.length}`);
              for (const [cellIndex, cell] of cells.entries()) {
                const field = cell.dataset.label || `field ${cellIndex + 1}`;
                const style = getComputedStyle(cell);
                const labelStyle = getComputedStyle(cell, "::before");
                const value = cell.firstElementChild;
                const cellRect = cell.getBoundingClientRect();
                const valueRect = value?.getBoundingClientRect();
                if (!cell.dataset.label || labelStyle.content === "none" || labelStyle.content === "normal") {
                  issues.push(`card ${rowIndex + 1} ${field}: missing visible label`);
                }
                if (style.whiteSpace !== "normal" || labelStyle.whiteSpace !== "normal") {
                  issues.push(`card ${rowIndex + 1} ${field}: label or field cannot wrap`);
                }
                if (!valueRect || !within(valueRect, cellRect)) {
                  issues.push(`card ${rowIndex + 1} ${field}: value escapes its field`);
                  continue;
                }
                const contentTop = cellRect.top + parseFloat(style.borderTopWidth) + parseFloat(style.paddingTop);
                let labelBottom;
                if (style.display === "grid") {
                  const columns = style.gridTemplateColumns.trim().split(/\s+/);
                  const labelRowHeight = parseFloat(style.gridTemplateRows);
                  if (columns.length !== 1 || !Number.isFinite(labelRowHeight) || labelRowHeight <= 0) {
                    issues.push(`card ${rowIndex + 1} ${field}: label and value are not in separate grid rows`);
                    continue;
                  }
                  labelBottom = contentTop + labelRowHeight;
                } else if (cellIndex === cells.length - 1 && style.display === "block" && labelStyle.display === "block") {
                  const lineHeight = parseFloat(labelStyle.lineHeight) || parseFloat(labelStyle.fontSize) * 1.2;
                  labelBottom = contentTop + lineHeight;
                } else {
                  issues.push(`card ${rowIndex + 1} ${field}: unexpected field layout ${style.display}`);
                  continue;
                }
                if (valueRect.top < labelBottom - 1) issues.push(`card ${rowIndex + 1} ${field}: value overlaps label`);
                for (const child of value.querySelectorAll("*")) {
                  if (child.matches("svg, path, use, wbr")) continue;
                  if (!within(child.getBoundingClientRect(), cellRect)) {
                    issues.push(`card ${rowIndex + 1} ${field}: nested value escapes its field`);
                  }
                }
                if (value.matches(".technical-value") && value.scrollWidth > value.clientWidth + 1) {
                  const valueStyle = getComputedStyle(value);
                  if (valueStyle.overflow !== "hidden" || valueStyle.textOverflow !== "ellipsis" || value.title !== value.textContent) {
                    issues.push(`card ${rowIndex + 1} ${field}: truncated technical value lacks a readable title`);
                  }
                }
              }
            }
            return issues;
          });
          findings.push(...cardFindings.map((finding) => `${viewport.name}/${color}/${language}: WireGuard ${finding}`));
        }
        if (viewport.width >= 900) {
          const actionsVisible = await page.evaluate(() => {
            const wrapper = document.querySelector("#wireguard-peers-content").getBoundingClientRect();
            return [...document.querySelectorAll(".wireguard-peer-menu-trigger")].every((button) => {
              const bounds = button.getBoundingClientRect();
              return bounds.left >= wrapper.left - 1 && bounds.right <= wrapper.right + 1 && bounds.right <= innerWidth + 1;
            });
          });
          if (!actionsVisible) findings.push(`${viewport.name}/${color}/${language}: WireGuard row actions clipped in the initial table view`);
        }
        const trigger = page.locator(".wireguard-peer-menu-trigger").first();
        await trigger.click();
        const menu = page.locator("#wireguard-peer-actions-popover");
        await menu.waitFor({ state: "visible" });
        const inside = await menu.evaluate((node) => { const r = node.getBoundingClientRect(); return r.left >= 0 && r.top >= 0 && r.right <= innerWidth + 1 && r.bottom <= innerHeight + 1; });
        if (!inside) findings.push(`${viewport.name}/${color}/${language}: peer menu clipped`);
        await page.keyboard.press("Escape");
        if (await menu.isVisible()) findings.push(`${viewport.name}/${color}/${language}: peer menu Escape failed`);
        await trigger.click();
        await page.locator("#management-wireguard-state").click();
        if (await menu.isVisible()) findings.push(`${viewport.name}/${color}/${language}: peer menu outside click failed`);
      }
      if (panel === "dashboard") {
        const before = await page.locator("#dashboard-killswitch-state").innerText();
        await page.locator("#dashboard-killswitch-info").focus();
        await page.locator("#dashboard-killswitch-description").waitFor({ state: "visible" });
        await page.keyboard.press("Escape");
        await page.locator("#dashboard-killswitch-info").click();
        await page.locator("#dashboard-killswitch-description").waitFor({ state: "visible" });
        await page.keyboard.press("Escape");
        if (await page.locator("#dashboard-killswitch-state").innerText() !== before) findings.push(`${viewport.name}/${color}/${language}: killswitch changed while opening info`);
      }
    }
    findings.push(...intercepted.failures.map((value) => `${viewport.name}/${color}/${language}: ${value}`));
    findings.push(...errors.map((value) => `${viewport.name}/${color}/${language}: console ${value}`));
    coverage.console_errors += errors.length;
    await context.close();
  }
  for (const viewport of viewports) for (const color of ["light", "dark"]) for (const language of ["en", "nl"]) for (const scenario of ["login", "wizard"]) {
    const context = await browser.newContext({ viewport, colorScheme: color, locale: language === "nl" ? "nl-NL" : "en-GB", reducedMotion: "reduce" });
    await context.addInitScript(({ language, color }) => {
      localStorage.setItem("exitlane-language", language);
      localStorage.setItem("exitlane-color-scheme", color);
    }, { language, color });
    const intercepted = await installSyntheticBrowser(context, { scenario });
    const page = await context.newPage();
    await page.clock.setFixedTime(new Date(fixtureTime));
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
    await page.goto(`${syntheticOrigin}/`);
    await page.locator(scenario === "login" ? "#login-panel" : "#wizard-panel").waitFor({ state: "visible" });
    await page.locator("#app-version").getByText(`v${sourceVersion}`).waitFor();
    const overflow = await page.evaluate(() => Math.max(document.body.scrollWidth, document.documentElement.scrollWidth) - innerWidth);
    const label = `${viewport.name}/${color}/${language}/${scenario}`;
    coverage.initial_states += 1;
    if (overflow > 1) {
      coverage.overflows += 1;
      findings.push(`${label}: page overflow ${overflow}px`);
    }
    if (qaOutput && viewport.name === "desktop" && color === "dark" && language === "en") {
      const file = `desktop-dark-en-${scenario}.png`;
      await writeQaFile(file, await page.screenshot({ fullPage: true, animations: "disabled" }));
      screenshots.push(file);
    }
    findings.push(...intercepted.failures.map((value) => `${label}: ${value}`), ...errors.map((value) => `${label}: console ${value}`));
    coverage.console_errors += errors.length;
    await context.close();
  }
} catch (error) {
  fatalError = error;
  findings.push(`browser run: ${error.message}`);
} finally {
  await browser.close();
  if (qaOutput) await writeQaFile("run-result.json", `${JSON.stringify({
    generated_at: new Date().toISOString(), mode: "synthetic-visual-qa", source,
    fixture_time: fixtureTime, matrix: {
      viewports, appearances: ["light", "dark"], languages: ["en", "nl"],
      authenticated_views: routes.map(([name]) => name), initial_states: ["login", "wizard"],
    }, coverage, screenshots, findings,
  }, null, 2)}\n`);
}
if (qaOutput) console.log(`Private QA output: ${qaOutput}`);
if (fatalError) throw fatalError;
if (findings.length) throw new Error(findings.join("\n"));
console.log("Visual QA passed: desktop/tablet/mobile/narrow, light/dark, EN/NL, seven views and safe initial states.");
