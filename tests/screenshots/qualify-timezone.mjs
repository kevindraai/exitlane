import { chromium } from "playwright";

const baseUrl = process.env.EXITLANE_SCREENSHOT_BASE_URL || "http://172.16.130.81:8787";
const username = process.env.EXITLANE_SCREENSHOT_USERNAME || "admin";
const password = process.env.EXITLANE_SCREENSHOT_PASSWORD;
const targetTimezone = process.env.EXITLANE_QA_TIMEZONE;
const expectFailure = process.env.EXITLANE_EXPECT_TIMEZONE_FAILURE === "1";

if (!password || !targetTimezone) {
  throw new Error("EXITLANE_SCREENSHOT_PASSWORD and EXITLANE_QA_TIMEZONE are required");
}

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ locale: "en-GB" });
  await context.addInitScript(() => {
    localStorage.setItem("exitlane-language", "en");
    localStorage.setItem("exitlane-color-scheme", "dark");
  });
  const page = await context.newPage();
  page.setDefaultTimeout(30_000);
  await page.goto(`${baseUrl}/#settings/general`, { waitUntil: "domcontentloaded" });
  await page.locator("#login-username").fill(username);
  await page.locator("#login-password").fill(password);
  await page.locator('#login-form button[type="submit"]').click();
  await page.locator("#dashboard-panel").waitFor({ state: "visible" });
  await page.evaluate(() => {
    window.location.hash = "#settings/general";
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
  await page.locator('#view-settings[data-view-panel="settings"]').waitFor({ state: "visible" });
  await page.waitForFunction(() => document.querySelector("#settings-timezone")?.options.length > 10);

  const originalTimezone = await page.locator("#settings-timezone").inputValue();
  if (originalTimezone === targetTimezone) {
    throw new Error(`Target timezone already active: ${targetTimezone}`);
  }
  await page.locator("#settings-timezone").selectOption(targetTimezone);
  await page.locator("#settings-general-save").click();

  if (expectFailure) {
    await page.locator("#settings-general-error").waitFor({ state: "visible" });
    const message = (await page.locator("#settings-general-error").innerText()).trim();
    if (!message || await page.locator("#settings-timezone").inputValue() !== originalTimezone) {
      throw new Error("Timezone failure did not preserve the original Settings value");
    }
    console.log(`Settings rejected ${targetTimezone} and preserved ${originalTimezone}: ${message}`);
  } else {
    await page.waitForFunction(
      (timezone) => document.querySelector("#settings-system-timezone")?.getAttribute("aria-label") === timezone,
      targetTimezone,
    );
    await page.waitForFunction(
      (timezone) => document.querySelector("#settings-timezone")?.value === timezone
        && document.querySelector("#settings-general-save")?.disabled,
      targetTimezone,
    );
    if (!await page.locator("#settings-general-error").isHidden()) {
      throw new Error(await page.locator("#settings-general-error").innerText());
    }
    console.log(`Settings and system status show ${targetTimezone}.`);
  }
} finally {
  await browser.close();
}
