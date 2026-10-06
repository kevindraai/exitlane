import { readFile } from "node:fs/promises";
import path from "node:path";
import { createSyntheticFixture } from "./synthetic-fixture.mjs";

const staticRoot = path.resolve(import.meta.dirname, "../../backend/exitlane/static");
export const syntheticOrigin = "http://exitlane.test";
const contentTypes = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".png": "image/png", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json" };

async function composedIndex() {
  let html = await readFile(path.join(staticRoot, "index.html"), "utf8");
  for (const match of [...html.matchAll(/<!-- EXITLANE_PARTIAL:([a-z/-]+) -->/g)]) {
    const fragment = await readFile(path.join(staticRoot, "partials", `${match[1]}.html`), "utf8");
    html = html.replace(match[0], fragment.trimEnd());
  }
  if (html.includes("EXITLANE_PARTIAL:")) throw new Error("Unresolved frontend partial");
  return html;
}

export async function installSyntheticBrowser(context, { scenario = "authenticated" } = {}) {
  const fixture = createSyntheticFixture({ scenario });
  const html = await composedIndex();
  const failures = [];
  const requests = [];
  await context.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const key = `${request.method()} ${url.pathname}${url.search}`;
    requests.push(key);
    if (url.origin !== syntheticOrigin) {
      failures.push(`external request: ${url.origin}`);
      await route.abort();
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      if (!Object.hasOwn(fixture.data, key)) {
        failures.push(`unhandled API: ${key}`);
        await route.fulfill({ status: 501, contentType: "application/json", body: JSON.stringify({ detail: "unhandled_synthetic_route" }) });
        return;
      }
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(fixture.data[key]) });
      return;
    }
    if (request.method() !== "GET") {
      failures.push(`unexpected request: ${key}`);
      await route.abort();
      return;
    }
    if (url.pathname === "/") {
      await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: html });
      return;
    }
    if (!url.pathname.startsWith("/assets/")) {
      failures.push(`unexpected asset: ${url.pathname}`);
      await route.abort();
      return;
    }
    const asset = path.resolve(staticRoot, url.pathname.slice("/assets/".length));
    if (!asset.startsWith(`${staticRoot}${path.sep}`)) {
      failures.push(`asset escaped static root: ${url.pathname}`);
      await route.abort();
      return;
    }
    try {
      await route.fulfill({ status: 200, contentType: contentTypes[path.extname(asset)] || "application/octet-stream", body: await readFile(asset) });
    } catch {
      failures.push(`missing asset: ${url.pathname}`);
      await route.abort();
    }
  });
  return { fixture, failures, requests };
}
