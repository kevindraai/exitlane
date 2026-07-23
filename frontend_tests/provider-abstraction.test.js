import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("VPN navigation is metadata-driven and contains no hardcoded provider item", async () => {
  const [sidebar, providers] = await Promise.all([
    read("../backend/exitlane/static/partials/sidebar.html"),
    read("../backend/exitlane/static/js/providers.js"),
  ]);
  assert.match(sidebar, /<button[^>]+aria-expanded="false"[^>]+id="vpn-navigation-toggle"/);
  assert.match(sidebar, /id="vpn-provider-navigation"/);
  assert.doesNotMatch(sidebar, /NordVPN/);
  assert.match(providers, /response\.providers \|\| \[\]/);
  assert.match(providers, /provider\.display_name/);
});

test("provider overview, provider route, and generic API paths are distinct", async () => {
  const [navigation, provider, overview] = await Promise.all([
    read("../backend/exitlane/static/js/navigation.js"),
    read("../backend/exitlane/static/js/provider.js"),
    read("../backend/exitlane/static/partials/views/vpn-overview.html"),
  ]);
  assert.match(navigation, /#vpn\/provider\/\$\{encodeURIComponent\(providerId\)\}/);
  assert.match(overview, /data-view-panel="vpn"/);
  assert.match(provider, /providerApiPath\("\/locations"\)/);
  assert.match(provider, /providerApiPath\("\/disconnect"\)/);
  assert.doesNotMatch(provider, /postJson\("\/api\/vpn\/connect"/);
});

test("authenticated provider state is isolated and wizard consumes provider metadata", async () => {
  const [state, app, wizard, settings] = await Promise.all([
    read("../backend/exitlane/static/js/state.js"),
    read("../backend/exitlane/static/js/app.js"),
    read("../backend/exitlane/static/js/wizard.js"),
    read("../backend/exitlane/static/partials/views/settings.html"),
  ]);
  assert.match(state, /providers: statusSlice\(\)/);
  assert.match(state, /"providers", "provider", "wireguard"/);
  assert.match(app, /startDashboard:[\s\S]+await loadProviders\(\)/);
  assert.match(wizard, /setup\.providers \|\| \[\]/);
  assert.doesNotMatch(settings, /NordVPN|settings-provider|settings-token/);
});
