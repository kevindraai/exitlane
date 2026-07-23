import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  providerOverviewRoute,
  providerOverviewView,
} from "../backend/exitlane/static/js/providers.js";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("VPN navigation is metadata-driven and contains no hardcoded provider item", async () => {
  const [sidebar, providers, lifecycle] = await Promise.all([
    read("../backend/exitlane/static/partials/sidebar.html"),
    read("../backend/exitlane/static/js/providers.js"),
    read("../backend/exitlane/static/js/lifecycle.js"),
  ]);
  assert.match(sidebar, /<button[^>]+aria-expanded="false"[^>]+id="vpn-navigation-toggle"/);
  assert.match(sidebar, /id="vpn-provider-navigation"/);
  assert.doesNotMatch(sidebar, /NordVPN/);
  assert.match(lifecycle, /items: response\.providers \|\| \[\]/);
  assert.match(providers, /provider\.display_name/);
});

test("provider overview, provider route, and generic API paths are distinct", async () => {
  const [navigation, provider, overview, providers] = await Promise.all([
    read("../backend/exitlane/static/js/navigation.js"),
    read("../backend/exitlane/static/js/provider.js"),
    read("../backend/exitlane/static/partials/views/vpn-overview.html"),
    read("../backend/exitlane/static/js/providers.js"),
  ]);
  assert.match(navigation, /#vpn\/provider\/\$\{encodeURIComponent\(providerId\)\}/);
  assert.match(overview, /data-view-panel="vpn"/);
  assert.match(provider, /providerApiPath\("\/locations"\)/);
  assert.match(provider, /providerApiPath\("\/disconnect"\)/);
  assert.doesNotMatch(provider, /postJson\("\/api\/vpn\/connect"/);
  assert.match(providers, /action\.addEventListener\("click", \(\) => showProviderView\(view\.id\)\)/);
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

const provider = ({
  authentication = "signed_in",
  connection = "disconnected",
  status = {},
} = {}) => ({
  id: "example-vpn",
  display_name: "Example VPN",
  description: "Provider supplied description",
  icon: "provider-example",
  active: true,
  status: {
    installed: true,
    available: true,
    authenticated: authentication === "signed_in",
    connected: connection === "connected",
    management: {
      provider: { id: "example-vpn", installation_state: "installed" },
      authentication: { state: authentication },
      connection: { state: connection },
      capabilities: {
        can_connect: authentication === "signed_in",
        can_disconnect: connection === "connected",
      },
    },
    ...status,
  },
});

test("connected overview exposes provider metadata, status and reliable optional fields", () => {
  const view = providerOverviewView(provider({
    connection: "connected",
    status: {
      country: "Netherlands",
      server: "server.example",
      external_ip: "192.0.2.10",
      latency_ms: 18,
    },
  }));
  assert.equal(view.displayName, "Example VPN");
  assert.equal(view.description, "Provider supplied description");
  assert.equal(view.icon, "provider-example");
  assert.equal(view.state, "connected");
  assert.equal(view.statusTone, "success");
  assert.deepEqual(view.fields.map(({ key }) => key), [
    "location", "server", "external_ip", "latency",
  ]);
  assert.equal(view.canOpen, true);
  assert.equal(providerOverviewRoute(view.id), "#vpn/provider/example-vpn");
});

test("disconnected, signed-out, unavailable and unknown states have honest semantics", () => {
  const disconnected = providerOverviewView(provider());
  assert.equal(disconnected.state, "disconnected");
  assert.equal(disconnected.statusTone, "neutral");

  const signedOut = providerOverviewView(provider({ authentication: "signed_out" }));
  assert.equal(signedOut.state, "signed_out");
  assert.equal(signedOut.authenticationState, "signed_out");
  assert.equal(signedOut.fields.length, 0);

  const unavailable = providerOverviewView(provider({
    authentication: "unavailable",
    connection: "error",
    status: { available: false },
  }));
  assert.equal(unavailable.state, "unavailable");
  assert.equal(unavailable.statusTone, "warning");

  const unknown = providerOverviewView(provider({
    authentication: "unknown",
    connection: "unknown",
  }));
  assert.equal(unknown.state, "unknown");
  assert.equal(unknown.statusTone, "neutral");
});

test("overview omits missing optional values and contains no provider-specific logic", async () => {
  const view = providerOverviewView({
    id: "minimal",
    display_name: "Minimal",
    status: {},
  });
  assert.equal(view.fields.length, 0);
  assert.equal(view.state, "unknown");

  const source = await read("../backend/exitlane/static/js/providers.js");
  const overviewStart = source.indexOf("export function providerOverviewView");
  const overviewEnd = source.indexOf("async function authenticateProvider");
  assert.doesNotMatch(source.slice(overviewStart, overviewEnd), /NordVPN|nordvpn/);
});

test("overview translations and responsive status styling exist", async () => {
  const [english, dutch, styles] = await Promise.all([
    read("../backend/exitlane/static/locales/en.json").then(JSON.parse),
    read("../backend/exitlane/static/locales/nl.json").then(JSON.parse),
    read("../backend/exitlane/static/style.css"),
  ]);
  for (const locale of [english, dutch]) {
    assert.ok(locale.vpn.overview.open_provider);
    assert.ok(locale.vpn.overview.not_available);
    for (const state of [
      "connected", "disconnected", "connecting", "disconnecting",
      "signed_out", "unavailable", "error", "unknown",
    ]) {
      assert.ok(locale.vpn.overview.states[state]);
    }
  }
  assert.match(styles, /provider-overview-status--success/);
  assert.match(styles, /provider-overview-status--busy/);
  assert.match(styles, /@media \(max-width: 650px\)[\s\S]+provider-overview-list[\s\S]+grid-template-columns: 1fr/);
});

test("VPN overview has its own authenticated catalog poller", async () => {
  const lifecycle = await read("../backend/exitlane/static/js/lifecycle.js");
  assert.match(lifecycle, /refreshProvidersState[\s\S]+\/api\/vpn\/providers/);
  assert.match(lifecycle, /const providers = createDomainPoller\([\s\S]+active\("vpn"\)/);
  assert.match(lifecycle, /if \(!active\("vpn"\)\) providers\.stop\(\)/);
});
