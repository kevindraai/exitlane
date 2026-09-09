import assert from "node:assert/strict";
import test from "node:test";

import { createDomainPoller } from "../backend/exitlane/static/js/lifecycle.js";
import {
  providerManagementView,
  providerRequestIsCurrent,
  providerViewContext,
  vpnProviderAccess,
} from "../backend/exitlane/static/js/provider-management.js";
import {
  providerApiPathFor,
  shouldLoadAuthenticatedProviderData,
  shouldReportProviderDataError,
} from "../backend/exitlane/static/js/provider.js";
import {
  applyProviderCredentialConstraints,
  providerOverviewView,
} from "../backend/exitlane/static/js/providers.js";

const application = (providerId) => ({
  mode: "dashboard",
  activeView: "vpn-provider",
  providerId,
});
const authenticatedSession = { data: { authenticated: true } };
const providerStatus = (providerId, authenticationState, { active = false } = {}) => ({
  installed: true,
  available: true,
  authenticated: authenticationState === "signed_in",
  connected: false,
  is_active: active,
  management: {
    provider: { id: providerId, installation_state: "available" },
    authentication: { state: authenticationState },
    connection: { state: "disconnected" },
    capabilities: {
      can_connect: active && authenticationState === "signed_in",
      can_disconnect: false,
      can_select_location: active && authenticationState === "signed_in",
      can_sign_in: authenticationState === "signed_out",
      can_sign_out: authenticationState === "signed_in",
    },
  },
});
const nordStatus = providerStatus("nordvpn", "signed_in", { active: true });
const mullvadStatus = providerStatus("mullvad", "signed_out");
const providersData = {
  activeProviderId: "nordvpn",
  items: [
    { id: "nordvpn", display_name: "NordVPN", active: true },
    { id: "mullvad", display_name: "Mullvad VPN", active: false },
  ],
};

function credentialElement() {
  const attributes = new Map();
  let minimum = -1;
  let maximum = -1;
  return {
    inputMode: "",
    get minLength() { return minimum; },
    set minLength(value) {
      if (maximum >= 0 && value > maximum) throw new RangeError("minLength exceeds maxLength");
      minimum = value;
    },
    get maxLength() { return maximum; },
    set maxLength(value) {
      if (minimum >= 0 && value < minimum) throw new RangeError("maxLength below minLength");
      maximum = value;
    },
    setAttribute(name, value) { attributes.set(name, value); },
    removeAttribute(name) {
      attributes.delete(name);
      if (name === "minlength") minimum = -1;
      if (name === "maxlength") maximum = -1;
    },
    hasAttribute(name) { return attributes.has(name); },
  };
}

test("Mullvad signed-out -> NordVPN signed-in uses only NordVPN blocker, countries and constraints", () => {
  const credential = credentialElement();
  applyProviderCredentialConstraints(credential, true);
  assert.doesNotThrow(() => applyProviderCredentialConstraints(credential, false));
  assert.equal(credential.minLength, 20);
  assert.equal(credential.maxLength, 512);
  assert.equal(credential.hasAttribute("pattern"), false);

  const context = providerViewContext(application("nordvpn"), providersData, nordStatus);
  assert.equal(context.viewedProviderId, "nordvpn");
  assert.equal(context.providerSliceId, "nordvpn");
  assert.equal(vpnProviderAccess(context.status).blocked, false);
  assert.equal(shouldLoadAuthenticatedProviderData(
    application("nordvpn"), authenticatedSession, { data: nordStatus },
  ), true);
  assert.equal(providerApiPathFor(context.viewedProviderId, "/locations"), "/api/vpn/providers/nordvpn/locations");
  assert.doesNotMatch(JSON.stringify(context), /Mullvad/);
});

test("NordVPN signed-in -> Mullvad signed-out shows Mullvad blocker and makes no NordVPN country request", () => {
  const context = providerViewContext(application("mullvad"), providersData, mullvadStatus);
  const canLoad = shouldLoadAuthenticatedProviderData(
    application("mullvad"), authenticatedSession, { data: mullvadStatus },
  );
  const requests = canLoad
    ? [providerApiPathFor(context.viewedProviderId, "/locations")]
    : [];
  assert.equal(context.metadata.display_name, "Mullvad VPN");
  assert.equal(vpnProviderAccess(context.status).state, "signed_out");
  assert.deepEqual(requests, []);
});

test("rapid Mullvad -> NordVPN -> Mullvad navigation aborts and ignores stale responses", async () => {
  let providerId = "nordvpn";
  const pending = [];
  const poller = createDomainPoller({
    key: () => providerId,
    isActive: () => true,
    refresh: ({ signal, providerId: requestedProviderId }) => new Promise((resolve) => {
      pending.push({ signal, providerId: requestedProviderId, resolve });
    }),
  });
  const stale = poller.refresh();
  providerId = "mullvad";
  const current = poller.refresh();
  assert.equal(pending[0].signal.aborted, true);
  assert.deepEqual(pending.map((request) => request.providerId), ["nordvpn", "mullvad"]);
  pending[0].resolve(nordStatus);
  pending[1].resolve(mullvadStatus);
  await Promise.all([stale, current]);
  assert.equal(providerRequestIsCurrent("nordvpn", application("mullvad"), nordStatus), false);
  assert.equal(providerRequestIsCurrent("mullvad", application("mullvad"), mullvadStatus), true);
  assert.equal(
    providerViewContext(application("mullvad"), providersData, mullvadStatus).status,
    mullvadStatus,
  );
  poller.stop();
});

test("active NordVPN and viewed Mullvad retain independent active and authentication truth", () => {
  const context = providerViewContext(application("mullvad"), providersData, mullvadStatus);
  assert.equal(context.viewedProviderId, "mullvad");
  assert.equal(context.activeProviderId, "nordvpn");
  assert.equal(context.status.is_active, false);
  assert.equal(providerManagementView(context.status).authenticationState, "signed_out");
});

test("overview and detail derive the same authentication and active truth from one snapshot", () => {
  const overview = providerOverviewView({
    ...providersData.items[0],
    status: nordStatus,
  });
  const detailContext = providerViewContext(application("nordvpn"), providersData, nordStatus);
  const detail = providerManagementView(detailContext.status);
  assert.equal(overview.authenticationState, detail.authenticationState);
  assert.equal(overview.active, detailContext.status.is_active);
  assert.equal(overview.connectionState, detail.connectionState);
});

test("signed-out or stale provider data never reports a country-load toast", () => {
  assert.equal(shouldReportProviderDataError({
    error: { code: "request_failed" },
    requestedProviderId: "mullvad",
    generation: 1,
    currentGeneration: 1,
    application: application("mullvad"),
    auth: authenticatedSession,
    providerSlice: { data: mullvadStatus },
  }), false);
  assert.equal(shouldReportProviderDataError({
    error: { code: "request_failed" },
    requestedProviderId: "nordvpn",
    generation: 1,
    currentGeneration: 2,
    application: application("mullvad"),
    auth: authenticatedSession,
    providerSlice: { data: mullvadStatus },
  }), false);
});
