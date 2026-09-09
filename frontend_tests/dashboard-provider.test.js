import assert from "node:assert/strict";
import test from "node:test";

import {
  dashboardProviderName,
  renderDashboardProvider,
} from "../backend/exitlane/static/js/dashboard.js";

test("dashboard renders the active provider metadata for NordVPN and Mullvad", () => {
  assert.equal(dashboardProviderName({
    active_provider: { id: "nordvpn", display_name: "NordVPN" },
  }), "NordVPN");
  assert.equal(dashboardProviderName({
    active_provider: { id: "mullvad", display_name: "Mullvad VPN" },
  }), "Mullvad VPN");
});

test("dashboard runtime provider switch does not retain the previous provider", () => {
  const snapshots = [
    { active_provider: { id: "nordvpn", display_name: "NordVPN" } },
    { active_provider: { id: "mullvad", display_name: "Mullvad VPN" } },
  ];

  let renderedProvider = null;
  const renderText = (selector, value) => {
    assert.equal(selector, "#dashboard-vpn-provider");
    renderedProvider = value ?? "—";
  };
  renderDashboardProvider(snapshots[0], renderText);
  assert.equal(renderedProvider, "NordVPN");
  renderDashboardProvider(snapshots[1], renderText);

  assert.equal(renderedProvider, "Mullvad VPN");
  assert.notEqual(renderedProvider, "NordVPN");
});

test("dashboard uses the neutral placeholder path when provider metadata is unavailable", () => {
  assert.equal(dashboardProviderName({}), null);
  assert.equal(dashboardProviderName({ active_provider: {} }), null);
});
