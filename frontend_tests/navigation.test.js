import assert from "node:assert/strict";
import test from "node:test";
import { renderApplicationState } from "../backend/exitlane/static/js/navigation.js";

class Element {
  constructor(dataset = {}) {
    this.dataset = dataset;
    this.hidden = true;
    this.attributes = new Map();
    const classes = new Set();
    this.classList = {
      toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name),
      contains: (name) => classes.has(name),
    };
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  removeAttribute(name) { this.attributes.delete(name); }
  getAttribute(name) { return this.attributes.get(name); }
}

function fixture() {
  const elements = {
    shell: new Element(), wizard: new Element(), login: new Element(), dashboard: new Element(),
    sidebar: new Element(), logout: new Element(), dashboardView: new Element({ viewPanel: "dashboard" }),
    vpnView: new Element({ viewPanel: "vpn" }), dashboardButton: new Element({ view: "dashboard" }),
    vpnButton: new Element({ view: "vpn" }),
  };
  const fixed = {
    ".app-shell": elements.shell, "#wizard-panel": elements.wizard, "#login-panel": elements.login,
    "#dashboard-panel": elements.dashboard, "#sidebar": elements.sidebar, "#logout-button": elements.logout,
  };
  const root = {
    querySelector: (selector) => fixed[selector]
      || (selector === '[data-view-panel="dashboard"]' ? elements.dashboardView : null)
      || (selector === '[data-view-panel="vpn"]' ? elements.vpnView : null),
    querySelectorAll: (selector) => selector === "[data-view-panel]"
      ? [elements.dashboardView, elements.vpnView]
      : selector === "[data-view]" ? [elements.dashboardButton, elements.vpnButton] : [],
  };
  return { root, elements };
}

const authenticated = { data: { authenticated: true } };
const anonymous = { data: { authenticated: false } };

test("authenticated dashboard mode renders one complete consistent shell", () => {
  const { root, elements: e } = fixture();
  renderApplicationState({ mode: "dashboard", activeView: "dashboard" }, root, authenticated);
  assert.equal(e.shell.dataset.applicationMode, "dashboard");
  assert.equal(e.sidebar.hidden, false);
  assert.equal(e.dashboard.hidden, false);
  assert.equal(e.dashboardView.hidden, false);
  assert.equal(e.vpnView.hidden, true);
  assert.equal(e.dashboardButton.classList.contains("active"), true);
  assert.equal(e.dashboardButton.getAttribute("aria-current"), "page");
  assert.equal(e.logout.hidden, false);
});

test("login and wizard modes each expose only their main panel", () => {
  const { root, elements: e } = fixture();
  renderApplicationState({ mode: "login", activeView: "dashboard" }, root, anonymous);
  assert.equal(e.login.hidden, false);
  assert.equal(e.wizard.hidden, true);
  assert.equal(e.dashboard.hidden, true);
  assert.equal(e.sidebar.hidden, true);
  assert.equal(e.logout.hidden, true);
  renderApplicationState({ mode: "wizard", activeView: "dashboard" }, root, anonymous);
  assert.equal(e.wizard.hidden, false);
  assert.equal(e.login.hidden, true);
  assert.equal(e.dashboard.hidden, true);
});

test("invalid views fall back to dashboard and repeated rendering stays complete", () => {
  const { root, elements: e } = fixture();
  const state = renderApplicationState({ mode: "dashboard", activeView: "missing" }, root, authenticated);
  assert.equal(state.activeView, "dashboard");
  e.sidebar.hidden = true;
  e.dashboardView.hidden = true;
  renderApplicationState(state, root, authenticated);
  assert.equal(e.sidebar.hidden, false);
  assert.equal(e.dashboardView.hidden, false);
});
