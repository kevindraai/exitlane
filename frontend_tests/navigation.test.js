import assert from "node:assert/strict";
import test from "node:test";
import {
  renderApplicationState,
  resetSessionNavigation,
} from "../backend/exitlane/static/js/navigation.js";
import { getSlice, updateSlice } from "../backend/exitlane/static/js/state.js";

class Element {
  constructor(dataset = {}) {
    this.dataset = dataset;
    this.hidden = true;
    this.attributes = new Map();
    const classes = new Set();
    this.classList = {
      toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name),
      contains: (name) => classes.has(name),
      add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
    };
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  removeAttribute(name) { this.attributes.delete(name); }
  getAttribute(name) { return this.attributes.get(name); }
  append(...children) { this.children = [...(this.children || []), ...children]; }
  replaceChildren(...children) { this.children = children; }
  close() { this.open = false; }
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

test("a new authentication session discards old routes and closes transient navigation UI", () => {
  const { root, elements: e } = fixture();
  const vpnToggle = new Element();
  const vpnItems = new Element();
  const settingsToggle = new Element();
  const settingsItems = new Element();
  const settingsChevron = new Element();
  const mobileToggle = new Element();
  const mobileMenu = new Element();
  const dialog = new Element();
  const details = new Element();
  const category = new Element();
  const level = new Element();
  vpnToggle.setAttribute("aria-expanded", "true");
  settingsToggle.setAttribute("aria-expanded", "true");
  vpnItems.hidden = false;
  settingsItems.hidden = false;
  mobileToggle.setAttribute("aria-expanded", "true");
  mobileMenu.hidden = false;
  dialog.open = true;
  details.open = true;
  category.value = "auth";
  level.value = "warning";
  e.sidebar.classList.add("mobile-open");

  const originalQuerySelector = root.querySelector;
  const fixed = new Map([
    ["#vpn-navigation-toggle", vpnToggle],
    ["#vpn-navigation-items", vpnItems],
    ["#settings-navigation-toggle", settingsToggle],
    ["#settings-navigation-items", settingsItems],
    ["#settings-navigation-toggle .sidebar-group-chevron", settingsChevron],
    ["#activity-category", category],
    ["#activity-level", level],
  ]);
  root.querySelector = (selector) => fixed.get(selector) || originalQuerySelector(selector);
  const originalQuerySelectorAll = root.querySelectorAll;
  root.querySelectorAll = (selector) => {
    if (selector === "[data-mobile-navigation-toggle]") return [mobileToggle];
    if (selector === "[data-mobile-navigation]") return [mobileMenu];
    if (selector === "dialog[open]") return [dialog];
    if (selector === "details[open]") return [details];
    return originalQuerySelectorAll(selector);
  };

  const local = new Map([["exitlane-active-view", "activity"], ["theme", "dark"]]);
  const session = new Map([["exitlane-active-view", "settings"], ["unrelated", "keep"]]);
  const storage = (values) => ({
    removeItem: (key) => values.delete(key),
  });
  const routes = [];
  const events = [];
  const navigationWindow = {
    history: { replaceState: (_state, _unused, route) => routes.push(route) },
    dispatchEvent: (event) => events.push(event),
    CustomEvent: class {
      constructor(type, options) { this.type = type; this.detail = options.detail; }
    },
  };
  updateSlice("application", {
    mode: "dashboard",
    activeView: "activity",
    providerId: "nordvpn",
    settingsSection: "security",
  });
  const previousDocument = globalThis.document;
  globalThis.document = { createElementNS: () => new Element() };
  try {
    resetSessionNavigation({
      root,
      persistentStorage: storage(local),
      sessionStorageArea: storage(session),
      navigationWindow,
    });
  } finally {
    globalThis.document = previousDocument;
  }

  assert.equal(getSlice("application").activeView, "dashboard");
  assert.equal(getSlice("application").providerId, null);
  assert.equal(getSlice("application").settingsSection, "general");
  assert.deepEqual(routes, ["#dashboard"]);
  assert.equal(local.has("exitlane-active-view"), false);
  assert.equal(session.has("exitlane-active-view"), false);
  assert.equal(local.get("theme"), "dark");
  assert.equal(session.get("unrelated"), "keep");
  assert.equal(vpnToggle.getAttribute("aria-expanded"), "false");
  assert.equal(settingsToggle.getAttribute("aria-expanded"), "false");
  assert.equal(vpnItems.hidden, true);
  assert.equal(settingsItems.hidden, true);
  assert.equal(mobileToggle.getAttribute("aria-expanded"), "false");
  assert.equal(mobileMenu.hidden, true);
  assert.equal(e.sidebar.classList.contains("mobile-open"), false);
  assert.equal(dialog.open, false);
  assert.equal(details.open, false);
  assert.equal(category.value, "");
  assert.equal(level.value, "");
  assert.equal(e.dashboardButton.classList.contains("active"), true);
  assert.equal(e.vpnButton.classList.contains("active"), false);
  assert.equal(events.at(-1).detail.view, "dashboard");
});
