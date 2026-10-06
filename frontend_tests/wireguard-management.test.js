import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  clearManagedConfiguration, configurationViewState, confirmPeerMutation,
  copyManagedConfiguration, handshakeLabel, initialiseWireGuardManagement,
  loadManagedPeers, openConfigurationQr, openPeerConfiguration, openPeerEditor,
  closePeerActions, openPeerActions, openPeerMutation, peerActions, peerPath, peerStatusView, renderPeerList,
  savePeerEditor, toggleManagedConfiguration,
} from "../backend/exitlane/static/js/wireguard-management.js";
import { getSlice, resetAuthenticatedState, updateSlice } from "../backend/exitlane/static/js/state.js";

const sourceUrl = new URL("../backend/exitlane/static/js/wireguard-management.js", import.meta.url);
const markupUrl = new URL("../backend/exitlane/static/partials/views/wireguard.html", import.meta.url);

class Element {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attributes = {};
    this.hidden = false; this.disabled = false; this.open = false; this.value = ""; this.listeners = new Map();
    this.classList = { add() {}, toggle() {} }; this.style = {}; this.isConnected = true;
  }
  set textContent(value) { this.children = []; this.text = String(value); }
  get textContent() { return this.children.length ? this.children.map((child) => child.textContent).join("") : this.text || ""; }
  set innerHTML(_) { throw new Error("Unsafe HTML rendering"); }
  set src(value) { this.setAttribute("src", value); }
  get src() { return this.getAttribute("src"); }
  set href(value) { this.setAttribute("href", value); }
  get href() { return this.getAttribute("href"); }
  set download(value) { this.setAttribute("download", value); }
  get download() { return this.getAttribute("download"); }
  append(...items) { for (const item of items) { item.parent = this; item.isConnected = true; this.children.push(item); } }
  appendChild(item) { this.append(item); }
  replaceChildren(...items) { this.text = ""; this.children = items; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(name, callback) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(callback); }
  dispatch(name, values = {}) { for (const callback of this.listeners.get(name) || []) callback({ currentTarget: this, preventDefault() {}, ...values }); }
  showModal() { this.open = true; }
  showPopover() { this.open = true; }
  hidePopover() { this.open = false; }
  getBoundingClientRect() { return {top:100,bottom:140,right:1000,width:220,height:260}; }
  close() { if (this.open) { this.open = false; this.dispatch("close"); } }
  reportValidity() { return false; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((item) => item !== this); this.isConnected = false; }
  focus() { document.activeElement = this; }
  select() { this.selected = true; }
  querySelectorAll(selector) {
    const matches = [];
    for (const child of this.children) { if (child.tagName?.toLowerCase() === selector) matches.push(child); matches.push(...(child.querySelectorAll?.(selector) || [])); }
    return matches;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

const markup = await readFile(markupUrl, "utf8");
const elements = new Map([...markup.matchAll(/id="([^"]+)"/g)].map((match) => [`#${match[1]}`, new Element()]));
elements.set("#toast-region", new Element());
// The real container owns the table body; match that relationship for busy controls.
elements.get("#wireguard-peers-content").append(elements.get("#wireguard-peer-list"));
globalThis.document = {
  querySelector: (selector) => elements.get(selector) || null,
  createElement: (tag) => new Element(tag), createElementNS: (_, tag) => new Element(tag),
  createTextNode: (text) => { const node = new Element(); node.textContent = text; return node; },
  activeElement: null,
};
const windowEvents = new Map();
globalThis.window = { innerWidth:1440, innerHeight:900, addEventListener: (name, cb) => { windowEvents.set(name, cb); }, setTimeout() {}, dispatchEvent() {} };
let copied = null;
Object.defineProperty(globalThis, "navigator", { configurable: true, value: { clipboard: { writeText: async (value) => { copied = value; } } } });
let requests = [];
let responseFor = () => ({});
globalThis.fetch = async (path, options) => {
  requests.push({ path, options });
  const payload = await responseFor(path, options);
  return { ok: true, headers: { get: () => "application/json" }, json: async () => payload };
};
initialiseWireGuardManagement();
const element = (id) => elements.get(`#${id}`);
const router = { peer_id: "router-id", name: "UniFi Gateway", description: "Router", public_key: "public-A", tunnel_ip: "10.99.99.2", status: "active", runtime_status: "active_recently", latest_handshake: 1000, handshake_age: 8, endpoint: "192.0.2.2:51820", received_bytes: 1024, sent_bytes: 2048, created_at: "2026-01-01T12:00:00Z" };
const deluge = { ...router, peer_id: "deluge-id", name: "Deluge - Synology", public_key: "public-B", tunnel_ip: "10.99.99.3", runtime_status: "inactive", handshake_age: 172800, received_bytes: 4096 };
const list = (peers = [router, deluge]) => ({ peers, total_peers: peers.length, recent_peers: 1, active: true, interface: "wg0", subnet: "10.99.99.0/24", endpoint: "192.0.2.1", listen_port: 51820 });
const config = { available: true, configuration: "PrivateKey = synthetic-private-B", filename: "exitlane-deluge-synology.conf" };

function reset() {
  closePeerActions(); clearManagedConfiguration(); requests = []; copied = null;
  responseFor = (path) => path.endsWith("/config") ? config : list();
  for (const id of ["wireguard-config-dialog", "wireguard-qr-dialog", "wireguard-peer-editor-dialog", "wireguard-peer-mutation-dialog"]) element(id).close();
}

test("configuration stays out of rendered code until explicitly shown", () => {
  const payload = { available: true, configuration: "PrivateKey = synthetic" };
  assert.deepEqual(configurationViewState(payload), { available: true, configuration: payload.configuration, displayedConfiguration: "" });
  assert.equal(configurationViewState(payload, true).displayedConfiguration, payload.configuration);
  assert.equal(configurationViewState({ available: false }).available, false);
});

test("runtime recency comes from backend and revoked state wins over old handshakes", () => {
  assert.equal(peerStatusView(router).key, "active_recently");
  assert.equal(peerStatusView(deluge).key, "inactive");
  assert.equal(peerStatusView({ ...router, runtime_status: "never_connected" }).key, "never_connected");
  assert.equal(peerStatusView({ ...router, status: "revoked" }).key, "revoked");
  assert.equal(peerStatusView({ runtime_status: "unrecognised" }).key, "unknown");
  assert.equal(handshakeLabel(router), "8 sec ago");
  assert.equal(handshakeLabel(deluge), "2 d ago");
  assert.equal(handshakeLabel({ latest_handshake: 0 }), "Never");
  assert.deepEqual(peerActions(router), ["config", "edit", "regenerate", "revoke"]);
  assert.deepEqual(peerActions({ status: "revoked" }), ["edit", "regenerate", "delete"]);
});

test("resource paths encode durable identity independently of display names", () => {
  assert.equal(peerPath("id/../two", "/config/qr"), "/api/ingress/wireguard/peers/id%2F..%2Ftwo/config/qr");
});

test("peer list maps identity, traffic, status and endpoint and safely renders untrusted names", () => {
  reset();
  renderPeerList(list([router, { ...deluge, name: '<img src=x onerror="bad()">', description: "<script>bad()</script>" }]));
  const rows = element("wireguard-peer-list").children;
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /UniFi Gateway.*10\.99\.99\.2.*Active recently.*8 sec ago.*192\.0\.2\.2.*RX 1/);
  assert.match(rows[1].textContent, /<img src=x onerror="bad\(\)">/);
  assert.match(rows[1].textContent, /Inactive.*2 d ago.*RX 4/);
  assert.equal(rows[0].dataset.peerId, "router-id");
  assert.equal(element("management-wireguard-total").textContent, "2");
  assert.equal(element("wireguard-peers-empty").hidden, true);
  assert.equal(element("wireguard-peers-content").hidden, false);
  renderPeerList(list([]));
  assert.equal(element("wireguard-peers-empty").hidden, false);
  assert.equal(element("wireguard-peers-content").hidden, true);
});

test("configuration modal copy/download/QR target selected device and clear secrets on close", async () => {
  reset();
  await openPeerConfiguration(deluge);
  assert.equal(requests[0].path, peerPath(deluge.peer_id, "/config"));
  assert.equal(requests[0].options.cache, "no-store");
  assert.equal(element("wireguard-config-dialog").open, true);
  assert.equal(element("management-wireguard-config").textContent, "");
  toggleManagedConfiguration();
  assert.equal(element("management-wireguard-config").textContent, config.configuration);
  assert.equal(element("wireguard-config-toggle").getAttribute("aria-expanded"), "true");
  await copyManagedConfiguration();
  assert.equal(copied, config.configuration);
  assert.equal(element("wireguard-config-download").href, peerPath("deluge-id", "/config/download"));
  assert.equal(element("wireguard-config-download").download, config.filename);
  assert.equal(openConfigurationQr(), true);
  assert.equal(element("wireguard-qr-image").src, peerPath("deluge-id", "/config/qr"));
  element("wireguard-qr-dialog").close();
  assert.equal(element("wireguard-qr-image").src, null);
  element("wireguard-config-dialog").close();
  assert.equal(element("management-wireguard-config").textContent, "");
  assert.equal(element("wireguard-config-download").href, null);
  assert.equal(openConfigurationQr(), false);
});

test("copy works on trusted LAN HTTP without Clipboard API and clears temporary secret", async () => {
  reset();
  await openPeerConfiguration(deluge);
  const previous = element("wireguard-config-copy");
  previous.focus();
  const originalNavigator = globalThis.navigator;
  let temporary;
  let copiedText;
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: {} });
  document.execCommand = (action) => {
    assert.equal(action, "copy");
    temporary = document.activeElement;
    assert.equal(temporary.selected, true);
    copiedText = temporary.value;
    return true;
  };
  try {
    await copyManagedConfiguration();
    assert.equal(copiedText, config.configuration);
    assert.equal(temporary.value, "");
    assert.equal(temporary.isConnected, false);
    assert.equal(document.activeElement, previous);
  } finally {
    Object.defineProperty(globalThis, "navigator", { configurable: true, value: originalNavigator });
    delete document.execCommand;
    element("wireguard-config-dialog").close();
  }
});

test("closing modal or losing authentication rejects a delayed secret response", async () => {
  reset();
  let resolve;
  responseFor = () => new Promise((done) => { resolve = done; });
  const loading = openPeerConfiguration(deluge);
  element("wireguard-config-dialog").close();
  resolve(config); await loading;
  assert.equal(element("wireguard-config-content").hidden, true);
  assert.equal(element("management-wireguard-config").textContent, "");
  const second = openPeerConfiguration(deluge);
  windowEvents.get("exitlane:authenticationrequired")();
  resolve(config); await second;
  assert.equal(element("wireguard-config-dialog").open, false);
  assert.equal(element("wireguard-config-download").href, null);
});

test("adding opens new device configuration immediately; edit only PATCHes metadata", async () => {
  reset();
  responseFor = (path, options) => options.method === "POST" ? { peer: deluge, ...config } : list();
  openPeerEditor(); element("wireguard-peer-name").value = deluge.name; element("wireguard-peer-description").value = "NAS consumer";
  await savePeerEditor({ preventDefault() {} });
  assert.equal(requests[0].path, "/api/ingress/wireguard/peers");
  assert.equal(requests[0].options.method, "POST");
  assert.deepEqual(JSON.parse(requests[0].options.body), { name: deluge.name, description: "NAS consumer" });
  assert.equal(element("wireguard-config-dialog").open, true);
  assert.equal(element("wireguard-config-download").href, peerPath("deluge-id", "/config/download"));
  assert.equal(requests.some(({ path }) => path.endsWith("/config")), false);
  reset();
  openPeerEditor(deluge); element("wireguard-peer-name").value = "NAS download container";
  await savePeerEditor({ preventDefault() {} });
  assert.equal(requests[0].path, peerPath("deluge-id"));
  assert.equal(requests[0].options.method, "PATCH");
  assert.deepEqual(Object.keys(JSON.parse(requests[0].options.body)).sort(), ["description", "name"]);
});

test("regenerate, revoke and delete are explicit confirmed resource mutations", async () => {
  for (const action of ["regenerate", "revoke", "delete"]) {
    reset();
    const peer = action === "delete" ? { ...deluge, status: "revoked" } : deluge;
    responseFor = (path, options) => options.method === "POST" ? { peer: { ...peer, status: "active", public_key: "new-B" }, ...config } : list([router, { ...deluge, public_key: "new-B" }]);
    assert.equal(openPeerMutation(peer, action), true);
    assert.equal(requests.length, 0);
    assert.match(element("wireguard-peer-mutation-title").textContent, /Deluge - Synology/);
    await confirmPeerMutation();
    assert.equal(requests[0].path, peerPath("deluge-id", action === "delete" ? "" : `/${action}`));
    assert.equal(requests[0].options.method, action === "delete" ? "DELETE" : "POST");
    assert.equal(element("wireguard-peer-mutation-confirm").disabled, false);
    assert.equal(element("wireguard-config-dialog").open, action === "regenerate");
  }
  assert.equal(openPeerMutation(router, "delete"), false);
});

test("duplicate mutation submits cannot race; failed action keeps confirmation visible", async () => {
  reset();
  let reject;
  responseFor = () => new Promise((_, fail) => { reject = fail; });
  openPeerMutation(deluge, "revoke");
  const first = confirmPeerMutation();
  await confirmPeerMutation();
  assert.equal(requests.length, 1);
  assert.equal(element("wireguard-peer-mutation-confirm").disabled, true);
  reject(new Error("synthetic transport failure")); await first;
  assert.equal(element("wireguard-peer-mutation-dialog").open, true);
  assert.equal(element("wireguard-peer-mutation-error").hidden, false);
  assert.equal(element("wireguard-peer-mutation-confirm").disabled, false);
});

test("revoked peer has no config access and external key change clears open secret", async () => {
  reset();
  await openPeerConfiguration({ ...deluge, status: "revoked" });
  assert.equal(requests.length, 0);
  await openPeerConfiguration(deluge, config);
  toggleManagedConfiguration();
  renderPeerList(list([router, { ...deluge, public_key: "replaced-public-key" }]));
  assert.equal(element("wireguard-config-dialog").open, false);
  assert.equal(element("management-wireguard-config").textContent, "");
});

test("list error displays stable translated message and never renders error payload secrets", async () => {
  reset();
  responseFor = () => { throw new Error("PrivateKey = must-not-be-rendered"); };
  await loadManagedPeers();
  assert.equal(element("wireguard-peers-error").hidden, false);
  assert.doesNotMatch(element("wireguard-peers-error").textContent, /PrivateKey/);
  assert.equal(element("wireguard-peers-loading").hidden, true);
});

test("central authenticated state includes and clears peer metadata", async () => {
  reset();
  responseFor = () => list();
  await loadManagedPeers();
  assert.equal(getSlice("wireguardPeers").data.peers[1].name, deluge.name);
  resetAuthenticatedState();
  assert.equal(getSlice("wireguardPeers").data, null);
});

test("navigation and page hide clear modal secrets", async () => {
  reset();
  updateSlice("application", { mode: "dashboard", activeView: "wireguard" });
  await openPeerConfiguration(deluge, config); toggleManagedConfiguration();
  updateSlice("application", { activeView: "dashboard" });
  assert.equal(element("management-wireguard-config").textContent, "");
  assert.equal(element("wireguard-config-dialog").open, false);
  await openPeerConfiguration(deluge, config); toggleManagedConfiguration();
  windowEvents.get("pagehide")();
  assert.equal(element("management-wireguard-config").textContent, "");
});

test("accessible dialogs and complete English/Dutch labels cover all device flows", async () => {
  for (const id of ["wireguard-peer-editor", "wireguard-config", "wireguard-peer-mutation", "wireguard-qr"]) {
    assert.match(markup, new RegExp(`<dialog[^>]+aria-labelledby="${id === "wireguard-peer-editor" ? id : id === "wireguard-peer-mutation" ? id : id}-title"`));
  }
  assert.match(markup, /aria-controls="management-wireguard-config" aria-expanded="false"/);
  assert.match(markup, /maxlength="80" required/);
  assert.match(markup, /maxlength="240" rows="3"/);
  const source = await readFile(sourceUrl, "utf8");
  assert.doesNotMatch(source, /innerHTML|localStorage|\/config\/regenerate/);
  for (const language of ["en", "nl"]) {
    const locale = JSON.parse(await readFile(new URL(`../backend/exitlane/static/locales/${language}.json`, import.meta.url), "utf8"));
    for (const key of ["add", "edit", "config", "show", "hide", "copy", "download", "qr", "regenerate", "revoke", "delete", "peers_empty", "unique_profile", "recency_help"]) assert.ok(locale.wireguard_management[key]);
    for (const key of ["active_recently", "inactive", "never_connected", "revoked", "unknown"]) assert.ok(locale.wireguard_management.peer_status[key]);
    for (const action of ["created", "updated", "regenerated", "revoked", "deleted"]) assert.match(locale.events.wireguard[`peer_${action}`], /\{name\}/);
    for (const action of ["regenerate", "revoke", "delete"]) assert.match(locale.wireguard_management[`${action}_title`], /\{name\}/);
  }
});


test("each row has one menu trigger; opening actions is private to the selected peer", () => {
  reset(); renderPeerList(list());
  const rows = element("wireguard-peer-list").children;
  assert.equal(rows[0].querySelectorAll("button").length, 1);
  const trigger = rows[1].querySelector("button");
  assert.equal(trigger.getAttribute("aria-expanded"), "false");
  openPeerActions(deluge, trigger);
  const menu = element("wireguard-peer-actions-popover");
  assert.equal(menu.open, true);
  assert.equal(trigger.getAttribute("aria-expanded"), "true");
  assert.match(menu.textContent, /Deluge - Synology.*Router.*Created/);
  assert.deepEqual(menu.querySelectorAll("button").map(b => b.dataset.peerAction), peerActions(deluge));
  assert.equal(requests.length, 0);
  menu.querySelectorAll("button")[1].dispatch("click");
  assert.equal(menu.open, false);
  assert.equal(element("wireguard-peer-name").value, deluge.name);
});

test("open actions survive telemetry refresh and close when peer access changes", () => {
  reset(); renderPeerList(list());
  openPeerActions(deluge, element("wireguard-peer-list").children[1].querySelector("button"));
  renderPeerList(list());
  assert.equal(element("wireguard-peer-actions-popover").open, true);
  assert.equal(element("wireguard-peer-list").children[1].querySelector("button").getAttribute("aria-expanded"), "true");
  renderPeerList(list([router, {...deluge, status:"revoked"}]));
  assert.equal(element("wireguard-peer-actions-popover").open, false);
  openPeerActions({...deluge, status:"revoked"}, element("wireguard-peer-list").children[1].querySelector("button"));
  assert.deepEqual(element("wireguard-peer-actions-popover").querySelectorAll("button").map(b => b.dataset.peerAction), ["edit", "regenerate", "delete"]);
  windowEvents.get("pagehide")();
  assert.equal(element("wireguard-peer-actions-popover").open, false);
});

test("new device uses a neutral translated name placeholder", async () => {
  assert.match(markup, /placeholder="Name"/);
  for (const [language, value] of [["en", "Name"], ["nl", "Naam"]]) {
    const locale = JSON.parse(await readFile(new URL(`../backend/exitlane/static/locales/${language}.json`, import.meta.url), "utf8"));
    assert.equal(locale.wireguard_management.name_placeholder, value);
    assert.match(locale.wireguard_management.actions_for, /\{name\}/);
  }
});

test("Escape returns focus to the trigger and light dismissal clears expanded state", () => {
  reset(); renderPeerList(list());
  const trigger = element("wireguard-peer-list").children[1].querySelector("button");
  const menu = element("wireguard-peer-actions-popover");
  assert.equal(trigger.getAttribute("popovertarget"), "wireguard-peer-actions-popover");
  trigger.dispatch("click");
  menu.dispatch("keydown", { key: "Escape" });
  assert.equal(menu.open, false);
  assert.equal(document.activeElement, trigger);
  assert.equal(trigger.getAttribute("aria-expanded"), "false");
  trigger.dispatch("click");
  menu.dispatch("beforetoggle", { newState: "closed" });
  assert.equal(trigger.getAttribute("aria-expanded"), "false");
});
