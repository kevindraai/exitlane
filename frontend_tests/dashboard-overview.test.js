import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dashboardLocation, dashboardPeerSummary, initialiseDashboard, renderDashboard, renderDashboardPeers } from "../backend/exitlane/static/js/dashboard.js";
import { getSlice, succeedRefresh, updateSlice } from "../backend/exitlane/static/js/state.js";
import { projectDashboardKillswitch } from "../backend/exitlane/static/js/providers.js";

const markup = await readFile(new URL("../backend/exitlane/static/partials/views/dashboard.html", import.meta.url), "utf8");
class Element {
  constructor() { this.children = []; this.attributes = {}; this.listeners = new Map(); this.dataset = {}; this.style = {}; this.hidden = false; this.open = false; this.classList = {add() {}, remove() {}, toggle() {}}; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.children.length ? this.children.map(c => c.textContent).join("") : this.text || ""; }
  set innerHTML(_) { throw Error("Unsafe HTML"); }
  setAttribute(k,v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.text = ""; this.children = items; }
  addEventListener(k,cb) { if (!this.listeners.has(k)) this.listeners.set(k,[]); this.listeners.get(k).push(cb); }
  dispatch(k,event={}) { for (const cb of this.listeners.get(k) || []) cb({preventDefault() {}, ...event}); }
  matches(selector) { return selector === ":popover-open" ? this.open : false; }
  showPopover() { if (!this.open) { this.open = true; this.dispatch("beforetoggle", {newState:"open"}); } }
  hidePopover() { if (this.open) { this.open = false; this.dispatch("beforetoggle", {newState:"closed"}); } }
  getBoundingClientRect() { return {left:100,top:100,bottom:130,width:200,height:60}; }
}
const elements = new Map([...markup.matchAll(/id="([^"]+)"/g)].map(m => [`#${m[1]}`,new Element()]));
const el = id => elements.get(`#${id}`);
const events = new Map();
globalThis.document = {querySelector: selector => elements.get(selector),createElement: () => new Element(),createElementNS: () => new Element(),createTextNode: text => {const e=new Element();e.textContent=text;return e;},activeElement:null};
globalThis.window = {innerWidth:1280,innerHeight:900,addEventListener:(k,cb)=>{if(!events.has(k))events.set(k,[]);events.get(k).push(cb);},setInterval(){},setTimeout:()=>1,clearTimeout(){}};
const peer = (id,name,state="inactive",status="active") => ({peer_id:id,name,status,runtime_status:state,received_bytes:1536,sent_bytes:1048576});
const data = () => ({health:{status:"healthy",issues:[]},active_provider:{display_name:"NordVPN"},vpn:{available:true,connected:true,city:"Amsterdam",country:"Netherlands",server:"nl1063.example.test",external_ip:"192.0.2.14",target:"Germany",updated_at:new Date().toISOString()},killswitch:{available:true,configured:true,state:"enabled_protected"},wireguard:{available:true,configured:true,active:true,peers:[peer("a","router","active_recently"),peer("b","Synology","never_connected")]},system:{available:true,hostname:"exitlane",cpu_percent:35.2,memory_used_bytes:185493094,memory_total_bytes:1073741824,memory_percent:17.3,disk_used_bytes:2040109465,disk_total_bytes:10737418240,disk_percent:19.4,uptime_seconds:496800,load_average:[3.02,2.85,2.62],temperature_celsius:42},version:"1.0.0"});
initialiseDashboard();

test("VPN facts retain provider, observed location and distinct requested target",()=>{
 renderDashboard(data());
 assert.equal(el("dashboard-vpn-provider").textContent,"NordVPN");
 assert.equal(el("dashboard-vpn-location").textContent,"Amsterdam, Netherlands");
 assert.equal(el("dashboard-vpn-target").textContent,"Germany");
 assert.equal(el("dashboard-vpn-server").title,"nl1063.example.test");
 assert.equal(el("dashboard-external-ip").title,"192.0.2.14");
 assert.equal(el("dashboard-vpn-updated").textContent,"just now");
 assert.equal(dashboardLocation({city:"Amsterdam"}),"Amsterdam");
 assert.equal(dashboardLocation({country:"Netherlands"}),"Netherlands");
 assert.equal(dashboardLocation({city:"Amsterdam",country:"—"}),"Amsterdam");
 assert.equal(dashboardLocation({}),"—");
});

test("killswitch reflects confirmed state and exposes appropriate explanation",()=>{
 const d=data();renderDashboard(d);
 assert.equal(el("dashboard-killswitch-state").textContent,"Active");
 assert.match(el("dashboard-killswitch-status").className,/status-success/);
 assert.equal(el("dashboard-killswitch-description").textContent,"Traffic is blocked when the VPN connection is lost.");
 d.killswitch={available:true,configured:false,state:"disabled"};renderDashboard(d);
 assert.equal(el("dashboard-killswitch-state").textContent,"Disabled");
 assert.equal(el("dashboard-killswitch-description").textContent,"Traffic can continue without an active VPN connection.");
 d.killswitch={available:false};renderDashboard(d);
 assert.equal(el("dashboard-killswitch-state").textContent,"Status unknown");
});

test("VPN killswitch request failure retains confirmed dashboard protection and freshness",()=>{
 const d=data();succeedRefresh("dashboard",d,1234);
 projectDashboardKillswitch(null);
 assert.deepEqual(getSlice("dashboard").data.killswitch,d.killswitch);
 assert.equal(getSlice("dashboard").updatedAt,1234);
 assert.equal(el("dashboard-killswitch-state").textContent,"Active");
 projectDashboardKillswitch({configured:false,state:"disabled"});
 assert.equal(el("dashboard-killswitch-state").textContent,"Disabled");
 assert.equal(getSlice("dashboard").updatedAt,1234);
});

test("info opens through hover, focus and click, closes with Escape and does not mutate state",()=>{
 const d=data();succeedRefresh("dashboard",d);
 const button=el("dashboard-killswitch-info"),tooltip=el("dashboard-killswitch-description");
 button.dispatch("pointerenter",{pointerType:"mouse"});assert.equal(tooltip.open,true);
 tooltip.hidePopover();button.dispatch("focus");assert.equal(tooltip.open,true);
 button.dispatch("click");assert.equal(tooltip.open,true);assert.equal(button.getAttribute("aria-expanded"),"true");
 button.dispatch("keydown",{key:"Escape"});assert.equal(tooltip.open,false);assert.equal(button.getAttribute("aria-expanded"),"false");
 button.dispatch("click");assert.equal(tooltip.open,true);button.dispatch("click");assert.equal(tooltip.open,false);
 assert.deepEqual(getSlice("dashboard").data.killswitch,d.killswitch);
 button.dispatch("click");updateSlice("application",{mode:"dashboard",activeView:"wireguard"});assert.equal(tooltip.open,false);
});

test("system facts show complete resource values and optional temperature",()=>{
 const d=data();renderDashboard(d);
 assert.equal(el("dashboard-hostname").title,"exitlane");assert.equal(el("dashboard-cpu").textContent,"35.2%");
 assert.equal(el("dashboard-memory").textContent,"176.9 MiB / 1.0 GiB · 17.3%");
 assert.equal(el("dashboard-disk").textContent,"1.9 GiB / 10.0 GiB · 19.4%");
 assert.equal(el("dashboard-uptime").textContent,"5d 18h");assert.equal(el("dashboard-load").textContent,"3.02 / 2.85 / 2.62");
 assert.equal(el("dashboard-temperature-fact").hidden,false);assert.equal(el("dashboard-temperature").textContent,"42 °C");
 d.system.temperature_celsius=null;renderDashboard(d);assert.equal(el("dashboard-temperature-fact").hidden,true);
});

test("peer summary covers empty, single, recent, stale, never and revoked without legacy aggregates",()=>{
 const wg={available:true,configured:true,active:true,connected:true,latest_handshake:1,peers:[]};renderDashboardPeers(wg);
 assert.equal(el("dashboard-wg-empty").hidden,false);assert.equal(el("dashboard-wg-table").hidden,true);
 wg.peers=[peer("b","Synology","never_connected")];renderDashboardPeers(wg);assert.equal(el("dashboard-wg-summary").textContent,"1 device");
 assert.equal(el("dashboard-wg-peer-list").children[0].children[0].children[0].getAttribute("aria-label"),"never_connected");
 wg.peers.push(peer("a","router","active_recently"),peer("c","stale"),peer("d","revoked","active_recently","revoked"));renderDashboardPeers(wg);
 const rows=el("dashboard-wg-peer-list").children;
 assert.equal(rows[0].children[1].textContent,"router");assert.equal(rows[0].children[2].textContent,"↓ 1.5 KiB↑ 1.0 MiB");
 assert.equal(rows[0].children[2].children[0].getAttribute("aria-label"),"received: 1.5 KiB");
 assert.match(rows[0].children[0].children[0].className,/status-success/);
 assert.match(rows.at(-1).children[0].children[0].className,/status-danger/);
 wg.peers=[peer("s","stale")];renderDashboardPeers(wg);assert.equal(el("dashboard-wg-pill").textContent,"waiting");
 wg.available=false;renderDashboardPeers(wg);assert.equal(el("dashboard-wg-error").hidden,false);
});

test("summary deterministically bounds devices to five with recently active first and revoked last",()=>{
 const peers=[peer("z","Zebra"),peer("c","Consumer"),peer("x","Alpha","inactive","revoked"),peer("d","delta"),peer("b","Beta"),peer("r","router","active_recently"),peer("a","alpha")];
 assert.deepEqual(dashboardPeerSummary(peers).map(p=>p.peer_id),["r","a","b","c","d"]);
 assert.deepEqual(dashboardPeerSummary([...peers].reverse()),dashboardPeerSummary(peers));
 renderDashboardPeers({available:true,active:true,peers});assert.equal(el("dashboard-wg-peer-list").children.length,5);assert.equal(el("dashboard-wg-more").textContent,"+ 2 more devices");
 assert.equal(el("dashboard-wg-more").hidden,false);
});

test("central dashboard and WireGuard subscriptions refresh peer traffic without resetting freshness",()=>{
 const d=data();succeedRefresh("dashboard",d,1234);const timestamp=getSlice("dashboard").updatedAt;
 succeedRefresh("wireguard",{...d.wireguard,peers:[{...peer("new","New consumer","active_recently"),received_bytes:4096}]});
 assert.equal(el("dashboard-wg-peer-list").children[0].children[1].textContent,"New consumer");
 assert.match(el("dashboard-wg-peer-list").textContent,/↓ 4.0 KiB/);
 assert.equal(getSlice("dashboard").updatedAt,timestamp);
 updateSlice("dashboard",{error:"request_failed",stale:true});assert.equal(el("dashboard-vpn-provider").textContent,"NordVPN");
});

test("inspecting an inactive provider cannot replace the active egress facts",()=>{
 const d=data();d.active_provider.id="nordvpn";succeedRefresh("dashboard",d);
 succeedRefresh("provider",{management:{provider:{id:"mullvad"}},country:"Sweden",city:"Stockholm",external_ip:"192.0.2.99"});
 assert.equal(el("dashboard-vpn-location").textContent,"Amsterdam, Netherlands");
 succeedRefresh("provider",{management:{provider:{id:"nordvpn"}},country:"Germany",city:"Berlin"});
 assert.equal(el("dashboard-vpn-location").textContent,"Berlin, Germany");
});

test("dashboard is semantic facts and a bounded accessible table with no nested metric boxes",async()=>{
 assert.equal((markup.match(/<dl class="dashboard-facts">/g)||[]).length,2);
 assert.doesNotMatch(markup,/class="metric|dashboard-killswitch-card|dashboard-wg-client|dashboard-wg-endpoint|dashboard-wg-handshake|dashboard-wg-received|dashboard-wg-sent|dashboard-wg-refresh/);
 assert.match(markup,/dashboard-wireguard-card/);assert.match(markup,/scope="col"/);
 assert.match(markup,/aria-describedby="dashboard-killswitch-description"/);assert.match(markup,/popover="auto" role="tooltip"/);
 assert.match(markup,/data-lucide-icon="info"/);
 for(const language of ["en","nl"]){const locale=JSON.parse(await readFile(new URL(`../backend/exitlane/static/locales/${language}.json`,import.meta.url),"utf8"));for(const key of ["location","killswitch_info","device","traffic","no_devices","more_devices","device_count","wireguard_devices"])assert.ok(locale.dashboard[key]);}
});
