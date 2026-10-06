import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const versionSource = readFileSync(path.join(root, "backend/exitlane/__init__.py"), "utf8");
export const sourceVersion = versionSource.match(/^__version__ = "([^"]+)"/m)?.[1];
if (!sourceVersion) throw new Error("Cannot derive ExitLane version from source");

export const fixtureTime = "2026-10-06T12:00:00Z";
const stamp = fixtureTime;
const handshakeAt = (ageSeconds) => new Date(Date.parse(stamp) - ageSeconds * 1000).toISOString();
const createdAt = "2026-09-01T12:00:00Z";
const peers = [
  { peer_id: "peer-unifi", name: "UniFi Gateway", description: "Site gateway", status: "active", runtime_status: "active_recently", tunnel_ip: "10.66.0.2", endpoint: "198.51.100.24:51820", latest_handshake: handshakeAt(36), handshake_age: 36, received_bytes: 12789312, sent_bytes: 5242880, created_at: createdAt },
  { peer_id: "peer-synology", name: "Synology", description: "Home storage", status: "active", runtime_status: "active_recently", tunnel_ip: "10.66.0.3", endpoint: "203.0.113.18:51820", latest_handshake: handshakeAt(75), handshake_age: 75, received_bytes: 8388608, sent_bytes: 2097152, created_at: createdAt },
  { peer_id: "peer-gluetun", name: "Gluetun", description: "Container gateway", status: "active", runtime_status: "active_recently", tunnel_ip: "10.66.0.4", endpoint: "192.0.2.46:51820", latest_handshake: handshakeAt(121), handshake_age: 121, received_bytes: 3219128, sent_bytes: 1064960, created_at: createdAt },
];
const provider = { id: "nordvpn", display_name: "NordVPN", authentication_method: "token", installed: true, authenticated: true, active: true, status: { connected: true } };
const vpn = { provider_id: "nordvpn", available: true, installed: true, authenticated: true, connected: true, country: "Netherlands", country_code: "NL", city: "Amsterdam", server: "nl01.vpn.example", external_ip: "203.0.113.24", target: "Netherlands", updated_at: stamp, latency_ms: 24,
  management: { provider: { id: "nordvpn", installation_state: "available", authentication_state: "signed_in", connection_state: "connected" }, capabilities: { can_select_location: true, can_connect: true, can_disconnect: true, can_install: false } }, operation: { state: "connected" } };
const wireguard = { available: true, configured: true, active: true, connected: true, interface: "wg0", subnet: "10.66.0.0/24", listen_port: 51820, endpoint: "gateway.example:51820", total_peers: 3, recent_peers: 3, peers };
const dashboard = { health: { status: "healthy", issues: [] }, active_provider: { id: "nordvpn", display_name: "NordVPN" }, vpn, wireguard, killswitch: { available: true, configured: true, state: "enabled_protected" }, system: { metric_scope: "host", available: true, hostname: "exitlane.example", cpu_percent: 18, memory_percent: 37, memory_used_bytes: 1589137899, memory_total_bytes: 4294967296, disk_percent: 28, disk_used_bytes: 15032385536, disk_total_bytes: 53687091200, uptime_seconds: 345600, load_average: [0.18, 0.24, 0.2], temperature_celsius: 42 }, version: sourceVersion, generated_at: stamp };
const diagnosticRun = {
  run_id: "00000000-0000-4000-8000-000000000001",
  connection_id: "provider:nordvpn",
  status: "passed",
  created_at: stamp,
  started_at: stamp,
  completed_at: stamp,
  probes: [
    { id: "exitlane_network", segment: "device_exitlane", status: "passed", code: "default_route_available", detail: { interface: "nordlynx" }, observed_at: stamp, duration_ms: 12 },
    { id: "vpn_interface", segment: "exitlane_vpn", status: "passed", code: "vpn_interface_active", detail: { interface: "nordlynx" }, observed_at: stamp, duration_ms: 18 },
    { id: "vpn_handshake", segment: "exitlane_vpn", status: "passed", code: "vpn_handshake_recent", detail: { age_seconds: 36 }, observed_at: stamp, duration_ms: 16 },
    { id: "vpn_route", segment: "exitlane_vpn", status: "passed", code: "vpn_route_active", detail: { interface: "nordlynx" }, observed_at: stamp, duration_ms: 11 },
    { id: "dns_resolution", segment: "vpn_internet", status: "passed", code: "dns_resolution_passed", detail: { target: "api.vpn.example", addresses: ["203.0.113.53"] }, observed_at: stamp, duration_ms: 25 },
    { id: "internet_reachability", segment: "vpn_internet", status: "passed", code: "internet_reachable", detail: { target: "192.0.2.1", latency_ms: 24.1 }, observed_at: stamp, duration_ms: 36 },
    { id: "public_ip", segment: "vpn_internet", status: "passed", code: "public_ip_available", detail: { address: "203.0.113.24" }, observed_at: stamp, duration_ms: 24 },
  ],
};
const runtimeCapabilities = { diagnostics: true, speedtest: false, package_installation: false, timezone_configuration: true, ingress: true, system_actions: [] };
const settings = {
  general: { timezone: "Europe/Amsterdam", provider_refresh_interval_seconds: 300 },
  timezones: ["Europe/Amsterdam", "Europe/London", "UTC"],
  system: { hostname: "exitlane.example", system_timezone: "Europe/Amsterdam", timezone_consistency: { consistent: true }, session_duration_seconds: 3600 },
  about: { product: "ExitLane", version: sourceVersion, release_channel: "stable", setup_complete: true, repository_url: "https://github.com/kevindraai/exitlane", license: "GPL-3.0" },
  runtime_capabilities: runtimeCapabilities,
};
const deploymentSecurity = {
  https: false, reverse_proxy: false, direct_peer_trusted: true, direct_peer: "192.0.2.2", secure_cookie: false,
  public_url: null, warnings: [],
  configuration: { public_url: null, trusted_proxies: [], management_prefixes: ["192.0.2.0/24"], secure_cookie_policy: "auto",
    environment_overrides: { public_url: false, trusted_proxies: false, management_prefixes: false, secure_cookie_policy: false },
    sources: { public_url: "default", trusted_proxies: "default", management_prefixes: "default", secure_cookie_policy: "default" } },
  mfa_required: false,
};

function canonicalHelp() {
  const code = `import json,sys\nsys.path.insert(0,'backend')\nfrom exitlane.documentation import documentation_index, documentation_document\nprint(json.dumps({'index':documentation_index(runtime_name='native'),'diagnostics':documentation_document('diagnostics',runtime_name='native')}))`;
  const result = spawnSync("python3", ["-c", code], { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(`Canonical Help parser failed: ${result.stderr || result.error?.message}`);
  return JSON.parse(result.stdout);
}

export function createSyntheticFixture({ scenario = "authenticated" } = {}) {
  const help = canonicalHelp();
  const session = scenario === "authenticated"
    ? { authenticated: true, setup_complete: true, user: { username: "admin" } }
    : scenario === "login"
      ? { authenticated: false, setup_complete: true, user: null }
      : { authenticated: false, setup_complete: false, user: null };
  const data = {
    "GET /api/health": { ok: true, service: "exitlane", version: sourceVersion },
    "GET /api/auth/session": session,
    "GET /api/config/public": { password: { minimum_length: 12, maximum_length: 128 }, wireguard: { default_interface: "wg0", default_subnet: "10.66.0.0/24", default_port: 51820, default_client: "device" }, frontend: { provider_refresh_interval_seconds: 300 } },
    "GET /api/vpn/providers": { active_provider_id: "nordvpn", providers: [provider] },
    "GET /api/vpn/providers/nordvpn/status": { status: vpn },
    "GET /api/vpn/providers/nordvpn/locations": { countries: [
      { country_code: "NL", name: "Netherlands", latency_ms: 24, latency_measured_at: stamp, is_connected: true },
      { country_code: "DE", name: "Germany", latency_ms: 31, latency_measured_at: stamp },
      { country_code: "BE", name: "Belgium", latency_ms: 38, latency_measured_at: stamp },
    ], quick_country_codes: ["NL", "DE", "BE"], vpn },
    "GET /api/dashboard": dashboard,
    "GET /api/ingress/wireguard/status": wireguard,
    "GET /api/ingress/wireguard/peers": wireguard,
    "GET /api/vpn/killswitch": { state: "enabled_protected", configured: true, effective: true, tunnel_available: true, protected_sources: ["WireGuard"], last_transition: stamp },
    "GET /api/runtime/capabilities": runtimeCapabilities,
    "GET /api/settings": settings,
    "GET /api/auth/security": { mfa: { enabled: false, recovery_codes_remaining: 0 }, sessions: [{ id: "fixture-session", user_agent: "Browser", client_ip: "192.0.2.2", current: true }] },
    "GET /api/deployment/security": deploymentSecurity,
    "POST /api/diagnostics/connection-runs": diagnosticRun,
    [`GET /api/diagnostics/connection-runs/${diagnosticRun.run_id}`]: diagnosticRun,
    "GET /api/help/documents": help.index,
    "GET /api/help/documents/diagnostics": help.diagnostics,
    "GET /api/events?limit=50": { items: [], next_cursor: null, has_more: false },
    "GET /api/setup/state": { steps: { system: true, administrator: false, provider: false, wireguard: false }, current_step: 2, providers: [provider], selected_provider_id: null, provider_deferred: false },
  };
  const fixtureId = `source-ui-${scenario}-v1`;
  const fixtureHash = createHash("sha256").update(readFileSync(import.meta.filename)).digest("hex");
  return { fixtureId, fixtureHash, data, dashboard, peers, sourceVersion };
}
