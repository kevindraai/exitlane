import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createSyntheticFixture, fixtureTime, sourceVersion } from "../tests/screenshots/synthetic-fixture.mjs";
import { installSyntheticBrowser, syntheticOrigin } from "../tests/screenshots/synthetic-browser.mjs";
import { assertSafeVisibleState, isPublicIpv4 } from "../tests/screenshots/privacy.mjs";
import { prepareCaptureDirectory, resolveCaptureOutput, writeCaptureFile } from "../tests/screenshots/output-policy.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("fixture reflects source version and a complete healthy three-device presentation", () => {
  const fixture = createSyntheticFixture();
  assert.equal(fixture.data["GET /api/health"].version, sourceVersion);
  assert.equal(fixture.dashboard.version, sourceVersion);
  assert.equal(fixture.dashboard.health.status, "healthy");
  assert.equal(fixture.dashboard.vpn.connected, true);
  assert.equal(fixture.dashboard.killswitch.state, "enabled_protected");
  assert.deepEqual(fixture.peers.map(({ name }) => name), ["UniFi Gateway", "Synology", "Gluetun"]);
  assert.equal(fixture.peers.filter(({ runtime_status }) => runtime_status === "active_recently").length, 3);
  assert.ok(fixture.peers.every(({ received_bytes, sent_bytes, latest_handshake }) => received_bytes > 0 && sent_bytes > 0 && latest_handshake));
  assert.ok(fixture.peers.every(({ latest_handshake, handshake_age, created_at }) => (
    (Date.parse(fixture.dashboard.generated_at) - Date.parse(latest_handshake)) / 1000 === handshake_age
    && Date.parse(created_at) < Date.parse(latest_handshake)
  )));
  assert.equal(fixture.data["GET /api/settings"].about.license, "GPL-3.0");
  assert.equal(fixture.data["POST /api/diagnostics/connection-runs"].status, "passed");
  const parser = [
    "import ast,json,pathlib",
    "source=pathlib.Path('backend/exitlane/services/connection_diagnostics.py').read_text()",
    "module=ast.parse(source)",
    "value=next(node.value for node in module.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='PROBE_DEFINITIONS' for target in node.targets))",
    "names={'exitlane_network':'probe_exitlane_network','vpn_interface':'probe_vpn_interface','vpn_handshake':'probe_vpn_handshake','vpn_route':'probe_vpn_route','dns_resolution':'dns_lookup','internet_reachability':'ping','public_ip':'external_ip'}",
    "functions={node.name:node for node in module.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}",
    "literals={probe:sorted({node.value for node in ast.walk(functions[name]) if isinstance(node,ast.Constant) and isinstance(node.value,str)}) for probe,name in names.items()}",
    "print(json.dumps({'definitions':ast.literal_eval(value),'literals':literals}))",
  ].join("\n");
  const result = spawnSync("python3", ["-c", parser], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const { definitions, literals } = JSON.parse(result.stdout);
  assert.deepEqual(
    fixture.data["POST /api/diagnostics/connection-runs"].probes.map(({ id, segment }) => [id, segment]),
    definitions,
  );
  assert.equal(definitions.length, 7);
  for (const probe of fixture.data["POST /api/diagnostics/connection-runs"].probes) {
    assert.ok(literals[probe.id].includes(probe.code), `${probe.id}: code absent from backend implementation`);
    for (const key of Object.keys(probe.detail)) {
      assert.ok(literals[probe.id].includes(key), `${probe.id}: detail key ${key} absent from backend implementation`);
    }
    assert.equal(probe.status, "passed");
    assert.equal(probe.observed_at, fixtureTime);
    assert.ok(probe.duration_ms >= 0);
  }
  assert.ok(fixture.data["GET /api/help/documents"].documents.length >= 12);
  assert.ok(fixture.data["GET /api/help/documents/diagnostics"].blocks.length > 0);
});

test("pre-capture privacy guard rejects visible secret canaries and exposed controls", async () => {
  const safe = { text: "Healthy · 203.0.113.24 · gateway.example", configClosed: true, qrClosed: true, dialogs: [], populatedPasswords: [] };
  const page = (state) => ({ evaluate: async () => state });
  await assert.doesNotReject(assertSafeVisibleState(page(safe), "safe-fixture"));
  for (const text of [
    "PrivateKey = TEST_CANARY",
    "PresharedKey = TEST_CANARY",
    "Bearer TEST_CANARY_123456789012",
    "recovery code: TEST_CANARY",
    "External IP 8.8.8.8",
  ]) {
    await assert.rejects(assertSafeVisibleState(page({ ...safe, text }), "canary"), /sensitive marker|unredacted public IP/);
  }
  for (const state of [
    { configClosed: false },
    { qrClosed: false },
    { dialogs: ["wireguard-config-dialog"] },
    { populatedPasswords: ["login-password"] },
  ]) {
    await assert.rejects(assertSafeVisibleState(page({ ...safe, ...state }), "canary"), /sensitive control or credential/);
  }
});

test("fixture and published capture paths contain only reserved network identities", async () => {
  const fixture = createSyntheticFixture();
  const content = JSON.stringify(fixture.data);
  assert.doesNotMatch(content, /PrivateKey\s*=|PresharedKey\s*=|Bearer\s+[A-Za-z0-9._~-]{12,}/i);
  const addresses = content.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  assert.ok(addresses.length > 0);
  assert.ok(addresses.every((address) => !isPublicIpv4(address)));
  assert.equal(isPublicIpv4("8.8.8.8"), true);
  assert.equal(isPublicIpv4("203.0.113.24"), false);
  assert.equal(isPublicIpv4("198.51.100.24"), false);
  const capture = await readFile(path.join(root, "tests/screenshots/capture.mjs"), "utf8");
  assert.doesNotMatch(capture, /172\.16\.130\.81|0\.2\.0-rc\.1/);
});

test("synthetic request boundary serves known source assets and fails closed", async () => {
  let handler;
  const context = { route: async (_pattern, callback) => { handler = callback; } };
  const result = await installSyntheticBrowser(context);
  const exercise = async (url, method = "GET") => {
    let response;
    const route = {
      request: () => ({ url: () => url, method: () => method }),
      fulfill: async (value) => { response = value; },
      abort: async () => { response = { aborted: true }; },
    };
    await handler(route);
    return response;
  };
  const index = await exercise(`${syntheticOrigin}/`);
  assert.equal(index.status, 200);
  assert.match(index.body, /id="dashboard-panel"/);
  assert.doesNotMatch(index.body, /EXITLANE_PARTIAL:/);
  const script = await exercise(`${syntheticOrigin}/assets/js/app.js`);
  assert.equal(script.status, 200);
  assert.match(script.contentType, /javascript/);
  const known = await exercise(`${syntheticOrigin}/api/dashboard`);
  assert.equal(JSON.parse(known.body).health.status, "healthy");
  const unknown = await exercise(`${syntheticOrigin}/api/not-a-product-route`);
  assert.equal(unknown.status, 501);
  const external = await exercise("https://example.com/");
  assert.equal(external.aborted, true);
  assert.deepEqual(result.failures, [
    "unhandled API: GET /api/not-a-product-route",
    "external request: https://example.com",
  ]);
});

test("live output requires an explicit private directory outside the repository", async () => {
  assert.throws(() => resolveCaptureOutput({ mode: "live", repositoryRoot: root }), /explicit/);
  assert.throws(() => resolveCaptureOutput({ mode: "live", repositoryRoot: root, requestedOutput: path.join(root, "docs/images") }), /outside/);
  assert.throws(() => resolveCaptureOutput({ mode: "live", repositoryRoot: root, requestedOutput: path.join(root, "private") }), /outside/);
  assert.equal(resolveCaptureOutput({ mode: "synthetic", repositoryRoot: root }), path.join(root, "docs/images"));
  const temporary = await mkdtemp(path.join(tmpdir(), "exitlane-live-output-test-"));
  try {
    const privateDirectory = path.join(temporary, "private");
    await prepareCaptureDirectory(privateDirectory, { mode: "live", repositoryRoot: root });
    assert.equal((await stat(privateDirectory)).mode & 0o777, 0o700);
    const file = path.join(privateDirectory, "capture.png");
    await writeCaptureFile(file, Buffer.from("private candidate"), { mode: "live" });
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const link = path.join(temporary, "link-to-repository");
    await symlink(root, link);
    await assert.rejects(
      prepareCaptureDirectory(link, { mode: "live", repositoryRoot: root }),
      /resolves inside the repository/,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
