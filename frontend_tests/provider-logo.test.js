import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { providerLogoView } from "../backend/exitlane/static/js/provider-logo.js";

const markup = fs.readFileSync(
  new URL("../backend/exitlane/static/partials/wizard/provider.html", import.meta.url),
  "utf8",
);
const css = fs.readFileSync(
  new URL("../backend/exitlane/static/style.css", import.meta.url),
  "utf8",
);
const wizard = fs.readFileSync(
  new URL("../backend/exitlane/static/js/wizard.js", import.meta.url),
  "utf8",
);
const asset = fs.readFileSync(
  new URL("../backend/exitlane/static/providers/nordvpn.svg", import.meta.url),
  "utf8",
);

test("NordVPN uses a repository-local provider asset without runtime CDN requests", () => {
  const view = providerLogoView({
    display_name: "NordVPN",
    logo: "/assets/providers/nordvpn.svg",
  });

  assert.equal(view.src, "/assets/providers/nordvpn.svg");
  assert.match(asset, /^<svg /);
  assert.doesNotMatch(markup, /cdn\.jsdelivr\.net|https?:\/\/[^"]+nordvpn\.svg/);
  assert.doesNotMatch(wizard, /cdn\.jsdelivr\.net|https?:\/\/[^"]+nordvpn\.svg/);
});

test("remote and missing logos receive a neutral local fallback", () => {
  assert.deepEqual(
    providerLogoView({
      display_name: "Example VPN",
      logo: "https://cdn.example.test/example.svg",
    }),
    { src: null, fallbackText: "E" },
  );
  assert.deepEqual(providerLogoView({ display_name: "Provider" }), {
    src: null,
    fallbackText: "P",
  });
});

test("provider name remains the accessible name while logos stay decorative", () => {
  assert.match(markup, /id="wizard-provider-name"[\s\S]*NordVPN/);
  assert.match(markup, /aria-hidden="true" class="provider-logo" data-provider-logo/);
  assert.doesNotMatch(markup, /alt="NordVPN"/);
  assert.match(wizard, /renderProviderLogo\(container, selected\)/);
});

test("generic logo containers cover compact, expanded and sign-in layouts", () => {
  assert.match(markup, /id="wizard-provider-logo"/);
  assert.match(markup, /id="install-provider-logo"/);
  assert.match(markup, /provider-logo provider-logo--compact/);
  assert.match(markup, /id="provider-login-logo"/);
  assert.match(css, /\.provider-logo\s*\{[\s\S]*object-fit: contain/);
  assert.match(css, /\.provider-logo--compact/);
  assert.match(css, /\.login-method-heading\s*\{[\s\S]*display: flex/);
});
