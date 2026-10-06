export function isPublicIpv4(value) {
  const octets = value.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second, third] = octets;
  return !(first === 0 || first === 10 || first === 127 || first >= 224
    || first === 169 && second === 254 || first === 172 && second >= 16 && second <= 31
    || first === 192 && second === 168 || first === 100 && second >= 64 && second <= 127
    || first === 192 && second === 0 && third === 2 || first === 198 && second === 51 && third === 100
    || first === 203 && second === 0 && third === 113);
}

export async function redactLiveIp(page, id, mode) {
  const selector = { dashboard: "#dashboard-external-ip", vpn: "#metric-ip" }[id];
  if (mode !== "live" || !selector) return [];
  const element = page.locator(selector);
  const original = ((await element.getAttribute("aria-label")) || await element.innerText()).trim();
  if (!isPublicIpv4(original)) throw new Error(`${id}: expected an observed public IP before redaction`);
  await element.evaluate((node) => {
    node.replaceChildren(document.createTextNode("Redacted"));
    node.setAttribute("aria-label", "External IP redacted for publication");
    node.setAttribute("title", "External IP redacted for publication");
  });
  return [{ selector, field: "external IP", strategy: "verified live value replaced before capture" }];
}

export async function assertSafeVisibleState(page, id) {
  const state = await page.evaluate(() => {
    const visible = (node) => !!node && !node.hidden && !!node.getClientRects().length && getComputedStyle(node).visibility !== "hidden";
    const secret = document.querySelector("#management-wireguard-config");
    return {
      text: document.body.innerText,
      configClosed: !visible(secret),
      qrClosed: ![...document.querySelectorAll("[id*='qr-dialog'], [id*='config-dialog'], [id*='recovery-codes']")].some((node) => node.open),
      dialogs: [...document.querySelectorAll("dialog[open]")].map((node) => node.id),
      populatedPasswords: [...document.querySelectorAll("input[type=password]")].filter((node) => node.value).map((node) => node.id),
    };
  });
  if (!state.configClosed || !state.qrClosed || state.dialogs.length || state.populatedPasswords.length) throw new Error(`${id}: sensitive control or credential is open`);
  if (/\b(?:PrivateKey|PresharedKey)\s*=|\brecovery code\s*:|\bbearer\s+[A-Za-z0-9._~-]{12,}/i.test(state.text)) throw new Error(`${id}: visible sensitive marker`);
  if ((state.text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).some(isPublicIpv4)) throw new Error(`${id}: visible content contains an unredacted public IP address`);
}
