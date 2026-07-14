import { postJson } from "./api.js";
import { appState } from "./state.js";
import {
  clearInlineError,
  select,
  setBusy,
  showInlineError,
  showMessage,
} from "./ui.js";
import { refreshSetup } from "./wizard.js";

async function generateWireGuard(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  setBusy(button, true, "Genereren…");
  clearInlineError();

  try {
    const client = select("#wg-client").value.trim();

    const result = await postJson("/api/ingress/wireguard", {
      endpoint: select("#wg-endpoint").value.trim(),
      subnet: select("#wg-subnet").value.trim(),
      port: Number(select("#wg-port").value),
      interface: select("#wg-interface").value.trim(),
      client,
    });

    appState.generatedClientName = result.client_name || client;

    select("#wireguard-config").textContent = result.client_config;
    select("#wireguard-download").href =
      `/api/ingress/wireguard/client/${encodeURIComponent(
        appState.generatedClientName,
      )}`;
    select("#wireguard-result").hidden = false;
    select("#wireguard-next").disabled = false;

    showMessage("WireGuard-configuraties gegenereerd.");
    await refreshSetup();
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

async function copyWireGuardConfig() {
  const configuration = select("#wireguard-config").textContent;

  try {
    await navigator.clipboard.writeText(configuration);
    showMessage("WireGuard-configuratie gekopieerd.");
  } catch {
    showMessage(
      "Kopiëren via de browser is niet gelukt. Selecteer de configuratie handmatig.",
      "error",
    );
  }
}

export function initialiseWireGuardControls() {
  select("#wireguard-form").addEventListener("submit", generateWireGuard);
  select("#wireguard-copy").addEventListener("click", copyWireGuardConfig);
}
