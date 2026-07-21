import { api, postJson } from "./api.js";
import { appState } from "./state.js";
import {
  clearInlineError,
  select,
  setBusy,
  showInlineError,
  showMessage,
} from "./ui.js";
import { refreshSetup } from "./wizard.js";
import { prepareFinishStep } from "./finish.js";
import { t } from "./i18n.js";

async function loadDetectedEndpoint() {
  const endpointInput = select("#wg-endpoint");
  const helpText = select("#wg-endpoint-help");

  if (endpointInput.value.trim()) {
    return;
  }

  try {
    const network = await api("/api/system/network");

    endpointInput.value = network.endpoint;
    helpText.textContent =
      `Automatisch gedetecteerd via ${network.interface}.`;
  } catch (error) {
    helpText.textContent =
      "Automatische detectie is mislukt. Vul het lokale IP-adres handmatig in.";

    showMessage(error.message, "error");
  }
}

async function generateWireGuard(event) {
  event.preventDefault();

  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');

  setBusy(
  button,
  true,
  t("busy.generating", {}, "Generating…"),
);
  clearInlineError();

  try {
    const client = select("#wg-client").value.trim();

    const result = await postJson(
      "/api/ingress/wireguard",
      {
        endpoint: select("#wg-endpoint").value.trim(),
        subnet: select("#wg-subnet").value.trim(),
        dns: select("#wg-dns").value.trim(),
        port: Number(select("#wg-port").value),
        interface: select("#wg-interface").value.trim(),
        client,
      },
    );

    appState.generatedClientName =
      result.client_name || client;

    appState.generatedClientConfig =
      result.client_config;

    prepareFinishStep({
      clientName: appState.generatedClientName,
      clientConfig: result.client_config,
    });

    select("#wireguard-config").textContent =
      result.client_config;

    select("#wireguard-download").href =
      `/api/ingress/wireguard/client/${encodeURIComponent(
        appState.generatedClientName,
      )}`;

    select("#wireguard-result").hidden = false;
    select("#wireguard-next").disabled = false;

    showMessage(
      "WireGuard-configuraties gegenereerd.",
    );

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
    showMessage(
  t(
    "messages.wireguard_config_copied",
    {},
    "WireGuard configuration copied.",
  ),
);
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
  loadDetectedEndpoint();
}
