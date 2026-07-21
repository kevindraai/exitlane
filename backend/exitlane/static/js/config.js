import { api } from "./api.js";
import { select } from "./ui.js";
import { t } from "./i18n.js";

export const frontendConfig = {
  password: {
    minimumLength: 8,
    maximumLength: 256,
  },
  wireguard: {
    defaultInterface: "wg0",
    defaultSubnet: "10.99.99.0/24",
    defaultPort: 51820,
    defaultClient: "router",
  },
  providerRefreshIntervalSeconds: 5,
};

export async function loadPublicConfig() {
  const response = await api("/api/config/public");

  frontendConfig.password.minimumLength =
    response.password.minimum_length;
  frontendConfig.password.maximumLength =
    response.password.maximum_length;

  frontendConfig.wireguard.defaultInterface =
    response.wireguard.default_interface;
  frontendConfig.wireguard.defaultSubnet =
    response.wireguard.default_subnet;
  frontendConfig.wireguard.defaultPort =
    response.wireguard.default_port;
  frontendConfig.wireguard.defaultClient =
    response.wireguard.default_client;

  frontendConfig.providerRefreshIntervalSeconds =
    response.frontend.provider_refresh_interval_seconds;

  applyPublicConfig();
  return frontendConfig;
}
function renderPasswordRequirement() {
  select("#password-requirement").textContent = t(
    "password.minimum_length",
    {
      length: frontendConfig.password.minimumLength,
    },
    `Minimum ${frontendConfig.password.minimumLength} characters.`,
  );
}
function applyPublicConfig() {
  const password = select("#admin-password");
  const confirmation = select("#admin-password-confirm");

  password.minLength = frontendConfig.password.minimumLength;
  password.maxLength = frontendConfig.password.maximumLength;

  confirmation.minLength = frontendConfig.password.minimumLength;
  confirmation.maxLength = frontendConfig.password.maximumLength;

  renderPasswordRequirement();

  select("#wg-subnet").value =
    frontendConfig.wireguard.defaultSubnet;
  select("#wg-port").value =
    frontendConfig.wireguard.defaultPort;
  select("#wg-interface").value =
    frontendConfig.wireguard.defaultInterface;
  select("#wg-client").value =
    frontendConfig.wireguard.defaultClient;
  window.addEventListener(
  "exitlane:languagechange",
  renderPasswordRequirement,
);
}
