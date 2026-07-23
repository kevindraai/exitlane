export function providerManagementView(status = {}) {
  const management = status.management || {};
  const provider = management.provider || {};
  const capabilities = management.capabilities || {};
  let authenticationState = management.authentication?.state;
  if (!authenticationState) {
    authenticationState = status.authenticated === true
      ? "signed_in"
      : status.installed === true && status.authenticated === false
        ? "signed_out"
        : status.installed === false
          ? "unavailable"
          : "unknown";
  }
  return {
    providerId: provider.id || "nordvpn",
    installationState: provider.installation_state
      || (status.installed === false ? "not_installed" : status.installed === true ? "installed" : "unknown"),
    authenticationState,
    connectionState: management.connection?.state
      || (status.connected === true ? "connected" : status.connected === false ? "disconnected" : "unknown"),
    errorCode: management.error_code || status.error_code || null,
    canSignIn: capabilities.can_sign_in === true,
    canSignOut: capabilities.can_sign_out === true,
    canManageKillswitch: capabilities.can_manage_killswitch === true,
  };
}
