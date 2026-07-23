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
    canConnect: capabilities.can_connect === true,
    canDisconnect: capabilities.can_disconnect === true,
    canSelectLocation: capabilities.can_select_location === true,
    canManageProviderKillswitch:
      capabilities.can_manage_provider_killswitch === true,
  };
}

export function vpnProviderAccess(status = {}) {
  const view = providerManagementView(status);
  const transient = new Set(["signing_in", "signing_out"]);
  let state = view.authenticationState;
  if (view.errorCode === "daemon_unavailable" || state === "unavailable") state = "unavailable";
  if (!["signed_in", "signed_out", "unavailable", "unknown", "signing_in", "signing_out"].includes(state)) {
    state = "unknown";
  }
  const inconsistent = state === "signed_out" && view.connectionState === "connected";
  return {
    ...view,
    state: inconsistent ? "unknown" : state,
    blocked: state !== "signed_in" || inconsistent,
    busy: transient.has(state),
  };
}
