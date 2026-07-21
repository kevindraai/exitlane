export const appState = {
  session: null,
  setup: null,
  provider: null,
  diagnostics: null,
  visibleStep: 1,
  generatedClientName: null,
  generatedClientConfig: null
};

export const stepNames = {
  1: "system",
  2: "admin",
  3: "provider",
  4: "wireguard",
  5: "complete",
};
