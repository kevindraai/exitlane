export function createDashboardRefreshState() {
  let lastSuccessfulData = null;
  let error = null;
  return {
    succeed(data) {
      lastSuccessfulData = data;
      error = null;
    },
    fail(message) {
      error = message;
    },
    snapshot() {
      return { lastSuccessfulData, error };
    },
  };
}
