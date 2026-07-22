export async function runColdStart({
  refreshSession,
  setMode,
  startWizard,
  showLogin,
  startDashboard,
}) {
  const session = await refreshSession();

  if (!session.setup_complete) {
    setMode("wizard");
    await startWizard();
    return "wizard";
  }

  if (!session.authenticated) {
    setMode("login");
    showLogin();
    return "login";
  }

  setMode("dashboard");
  await startDashboard();
  return "dashboard";
}
