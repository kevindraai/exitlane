export function passwordRequirementState({
  currentPassword,
  newPassword,
  confirmation,
  minimumLength,
}) {
  const touched = Boolean(currentPassword || newPassword || confirmation);
  return {
    minimum: newPassword ? newPassword.length >= minimumLength : null,
    different: currentPassword && newPassword ? currentPassword !== newPassword : null,
    matches: confirmation ? newPassword === confirmation : null,
    complete: Boolean(
      currentPassword
      && newPassword.length >= minimumLength
      && confirmation
      && newPassword === confirmation
      && currentPassword !== newPassword
    ),
    touched,
  };
}

export function passwordErrorTarget(code) {
  const targets = {
    invalid_credentials: "#settings-current-password-error",
    password_mismatch: "#settings-confirm-password-error",
    password_unchanged: "#settings-new-password-error",
    password_policy: "#settings-new-password-error",
  };
  return targets[code] || "#settings-password-status";
}
