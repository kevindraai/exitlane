export const MFA_STATES = Object.freeze({
  DISABLED: "disabled",
  ENROLLMENT_PENDING: "enrollment_pending",
  ENABLED: "enabled",
  RECOVERY_CODES_REVEALED: "recovery_codes_revealed",
});

export function createMfaState() {
  return {
    mode: MFA_STATES.DISABLED,
    pendingEnrollment: null,
    setupKey: null,
    qrSvg: null,
    recoveryCodes: [],
  };
}

export function clearMfaSecrets(state, mode = MFA_STATES.DISABLED) {
  state.mode = mode;
  state.pendingEnrollment = null;
  state.setupKey = null;
  state.qrSvg = null;
  state.recoveryCodes.splice(0);
  return state;
}

export function reconcileMfaState(state, backendMfa) {
  if (!backendMfa?.enabled) return clearMfaSecrets(state, MFA_STATES.DISABLED);
  if (state.mode !== MFA_STATES.RECOVERY_CODES_REVEALED) {
    clearMfaSecrets(state, MFA_STATES.ENABLED);
  }
  return state;
}

export function beginEnrollmentState(state, enrollment) {
  clearMfaSecrets(state, MFA_STATES.ENROLLMENT_PENDING);
  state.pendingEnrollment = enrollment.enrollment;
  state.setupKey = enrollment.setup_key;
  state.qrSvg = enrollment.qr_svg;
  return state;
}

export function revealRecoveryCodes(state, codes) {
  clearMfaSecrets(state, MFA_STATES.RECOVERY_CODES_REVEALED);
  state.recoveryCodes.push(...codes);
  return state;
}

export function mfaVisibility(mode) {
  return {
    disabled: mode === MFA_STATES.DISABLED,
    enrollment: mode === MFA_STATES.ENROLLMENT_PENDING,
    enabled: mode === MFA_STATES.ENABLED || mode === MFA_STATES.RECOVERY_CODES_REVEALED,
    recovery: mode === MFA_STATES.RECOVERY_CODES_REVEALED,
  };
}
