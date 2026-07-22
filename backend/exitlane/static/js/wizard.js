import { api, postJson } from "./api.js";
import { showLogin } from "./auth.js";
import { t } from "./i18n.js";
import { setApplicationMode } from "./navigation.js";
import { appState, getSlice, stepNames, updateSlice } from "./state.js";
import {
  clearInlineError,
  escapeHtml,
  select,
  selectAll,
  setBusy,
  showInlineError,
  showMessage,
} from "./ui.js";

let navigationInitialised = false;

function isStepComplete(stepNumber, setup = appState.setup) {
  if (!setup) {
    return false;
  }

  if (stepNumber === 5) {
    return Boolean(setup.complete);
  }

  return Boolean(setup.steps?.[stepNames[stepNumber]]);
}

function canOpenStep(stepNumber) {
  const setup = appState.setup;
  if (!setup) {
    return stepNumber === 1;
  }

  return (
    stepNumber <= Number(setup.current_step || 1) ||
    isStepComplete(stepNumber)
  );
}
function renderWizardProgress() {
  select("#wizard-progress").textContent = t(
    "wizard.progress",
    {
      current: appState.visibleStep,
      total: 5,
    },
    `Step ${appState.visibleStep} of 5`,
  );
}
export function showStep(stepNumber, { force = false } = {}) {
  const number = Number(stepNumber);

  if (!force && !canOpenStep(number)) {
    showMessage(
  t(
    "wizard.complete_current_first",
    {},
    "Complete the current step first.",
  ),
  "error",
);
    return;
  }

  appState.visibleStep = number;
  updateSlice("application", { wizardStep: number });

  selectAll(".wizard-step").forEach((element) => {
    element.hidden = element.id !== `step-${number}`;
  });

  selectAll("#wizard-steps button").forEach((button) => {
    button.classList.toggle(
      "active",
      Number(button.dataset.step) === number,
    );
  });

  renderWizardProgress();
  clearInlineError();
}
function updateApplicationMode(setup) {
  const complete = Boolean(setup.complete);
  setApplicationMode(
    complete
      ? getSlice("auth").data?.authenticated
        ? "dashboard"
        : "login"
      : "wizard",
  );
}
export function renderSetupState(setup) {
  appState.setup = setup;
  updateApplicationMode(setup);

  selectAll("#wizard-steps button").forEach((button) => {
    const number = Number(button.dataset.step);
    const completed = isStepComplete(number, setup);

    button.classList.toggle("completed", completed);
    button.disabled =
      !completed &&
      number > Number(setup.current_step || 1);

    const numberElement = button.querySelector(".step-number");
    numberElement.textContent = completed ? "✓" : String(number);
  });

  select("#system-next").disabled = !setup.steps.system;
  select("#provider-next").disabled = !setup.steps.provider;
  select("#wireguard-next").disabled = !setup.steps.wireguard;

  renderCompletionChecks(setup);

  const requestedStep = setup.complete
    ? 5
    : Number(setup.current_step || 1);

  showStep(requestedStep, { force: true });
}

function renderCompletionChecks(setup) {
  const labels = {
    system: t(
      "completion.system",
      {},
      "System check",
    ),
    admin: t(
      "completion.admin",
      {},
      "Local administrator",
    ),
    provider: t(
      "completion.provider",
      {},
      "VPN provider",
    ),
    wireguard: t(
      "completion.wireguard",
      {},
      "WireGuard ingress",
    ),
  };

  select("#completion-checks").innerHTML =
    Object.entries(labels)
      .map(([key, label]) => {
        const complete = Boolean(
          setup.steps?.[key],
        );

        const status = complete
          ? t(
              "completion.ready",
              {},
              "Ready",
            )
          : t(
              "completion.not_ready",
              {},
              "Not ready",
            );

        return `
          <div class="completion-check">
            <span>${escapeHtml(label)}</span>
            <span>${escapeHtml(status)}</span>
          </div>
        `;
      })
      .join("");

  select("#complete-button").disabled =
    !Object.values(
      setup.steps || {},
    ).every(Boolean);
}

export async function runDiagnostics(
  { automatic = false } = {},
) {
  const button = select("#diagnostics-button");

  setBusy(
    button,
    true,
    automatic
  ? t(
      "busy.checking_automatic",
      {},
      "Checking automatically…",
    )
  : t(
      "busy.checking",
      {},
      "Checking…",
    ),
  );

  clearInlineError();

  try {
    const result = await api("/api/diagnostics");
    appState.diagnostics = result;

    renderDiagnostics(result);

    const setup = await api("/api/setup/state");
    renderSetupState(setup);

    if (result.ok) {
      if (!automatic) {
        showMessage(
  t(
    "messages.system_checks_passed",
    {},
    "All system checks passed.",
  ),
);
      }
    } else {
      showStep(1, { force: true });

      showInlineError(
  t(
    "messages.system_check_failed",
    {},
    "Exitlane found a problem during the system check.",
  ),
);
    }
  } catch (error) {
    showStep(1, { force: true });
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

function renderDiagnostics(result) {
  const checks = result.checks || [];
  const passed = checks.filter((check) => check.ok).length;
  const percentage = checks.length
    ? Math.round((passed / checks.length) * 100)
    : 0;

  select("#diagnostics-summary").hidden = false;
  select("#diagnostics-score").textContent = `${passed} / ${checks.length}`;
  select("#diagnostics-progress").style.width = `${percentage}%`;

  select("#diagnostics-list").innerHTML = checks
    .map(
      (check) => `
        <div class="check-item">
          <div>
            <strong>${escapeHtml(check.name)}</strong>
            <small>${escapeHtml(check.detail ?? "")}</small>
          </div>
          <span class="check-result ${check.ok ? "pass" : "fail"}">
            ${check.ok ? "PASS" : "FAIL"}
          </span>
        </div>
      `,
    )
    .join("");
}

export async function createAdmin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submitButton = form.querySelector('button[type="submit"]');
  const password = select("#admin-password").value;
  const confirmation = select("#admin-password-confirm").value;

  clearInlineError();

  if (password !== confirmation) {
    showInlineError(
  t(
    "messages.passwords_do_not_match",
    {},
    "The entered passwords do not match.",
  ),
);
    return;
  }

  setBusy(
  submitButton,
  true,
  t(
    "busy.creating",
    {},
    "Creating…",
  ),
);

  try {
    await postJson("/api/setup/admin", {
      username: select("#admin-username").value.trim(),
      password,
    });

    select("#admin-password").value = "";
    select("#admin-password-confirm").value = "";
    showMessage(
  t(
    "messages.admin_created",
    {},
    "Administrator created.",
  ),
);
    await refreshSetup();
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    showInlineError(error.message);
  } finally {
    setBusy(submitButton, false);
  }
}

export async function completeSetup() {
  const button = select("#complete-button");

  setBusy(
  button,
  true,
  t(
    "busy.finishing",
    {},
    "Finishing…",
  ),
);
  clearInlineError();

  try {
    const result = await postJson(
      "/api/setup/complete",
    );

    showMessage(
  result.message ||
    t(
      "messages.setup_completed",
      {},
      "Setup completed.",
    ),
);

    await refreshSetup();
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

export async function refreshSetup({
  runAutomaticDiagnostics = false,
} = {}) {
  const setup = await api("/api/setup/state");
  renderSetupState(setup);

  if (
    runAutomaticDiagnostics &&
    !setup.steps.system
  ) {
    showStep(1, { force: true });
    await runDiagnostics({
      automatic: true,
    });
  }

  return setup;
}

function updatePasswordMatchState() {
  const password = select("#admin-password");
  const confirmation = select("#admin-password-confirm");
  const status = select("#password-match");
  const submitButton = select(
    '#admin-form button[type="submit"]',
  );

  const minimumLength = Number(password.minLength || 8);
  const passwordValid =
    password.value.length >= minimumLength;
  const matches =
    confirmation.value.length > 0 &&
    password.value === confirmation.value;

  status.classList.remove("ok", "error");

  if (!confirmation.value) {
  status.textContent = t(
    "password.repeat",
    {},
    "Repeat the password",
  );
} else if (matches) {
  status.textContent = t(
    "password.matches",
    {},
    "✓ Passwords match",
  );

  status.classList.add("ok");
} else {
  status.textContent = t(
    "password.no_match",
    {},
    "✕ Passwords do not match yet",
  );

  status.classList.add("error");
}

  submitButton.disabled = !(passwordValid && matches);
}

export function initialiseWizardNavigation() {
  if (navigationInitialised) return;
  navigationInitialised = true;
  selectAll("#wizard-steps button").forEach((button) => {
    button.addEventListener("click", () => {
      showStep(Number(button.dataset.step));
    });
  });

  selectAll("[data-back]").forEach((button) => {
    button.addEventListener("click", () => {
      showStep(Number(button.dataset.back), { force: true });
    });
  });

  select("#system-next").addEventListener("click", () => showStep(2));
  select("#provider-next").addEventListener("click", () => showStep(4));
  select("#wireguard-next").addEventListener("click", () => showStep(5));
  select("#diagnostics-button").addEventListener("click", runDiagnostics);
  select("#admin-form").addEventListener("submit", createAdmin);
  select("#complete-button").addEventListener("click", completeSetup);

  const password = select("#admin-password");
  const confirmation = select("#admin-password-confirm");

  password.addEventListener("input", updatePasswordMatchState);
  confirmation.addEventListener("input", updatePasswordMatchState);

  updatePasswordMatchState();
  renderWizardProgress();

window.addEventListener(
  "exitlane:languagechange",
  () => {
    renderWizardProgress();
    updatePasswordMatchState();

    if (appState.setup) {
      renderCompletionChecks(
        appState.setup,
      );
    }
  },
);
}
