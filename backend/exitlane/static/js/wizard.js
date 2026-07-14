import { api, postJson } from "./api.js";
import { appState, stepNames } from "./state.js";
import {
  clearInlineError,
  escapeHtml,
  select,
  selectAll,
  setBusy,
  showInlineError,
  showMessage,
} from "./ui.js";

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

export function showStep(stepNumber, { force = false } = {}) {
  const number = Number(stepNumber);

  if (!force && !canOpenStep(number)) {
    showMessage("Rond eerst de huidige stap af.", "error");
    return;
  }

  appState.visibleStep = number;

  selectAll(".wizard-step").forEach((element) => {
    element.hidden = element.id !== `step-${number}`;
  });

  selectAll("#wizard-steps button").forEach((button) => {
    button.classList.toggle(
      "active",
      Number(button.dataset.step) === number,
    );
  });

  select("#wizard-progress").textContent = `Stap ${number} van 5`;
  clearInlineError();
}

export function renderSetupState(setup) {
  appState.setup = setup;

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
    system: "Systeemcontrole",
    admin: "Lokale beheerder",
    provider: "VPN-provider",
    wireguard: "WireGuard-ingang",
  };

  select("#completion-checks").innerHTML = Object.entries(labels)
    .map(([key, label]) => {
      const complete = Boolean(setup.steps?.[key]);
      return `
        <div class="completion-check">
          <span>${escapeHtml(label)}</span>
          <span>${complete ? "Gereed" : "Niet gereed"}</span>
        </div>
      `;
    })
    .join("");

  select("#complete-button").disabled = !Object.values(
    setup.steps || {},
  ).every(Boolean);
}

export async function runDiagnostics() {
  const button = select("#diagnostics-button");
  setBusy(button, true, "Controleren…");
  clearInlineError();

  try {
    const result = await api("/api/diagnostics");
    appState.diagnostics = result;
    renderDiagnostics(result);
    await refreshSetup();

    if (result.ok) {
      showMessage("Alle systeemcontroles zijn geslaagd.");
    } else {
      showInlineError(
        "Niet alle systeemcontroles zijn geslaagd. Los de rode controles eerst op.",
      );
    }
  } catch (error) {
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
    showInlineError("De ingevoerde wachtwoorden komen niet overeen.");
    return;
  }

  setBusy(submitButton, true, "Aanmaken…");

  try {
    await postJson("/api/setup/admin", {
      username: select("#admin-username").value.trim(),
      password,
    });

    select("#admin-password").value = "";
    select("#admin-password-confirm").value = "";
    showMessage("Beheerder aangemaakt.");
    await refreshSetup();
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(submitButton, false);
  }
}

export async function completeSetup() {
  const button = select("#complete-button");
  setBusy(button, true, "Afronden…");
  clearInlineError();

  try {
    const result = await postJson("/api/setup/complete");
    showMessage(result.message || "Setup afgerond.");
    await refreshSetup();
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
}

export async function refreshSetup() {
  const setup = await api("/api/setup/state");
  renderSetupState(setup);
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
    status.textContent = "Herhaal het wachtwoord";
  } else if (matches) {
    status.textContent = "✓ Wachtwoorden komen overeen";
    status.classList.add("ok");
  } else {
    status.textContent = "✕ Wachtwoorden komen nog niet overeen";
    status.classList.add("error");
  }

  submitButton.disabled = !(passwordValid && matches);
}

export function initialiseWizardNavigation() {
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
}
