import { api, postJson } from "./api.js";
import { showLogin } from "./auth.js";
import { t } from "./i18n.js";
import { refreshProviderState } from "./lifecycle.js";
import { setApplicationMode } from "./navigation.js";
import { renderProviderLogo } from "./provider-logo.js";
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
let renderedWizardProviderId = null;
let providerSelectionInFlight = false;

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
  renderWizardProviders(setup);

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
  const providerDeferred = Boolean(setup.provider_deferred);
  select("#provider-defer-choice").hidden = providerDeferred
    || Boolean(setup.provider_authenticated);
  select("#provider-deferred-status").hidden = !providerDeferred;

  renderCompletionChecks(setup);

  const requestedStep = setup.complete
    ? 5
    : Number(setup.current_step || 1);

  showStep(requestedStep, { force: true });
}

async function saveProviderSelection(providerIds) {
  if (providerSelectionInFlight) return;
  providerSelectionInFlight = true;
  const container = select("#wizard-provider-choices");
  container.setAttribute("aria-busy", "true");
  container.querySelectorAll("button").forEach((button) => {
    button.disabled = true;
  });
  clearInlineError();
  try {
    await postJson("/api/setup/providers", { provider_ids: providerIds });
    await refreshSetup();
  } catch (error) {
    showInlineError(error.message);
  } finally {
    providerSelectionInFlight = false;
    container.removeAttribute("aria-busy");
    container.querySelectorAll("button").forEach((button) => {
      button.disabled = false;
    });
  }
}

async function activateSetupProvider(providerId, button) {
  setBusy(button, true, t("step3.activating_provider", {}, "Activating…"));
  clearInlineError();
  try {
    await postJson(`/api/vpn/providers/${encodeURIComponent(providerId)}/activate`);
    await refreshSetup();
  } catch (error) {
    showInlineError(t(
      `provider.errors.${error.payload?.detail || error.code}`,
      {},
      t("provider.errors.provider_switch_failed", {}, "The active provider could not be changed."),
    ));
  } finally {
    setBusy(button, false);
  }
}

export function renderWizardProviders(setup) {
  const providers = setup.providers || [];
  const selectedIds = setup.selected_provider_ids || [];
  const selectedId = selectedIds.length ? setup.selected_provider_id : null;
  const container = select("#wizard-provider-choices");
  container.replaceChildren();
  for (const provider of providers) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "provider-choice";
    item.dataset.providerId = provider.id;
    const selected = selectedIds.includes(provider.id);
    item.classList.toggle("provider-choice--selected", selected);
    item.setAttribute("role", "checkbox");
    item.setAttribute("aria-checked", String(selected));
    item.setAttribute("aria-pressed", String(selected));
    const status = provider.status?.authenticated
      ? t("vpn.overview.states.signed_in", {}, "Signed in")
      : provider.status?.installed
        ? t("vpn.overview.states.signed_out", {}, "Signed out")
        : t("provider.status.not_installed", {}, "Not installed");
    item.textContent = `${selected ? "✓ " : ""}${provider.display_name} · ${status}`;
    item.addEventListener("click", () => {
      const next = selected
        ? selectedIds.filter((id) => id !== provider.id)
        : [...selectedIds, provider.id];
      void saveProviderSelection(next);
    });
    container.append(item);
  }
  const selected = providers.find((provider) => provider.id === selectedId);
  select("#wizard-provider-configuration").hidden = !selected;
  if (selected) {
    select("#wizard-provider-name").textContent = selected.display_name;
    selectAll("[data-provider-logo]").forEach((container) => {
      renderProviderLogo(container, selected);
    });
    const pending = (setup.pending_provider_ids || []).includes(selected.id);
    select("#provider-skip").hidden = !pending;
    select("#provider-skip").textContent = t(
      "step3.skip_provider",
      { provider: selected.display_name },
      `Skip ${selected.display_name}`,
    );
  }

  if (selectedId !== renderedWizardProviderId) {
    renderedWizardProviderId = selectedId;
    updateSlice("application", { providerId: selectedId });
    window.dispatchEvent(new CustomEvent("exitlane:wizardproviderchange", {
      detail: { providerId: selectedId },
    }));
    if (selectedId) refreshProviderState({ deduplicate: false }).catch(() => {});
  }

  const activeSelection = select("#wizard-active-provider-selection");
  activeSelection.hidden = !setup.active_provider_selection_required;
  const activeChoices = select("#wizard-active-provider-choices");
  activeChoices.replaceChildren();
  if (setup.active_provider_selection_required) {
    for (const provider of providers.filter((item) => (
      selectedIds.includes(item.id) && item.status?.authenticated
    ))) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "button button-primary";
      button.textContent = t(
        "step3.make_provider_active",
        { provider: provider.display_name },
        `Use ${provider.display_name}`,
      );
      button.addEventListener("click", () => activateSetupProvider(provider.id, button));
      activeChoices.append(button);
    }
  }
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

        const status = key === "provider" && setup.provider_deferred
          ? t(
              "completion.deferred",
              {},
              "Deferred",
            )
          : complete
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

export async function deferProviderSetup() {
  const button = select("#provider-defer");
  setBusy(
    button,
    true,
    t("step3.deferring", {}, "Saving choice…"),
  );
  clearInlineError();
  try {
    await postJson("/api/setup/provider/defer");
    await refreshSetup();
    showMessage(
      t(
        "step3.deferred_message",
        {},
        "Provider setup deferred. You can configure one later from VPN management.",
      ),
    );
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

export async function skipCurrentProvider() {
  const providerId = appState.setup?.selected_provider_id;
  if (!providerId) return;
  const button = select("#provider-skip");
  setBusy(button, true, t("step3.skipping_provider", {}, "Skipping…"));
  clearInlineError();
  try {
    await postJson(`/api/setup/providers/${encodeURIComponent(providerId)}/skip`);
    await refreshSetup();
  } catch (error) {
    showInlineError(error.message);
  } finally {
    setBusy(button, false);
  }
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
  select("#provider-defer").addEventListener("click", deferProviderSetup);
  select("#provider-skip").addEventListener("click", skipCurrentProvider);
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
