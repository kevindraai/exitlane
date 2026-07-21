import {
  select,
  selectAll,
} from "./ui.js";

const STORAGE_KEY =
  "exitlane-active-view";

const DEFAULT_VIEW =
  "dashboard";

const APPLICATION_MODES = new Set([
  "wizard",
  "login",
  "dashboard",
]);

export function setApplicationMode(mode) {
  if (!APPLICATION_MODES.has(mode)) {
    throw new Error(
      `Unknown application mode: ${mode}`,
    );
  }

  const shell = select(".app-shell");

  select("#wizard-panel").hidden =
    mode !== "wizard";
  select("#login-panel").hidden =
    mode !== "login";
  select("#dashboard-panel").hidden =
    mode !== "dashboard";
  select("#sidebar").hidden =
    mode !== "dashboard";

  shell.dataset.applicationMode = mode;
  shell.classList.toggle(
    "has-sidebar",
    mode === "dashboard",
  );
}

function viewExists(name) {
  return Boolean(
    document.querySelector(
      `[data-view-panel="${name}"]`,
    ),
  );
}

export function showView(
  name,
  {
    persist = true,
  } = {},
) {
  const requestedView = viewExists(name)
    ? name
    : DEFAULT_VIEW;

  selectAll("[data-view-panel]")
    .forEach((panel) => {
      panel.hidden =
        panel.dataset.viewPanel !==
        requestedView;
    });

  selectAll("[data-view]")
    .forEach((button) => {
      const active =
        button.dataset.view ===
        requestedView;

      button.classList.toggle(
        "active",
        active,
      );

      if (active) {
        button.setAttribute(
          "aria-current",
          "page",
        );
      } else {
        button.removeAttribute(
          "aria-current",
        );
      }
    });

  if (persist) {
    localStorage.setItem(
      STORAGE_KEY,
      requestedView,
    );
  }
}

export function initialiseNavigation() {
  document
    .querySelectorAll("[data-view]")
    .forEach((button) => {
      button.disabled = false;

      button.addEventListener(
        "click",
        () => {
          showView(
            button.dataset.view,
          );
        },
      );
    });

  document
    .querySelectorAll("[data-open-view]")
    .forEach((button) => {
      button.addEventListener(
        "click",
        () => {
          showView(
            button.dataset.openView,
          );
        },
      );
    });

  const storedView =
    localStorage.getItem(
      STORAGE_KEY,
    );

  showView(
    storedView || DEFAULT_VIEW,
    {
      persist: false,
    },
  );
}
