import { t } from "./i18n.js";

const STORAGE_KEY = "exitlane-color-scheme";

const VALID_PREFERENCES = new Set([
  "system",
  "light",
  "dark",
]);

const systemScheme = window.matchMedia(
  "(prefers-color-scheme: dark)",
);

function resolveColorScheme(preference) {
  if (preference === "system") {
    return systemScheme.matches
      ? "dark"
      : "light";
  }

  return preference;
}

export function getColorSchemePreference() {
  const stored = localStorage.getItem(
    STORAGE_KEY,
  );

  return VALID_PREFERENCES.has(stored)
    ? stored
    : "system";
}

function preferenceLabel(preference) {
  const keys = {
    system: "theme.system",
    light: "theme.light",
    dark: "theme.dark",
  };
  return t(keys[preference] || keys.system, {}, preference);
}

function updateControls(preference) {
  document
    .querySelectorAll("[data-color-scheme-select]")
    .forEach((select) => {
      select.value = preference;
    });

  const current = document.querySelector(
    "#color-scheme-current",
  );

  if (current) {
    current.textContent =
      preferenceLabel(preference);
  }

  document
    .querySelectorAll(
      "[data-color-scheme-value]",
    )
    .forEach((button) => {
      const active =
        button.dataset.colorSchemeValue ===
        preference;

      button.classList.toggle(
        "is-active",
        active,
      );

      button.setAttribute(
        "aria-checked",
        String(active),
      );
    });
}

function setMenuOpen(open) {
  const trigger = document.querySelector(
    "#color-scheme-trigger",
  );
  const options = document.querySelector(
    "#color-scheme-options",
  );

  if (!trigger || !options) {
    return;
  }

  options.hidden = !open;

  trigger.setAttribute(
    "aria-expanded",
    String(open),
  );
}

function toggleMenu() {
  const options = document.querySelector(
    "#color-scheme-options",
  );

  if (options) {
    setMenuOpen(options.hidden);
  }
}

function closeMenu() {
  setMenuOpen(false);
}

export function applyColorScheme(preference) {
  const resolved =
    resolveColorScheme(preference);

  document.documentElement.dataset.colorScheme =
    resolved;

  document.documentElement.dataset.colorSchemePreference =
    preference;

  updateControls(preference);
}

export function setColorScheme(preference) {
  if (!VALID_PREFERENCES.has(preference)) {
    return;
  }

  localStorage.setItem(
    STORAGE_KEY,
    preference,
  );

  applyColorScheme(preference);
}

function handleSystemSchemeChange() {
  const preference =
    getColorSchemePreference();

  if (preference === "system") {
    applyColorScheme(preference);
  }
}

export function initialiseColorScheme() {
  const preference =
    getColorSchemePreference();

  applyColorScheme(preference);

  const trigger = document.querySelector(
    "#color-scheme-trigger",
  );

  if (trigger) {
    trigger.addEventListener(
      "click",
      toggleMenu,
    );
  }

  document
    .querySelectorAll("[data-color-scheme-select]")
    .forEach((select) => {
      select.addEventListener("change", () => {
        setColorScheme(select.value);
      });
    });

  document
    .querySelectorAll(
      "[data-color-scheme-value]",
    )
    .forEach((button) => {
      button.addEventListener(
        "click",
        () => {
          setColorScheme(
            button.dataset.colorSchemeValue,
          );

          closeMenu();
        },
      );
    });

  document.addEventListener(
    "click",
    (event) => {
      const menu = document.querySelector(
        ".color-scheme-menu",
      );

      if (menu && !menu.contains(event.target)) {
        closeMenu();
      }
    },
  );

  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Escape") {
        closeMenu();
        if (trigger) {
          trigger.focus();
        }
      }
    },
  );

  systemScheme.addEventListener(
    "change",
    handleSystemSchemeChange,
  );
}
