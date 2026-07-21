const STORAGE_KEY = "exitlane-language";

const SUPPORTED_LANGUAGES = new Set([
  "en",
  "nl",
]);

const FALLBACK_LANGUAGE = "en";

let currentLanguage = FALLBACK_LANGUAGE;
let messages = {};

function normaliseLanguage(value) {
  if (!value) {
    return null;
  }

  const language = value
    .toLowerCase()
    .split("-", 1)[0];

  return SUPPORTED_LANGUAGES.has(language)
    ? language
    : null;
}

function detectBrowserLanguage() {
  const candidates = [
    ...(navigator.languages || []),
    navigator.language,
  ];

  for (const candidate of candidates) {
    const language = normaliseLanguage(candidate);

    if (language) {
      return language;
    }
  }

  return FALLBACK_LANGUAGE;
}

function getStoredLanguage() {
  return normaliseLanguage(
    localStorage.getItem(STORAGE_KEY),
  );
}

function resolveLanguage() {
  return (
    getStoredLanguage() ||
    detectBrowserLanguage() ||
    FALLBACK_LANGUAGE
  );
}

function getNestedValue(object, key) {
  return key
    .split(".")
    .reduce(
      (value, part) =>
        value &&
        Object.prototype.hasOwnProperty.call(
          value,
          part,
        )
          ? value[part]
          : undefined,
      object,
    );
}

function interpolate(value, variables = {}) {
  return value.replace(
    /\{([A-Za-z0-9_]+)\}/g,
    (match, key) => {
      const replacement = variables[key];

      return replacement === undefined
        ? match
        : String(replacement);
    },
  );
}

async function loadMessages(language) {
  const response = await fetch(
    `/assets/locales/${language}.json`,
    {
      cache: "no-cache",
    },
  );

  if (!response.ok) {
    throw new Error(
      `Could not load language '${language}'.`,
    );
  }

  return response.json();
}

export function t(
  key,
  variables = {},
  fallback = key,
) {
  const value = getNestedValue(
    messages,
    key,
  );

  if (typeof value !== "string") {
    return fallback;
  }

  return interpolate(
    value,
    variables,
  );
}

function translateTextContent(root) {
  root
    .querySelectorAll("[data-i18n]")
    .forEach((element) => {
      const key = element.dataset.i18n;
      element.textContent = t(
        key,
        {},
        element.textContent.trim(),
      );
    });
}

function translateAttributes(root) {
  const attributes = [
    ["data-i18n-placeholder", "placeholder"],
    ["data-i18n-title", "title"],
    ["data-i18n-aria-label", "aria-label"],
  ];

  for (const [
    dataAttribute,
    htmlAttribute,
  ] of attributes) {
    root
      .querySelectorAll(
        `[${dataAttribute}]`,
      )
      .forEach((element) => {
        const key =
          element.getAttribute(
            dataAttribute,
          );

        const current =
          element.getAttribute(
            htmlAttribute,
          ) || "";

        element.setAttribute(
          htmlAttribute,
          t(key, {}, current),
        );
      });
  }
}

export function translateDocument(
  root = document,
) {
  translateTextContent(root);
  translateAttributes(root);

  document.documentElement.lang =
    currentLanguage;
}

function languageLabel(language) {
  const labels = {
    en: "English",
    nl: "Nederlands",
  };

  return labels[language] || labels.en;
}

function updateLanguageControls() {
  document
    .querySelectorAll("[data-language-select]")
    .forEach((select) => {
      select.value = currentLanguage;
    });

  document
    .querySelectorAll(
      "[data-language-value]",
    )
    .forEach((button) => {
      const active =
        button.dataset.languageValue ===
        currentLanguage;

      button.classList.toggle(
        "is-active",
        active,
      );

      button.setAttribute(
        "aria-checked",
        String(active),
      );
    });

const current = document.querySelector(
  "#language-current",
);

if (current) {
  current.textContent =
    languageLabel(currentLanguage);
} 
}

function setLanguageMenuOpen(open) {
  const trigger = document.querySelector(
    "#language-trigger",
  );
  const options = document.querySelector(
    "#language-options",
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

function toggleLanguageMenu() {
  const options = document.querySelector(
    "#language-options",
  );

  if (!options) {
    return;
  }

  setLanguageMenuOpen(options.hidden);
}

function closeLanguageMenu() {
  setLanguageMenuOpen(false);
}

export async function setLanguage(
  language,
  {
    persist = true,
    translate = true,
  } = {},
) {
  const normalised =
    normaliseLanguage(language) ||
    FALLBACK_LANGUAGE;

  let loadedLanguage = normalised;

  try {
    messages =
      await loadMessages(
        loadedLanguage,
      );
  } catch (error) {
    if (
      loadedLanguage ===
      FALLBACK_LANGUAGE
    ) {
      throw error;
    }

    loadedLanguage =
      FALLBACK_LANGUAGE;

    messages =
      await loadMessages(
        loadedLanguage,
      );
  }

  currentLanguage = loadedLanguage;

  if (persist) {
    localStorage.setItem(
      STORAGE_KEY,
      currentLanguage,
    );
  }

  updateLanguageControls();

  if (translate) {
    translateDocument();
  }

  window.dispatchEvent(
    new CustomEvent(
      "exitlane:languagechange",
      {
        detail: {
          language:
            currentLanguage,
        },
      },
    ),
  );

  return currentLanguage;
}

export function getCurrentLanguage() {
  return currentLanguage;
}

export async function initialiseI18n() {
  await setLanguage(
    resolveLanguage(),
    {
      persist: false,
      translate: true,
    },
  );

  const trigger = document.querySelector(
    "#language-trigger",
  );

  if (trigger) {
    trigger.addEventListener(
      "click",
      toggleLanguageMenu,
    );
  }

  document
    .querySelectorAll("[data-language-select]")
    .forEach((select) => {
      select.addEventListener("change", async () => {
        await setLanguage(select.value);
      });
    });

  document
    .querySelectorAll(
      "[data-language-value]",
    )
    .forEach((button) => {
      button.addEventListener(
        "click",
        async () => {
          await setLanguage(
            button.dataset.languageValue,
          );

          closeLanguageMenu();
        },
      );
    });

  document.addEventListener(
    "click",
    (event) => {
      const menu = document.querySelector(
        ".language-menu",
      );

      if (
        menu &&
        !menu.contains(event.target)
      ) {
        closeLanguageMenu();
      }
    },
  );

  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key !== "Escape") {
        return;
      }

      closeLanguageMenu();

      if (trigger) {
        trigger.focus();
      }
    },
  );

  return currentLanguage;
}
