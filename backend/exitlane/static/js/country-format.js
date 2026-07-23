import { getCurrentLanguage } from "./i18n.js";

export function localisedCountryName(countryCode, fallback = "") {
  if (!countryCode || typeof Intl.DisplayNames !== "function") {
    return fallback || countryCode || "";
  }
  try {
    return new Intl.DisplayNames([getCurrentLanguage()], { type: "region" })
      .of(String(countryCode).toUpperCase()) || fallback || countryCode;
  } catch {
    return fallback || countryCode;
  }
}
