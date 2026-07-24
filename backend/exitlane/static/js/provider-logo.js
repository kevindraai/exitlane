const LOCAL_PROVIDER_LOGO = /^\/assets\/providers\/[a-z0-9_-]+\.svg$/;

export function providerLogoView(provider = {}) {
  const displayName =
    typeof provider.display_name === "string" ? provider.display_name.trim() : "";
  const logo = typeof provider.logo === "string" ? provider.logo.trim() : "";

  return {
    src: LOCAL_PROVIDER_LOGO.test(logo) ? logo : null,
    fallbackText: displayName.slice(0, 1).toUpperCase() || "•",
  };
}

function showFallback(container, fallbackText) {
  const fallback = document.createElement("span");
  fallback.className = "provider-logo__fallback";
  fallback.setAttribute("aria-hidden", "true");
  fallback.textContent = fallbackText;
  container.replaceChildren(fallback);
}

export function renderProviderLogo(container, provider) {
  if (!container) return;

  const view = providerLogoView(provider);
  container.classList.add("provider-logo");
  container.setAttribute("aria-hidden", "true");

  if (!view.src) {
    showFallback(container, view.fallbackText);
    return;
  }

  const image = document.createElement("img");
  image.className = "provider-logo__image";
  image.src = view.src;
  image.alt = "";
  image.setAttribute("aria-hidden", "true");
  image.addEventListener(
    "error",
    () => showFallback(container, view.fallbackText),
    { once: true },
  );
  container.replaceChildren(image);
}
