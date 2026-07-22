export function normaliseFilters(filters = {}) {
  const categories = new Set(["auth", "setup", "provider", "wireguard", "settings", "notifications", "system"]);
  const levels = new Set(["info", "warning", "error"]);
  return {
    category: categories.has(filters.category) ? filters.category : "",
    level: levels.has(filters.level) ? filters.level : "",
  };
}

export function mergeEventPages(current = [], incoming = []) {
  const events = new Map();
  for (const event of [...current, ...incoming]) {
    if (event && Number.isInteger(event.id)) events.set(event.id, event);
  }
  return [...events.values()].sort((a, b) => b.id - a.id);
}

export function eventTranslation(event = {}) {
  const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
  const variables = {
    ...metadata,
    fields: Array.isArray(metadata.fields) ? metadata.fields.join(", ") : "",
  };
  return { key: `events.${event.code || "unknown"}`, variables, fallback: event.code || "Unknown event" };
}

export function safeDetails(event = {}) {
  const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
  return Object.entries(metadata)
    .filter(([, value]) => typeof value === "string" || Array.isArray(value))
    .slice(0, 20)
    .map(([key, value]) => [key, Array.isArray(value) ? value.join(", ") : String(value).slice(0, 160)]);
}
