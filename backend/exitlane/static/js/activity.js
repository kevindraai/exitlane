import { api } from "./api.js";
import { t } from "./i18n.js";
import { getSlice, subscribe, updateSlice } from "./state.js";
import { eventTranslation, mergeEventPages, normaliseFilters, safeDetails } from "./activity-format.js";

let initialised = false;
let inFlight = null;

function queryString({ cursor = null } = {}) {
  const { filters } = getSlice("activity");
  const params = new URLSearchParams({ limit: "50" });
  if (filters.category) params.set("category", filters.category);
  if (filters.level) params.set("level", filters.level);
  if (cursor) params.set("cursor", String(cursor));
  return params.toString();
}

export function refreshActivity({ signal, loadMore = false } = {}) {
  if (inFlight) return inFlight;
  const current = getSlice("activity");
  updateSlice("activity", { loading: current.data.length === 0, stale: current.data.length > 0, error: null });
  inFlight = api(`/api/events?${queryString({ cursor: loadMore ? current.nextCursor : null })}`, { signal })
    .then((page) => {
      updateSlice("activity", {
        data: loadMore ? mergeEventPages(current.data, page.items) : mergeEventPages([], page.items),
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        loading: false,
        stale: false,
        error: null,
        updatedAt: Date.now(),
      });
      return page;
    })
    .catch((error) => {
      if (error.code !== "aborted") updateSlice("activity", { loading: false, stale: current.data.length > 0, error: error.code || "request_failed" });
      throw error;
    })
    .finally(() => { inFlight = null; });
  return inFlight;
}

function renderEvent(event) {
  const item = document.createElement("li");
  item.className = `activity-event activity-${event.level}`;
  const heading = document.createElement("div");
  heading.className = "activity-event-heading";
  const label = document.createElement("strong");
  const translated = eventTranslation(event);
  label.textContent = t(translated.key, translated.variables, translated.fallback);
  const pill = document.createElement("span");
  pill.className = `status-pill status-${event.level === "error" ? "danger" : "neutral"}`;
  pill.textContent = t(`activity.level.${event.level}`, {}, event.level);
  heading.append(label, pill);
  const meta = document.createElement("p");
  meta.className = "activity-event-meta";
  const time = new Date(event.created_at).toLocaleString();
  meta.textContent = [time, t(`activity.category.${event.category}`, {}, event.category), event.actor?.username].filter(Boolean).join(" · ");
  item.append(heading, meta);
  const details = safeDetails(event);
  if (details.length) {
    const disclosure = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = t("activity.details", {}, "Details");
    const list = document.createElement("dl");
    for (const [key, value] of details) {
      const term = document.createElement("dt"); term.textContent = t(`activity.metadata.${key}`, {}, key);
      const description = document.createElement("dd"); description.textContent = value;
      list.append(term, description);
    }
    disclosure.append(summary, list); item.append(disclosure);
  }
  return item;
}

export function renderActivity(slice = getSlice("activity")) {
  const list = document.querySelector("#activity-list");
  if (!list) return;
  document.querySelector("#activity-category").value = slice.filters.category;
  document.querySelector("#activity-level").value = slice.filters.level;
  list.replaceChildren(...slice.data.map(renderEvent));
  document.querySelector("#activity-loading").hidden = !(slice.loading && !slice.data.length);
  document.querySelector("#activity-empty").hidden = Boolean(slice.loading || slice.data.length || slice.error);
  document.querySelector("#activity-error").hidden = !slice.error;
  document.querySelector("#activity-updating").hidden = !slice.stale;
  document.querySelector("#activity-load-more").hidden = !slice.hasMore;
  document.querySelector("#activity-load-more").disabled = slice.loading;
  document.querySelector("#activity-updated").textContent = slice.updatedAt ? new Date(slice.updatedAt).toLocaleString() : "—";
}

export function initialiseActivity() {
  if (initialised) return;
  initialised = true;
  subscribe("activity", renderActivity, { immediate: true });
  document.querySelector("#activity-refresh").addEventListener("click", () => refreshActivity().catch(() => {}));
  document.querySelector("#activity-load-more").addEventListener("click", () => refreshActivity({ loadMore: true }).catch(() => {}));
  for (const id of ["activity-category", "activity-level"]) document.querySelector(`#${id}`).addEventListener("change", () => {
    const filters = normaliseFilters({ category: document.querySelector("#activity-category").value, level: document.querySelector("#activity-level").value });
    updateSlice("activity", { filters, nextCursor: null, hasMore: false });
    refreshActivity().catch(() => {});
  });
  document.querySelector("#activity-reset").addEventListener("click", () => {
    document.querySelector("#activity-category").value = ""; document.querySelector("#activity-level").value = "";
    updateSlice("activity", { filters: { category: "", level: "" }, nextCursor: null, hasMore: false });
    refreshActivity().catch(() => {});
  });
  window.addEventListener("exitlane:languagechange", () => renderActivity());
}
