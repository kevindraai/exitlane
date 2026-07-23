// Selected from Lucide Icons 1.26.0 (ISC; Feather-derived icons MIT).
const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
const FALLBACK_ICON = "shield-check";

const ICONS = Object.freeze({
  "archive-restore": [["rect", { width: "20", height: "5", x: "2", y: "3", rx: "1" }], ["path", { d: "M4 8v11a2 2 0 0 0 2 2h2" }], ["path", { d: "M20 8v5" }], ["path", { d: "M10 12h2" }], ["path", { d: "m9 17 3-3 3 3" }], ["path", { d: "M12 14v7" }]],
  bell: [["path", { d: "M10.268 21a2 2 0 0 0 3.464 0" }], ["path", { d: "M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326" }]],
  "chart-no-axes-column": [["path", { d: "M5 21v-6" }], ["path", { d: "M12 21V3" }], ["path", { d: "M19 21V9" }]],
  "chevron-down": [["path", { d: "m6 9 6 6 6-6" }]],
  "chevron-right": [["path", { d: "m9 18 6-6-6-6" }]],
  circle: [["circle", { cx: "12", cy: "12", r: "10" }]],
  "circle-alert": [["circle", { cx: "12", cy: "12", r: "10" }], ["line", { x1: "12", x2: "12", y1: "8", y2: "12" }], ["line", { x1: "12", x2: "12.01", y1: "16", y2: "16" }]],
  "circle-check": [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "m9 12 2 2 4-4" }]],
  "circle-x": [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "m15 9-6 6" }], ["path", { d: "m9 9 6 6" }]],
  "circle-question-mark": [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" }], ["path", { d: "M12 17h.01" }]],
  gauge: [["path", { d: "m12 14 4-4" }], ["path", { d: "M3.34 19a10 10 0 1 1 17.32 0" }]],
  globe: [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" }], ["path", { d: "M2 12h20" }]],
  history: [["path", { d: "M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" }], ["path", { d: "M3 3v5h5" }], ["path", { d: "M12 7v5l4 2" }]],
  info: [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "M12 16v-4" }], ["path", { d: "M12 8h.01" }]],
  "key-round": [["path", { d: "M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z" }], ["circle", { cx: "16.5", cy: "7.5", r: ".5", fill: "currentColor" }]],
  "layout-dashboard": [["rect", { width: "7", height: "9", x: "3", y: "3", rx: "1" }], ["rect", { width: "7", height: "5", x: "14", y: "3", rx: "1" }], ["rect", { width: "7", height: "9", x: "14", y: "12", rx: "1" }], ["rect", { width: "7", height: "5", x: "3", y: "16", rx: "1" }]],
  "loader-circle": [["path", { d: "M21 12a9 9 0 1 1-6.219-8.56" }]],
  "log-in": [["path", { d: "m10 17 5-5-5-5" }], ["path", { d: "M15 12H3" }], ["path", { d: "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" }]],
  "log-out": [["path", { d: "m16 17 5-5-5-5" }], ["path", { d: "M21 12H9" }], ["path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" }]],
  "map-pinned": [["path", { d: "M18 8c0 3.613-3.869 7.429-5.393 8.795a1 1 0 0 1-1.214 0C9.87 15.429 6 11.613 6 8a6 6 0 0 1 12 0" }], ["circle", { cx: "12", cy: "8", r: "2" }], ["path", { d: "M8.714 14h-3.71a1 1 0 0 0-.948.683l-2.004 6A1 1 0 0 0 3 22h18a1 1 0 0 0 .948-1.316l-2-6a1 1 0 0 0-.949-.684h-3.712" }]],
  network: [["rect", { x: "16", y: "16", width: "6", height: "6", rx: "1" }], ["rect", { x: "2", y: "16", width: "6", height: "6", rx: "1" }], ["rect", { x: "9", y: "2", width: "6", height: "6", rx: "1" }], ["path", { d: "M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3" }], ["path", { d: "M12 12V8" }]],
  "refresh-cw": [["path", { d: "M3 12a9 9 0 0 1 15-6.7L21 8" }], ["path", { d: "M21 3v5h-5" }], ["path", { d: "M21 12a9 9 0 0 1-15 6.7L3 16" }], ["path", { d: "M8 16H3v5" }]],
  server: [["rect", { width: "20", height: "8", x: "2", y: "2", rx: "2", ry: "2" }], ["rect", { width: "20", height: "8", x: "2", y: "14", rx: "2", ry: "2" }], ["line", { x1: "6", x2: "6.01", y1: "6", y2: "6" }], ["line", { x1: "6", x2: "6.01", y1: "18", y2: "18" }]],
  settings: [["path", { d: "M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915" }], ["circle", { cx: "12", cy: "12", r: "3" }]],
  shield: [["path", { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }]],
  "shield-check": [["path", { d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" }], ["path", { d: "m9 12 2 2 4-4" }]],
  "sliders-horizontal": [["line", { x1: "21", x2: "14", y1: "4", y2: "4" }], ["line", { x1: "10", x2: "3", y1: "4", y2: "4" }], ["line", { x1: "21", x2: "12", y1: "12", y2: "12" }], ["line", { x1: "8", x2: "3", y1: "12", y2: "12" }], ["line", { x1: "21", x2: "16", y1: "20", y2: "20" }], ["line", { x1: "12", x2: "3", y1: "20", y2: "20" }], ["line", { x1: "14", x2: "14", y1: "2", y2: "6" }], ["line", { x1: "8", x2: "8", y1: "10", y2: "14" }], ["line", { x1: "16", x2: "16", y1: "18", y2: "22" }]],
  "user-round-check": [["path", { d: "M2 21a8 8 0 0 1 13.292-6" }], ["circle", { cx: "10", cy: "8", r: "5" }], ["path", { d: "m16 19 2 2 4-4" }]],
  "triangle-alert": [["path", { d: "m21.73 18-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" }], ["path", { d: "M12 9v4" }], ["path", { d: "M12 17h.01" }]],
});

export const LUCIDE_VERSION = "1.26.0";
export const LUCIDE_ICON_NAMES = Object.freeze(Object.keys(ICONS));

export function resolveIconName(identifier, fallback = FALLBACK_ICON) {
  return typeof identifier === "string" && Object.hasOwn(ICONS, identifier)
    ? identifier
    : fallback;
}

export function createIcon(identifier, { label = null, className = "" } = {}) {
  const name = resolveIconName(identifier);
  const svg = document.createElementNS(SVG_NAMESPACE, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("focusable", "false");
  svg.dataset.lucide = name;
  svg.classList.add("lucide-icon");
  if (className) svg.classList.add(...className.split(/\s+/).filter(Boolean));
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
  }
  for (const [tag, attributes] of ICONS[name]) {
    const child = document.createElementNS(SVG_NAMESPACE, tag);
    for (const [attribute, value] of Object.entries(attributes)) {
      child.setAttribute(attribute, value);
    }
    svg.append(child);
  }
  return svg;
}

export function renderIcon(element, identifier, options = {}) {
  if (!element) return null;
  const icon = createIcon(identifier, options);
  element.replaceChildren(icon);
  element.dataset.lucideIcon = icon.dataset.lucide;
  return icon;
}

export function initialiseIcons(root = document) {
  root.querySelectorAll("[data-lucide-icon]").forEach((element) => {
    renderIcon(element, element.dataset.lucideIcon);
  });
}

export function statusIconName(state) {
  if (state === "connected" || state === "signed_in" || state === "success") return "circle-check";
  if (state === "connecting" || state === "disconnecting" || state === "busy") return "loader-circle";
  if (["unavailable", "error", "warning", "danger"].includes(state)) return "circle-alert";
  if (state === "unknown") return "circle-question-mark";
  return "circle";
}
