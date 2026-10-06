import { select } from "./ui.js";

let pinned = false;
let dismissTimer = null;
const button = () => select("#dashboard-killswitch-info");
const popover = () => select("#dashboard-killswitch-description");

function positionInfo() {
  if (!popover().matches(":popover-open")) return;
  const anchor = button().getBoundingClientRect();
  const bounds = popover().getBoundingClientRect();
  popover().style.left = `${Math.max(8, Math.min(anchor.left, window.innerWidth - bounds.width - 8))}px`;
  popover().style.top = `${Math.max(8, anchor.bottom + bounds.height + 8 <= window.innerHeight ? anchor.bottom + 4 : anchor.top - bounds.height - 4)}px`;
}

function showInfo() {
  window.clearTimeout(dismissTimer);
  popover().showPopover();
  positionInfo();
}

export function closeDashboardInfo() {
  window.clearTimeout(dismissTimer);
  pinned = false;
  popover().hidePopover();
  button().setAttribute("aria-expanded", "false");
}

function dismissUnpinned() {
  window.clearTimeout(dismissTimer);
  // Allow the pointer to cross the gap into the explanatory text.
  dismissTimer = window.setTimeout(() => {
    if (!pinned && document.activeElement !== button() && !popover().matches(":hover") && !button().matches(":hover")) closeDashboardInfo();
  }, 150);
}

export function initialiseDashboardInfo() {
  button().addEventListener("pointerenter", (event) => {
    if (event.pointerType !== "touch") showInfo();
  });
  button().addEventListener("pointerleave", dismissUnpinned);
  button().addEventListener("focus", showInfo);
  button().addEventListener("blur", dismissUnpinned);
  button().addEventListener("click", (event) => {
    event.preventDefault();
    if (pinned && popover().matches(":popover-open")) closeDashboardInfo();
    else { showInfo(); pinned = true; }
  });
  popover().addEventListener("pointerenter", () => window.clearTimeout(dismissTimer));
  popover().addEventListener("pointerleave", dismissUnpinned);
  popover().addEventListener("beforetoggle", (event) => {
    button().setAttribute("aria-expanded", String(event.newState === "open"));
    if (event.newState === "closed") pinned = false;
  });
  button().addEventListener("keydown", (event) => {
    if (event.key === "Escape") { closeDashboardInfo(); event.preventDefault(); }
  });
  window.addEventListener("resize", positionInfo);
  window.addEventListener("scroll", positionInfo, true);
  window.addEventListener("pagehide", closeDashboardInfo);
  window.addEventListener("exitlane:authenticationrequired", closeDashboardInfo);
}
