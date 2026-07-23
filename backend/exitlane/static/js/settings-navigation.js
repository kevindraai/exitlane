import { createIcon, renderIcon } from "./icons.js";
import { t } from "./i18n.js";

export const SETTINGS_SECTIONS = Object.freeze([
  Object.freeze({ id: "general", route: "settings/general", labelKey: "nav.settings_general", icon: "sliders-horizontal", order: 10, enabled: true }),
  Object.freeze({ id: "security", route: "settings/security", labelKey: "nav.settings_security", icon: "shield-check", order: 20, enabled: true }),
  Object.freeze({ id: "network", route: "settings/network", labelKey: "nav.settings_network", icon: "network", order: 30, enabled: true }),
  Object.freeze({ id: "notifications", route: "settings/notifications", labelKey: "nav.settings_notifications", icon: "bell", order: 40, enabled: true }),
  Object.freeze({ id: "backup", route: "settings/backup", labelKey: "nav.settings_backup", icon: "archive-restore", order: 50, enabled: false }),
  Object.freeze({ id: "updates", route: "settings/updates", labelKey: "nav.settings_updates", icon: "refresh-cw", order: 60, enabled: false }),
  Object.freeze({ id: "about", route: "settings/about", labelKey: "nav.settings_about", icon: "info", order: 70, enabled: true }),
]);

export const availableSettingsSections = () =>
  SETTINGS_SECTIONS.filter((section) => section.enabled).sort((a, b) => a.order - b.order);

export function validSettingsSection(id) {
  return availableSettingsSections().some((section) => section.id === id);
}

export function renderSettingsNavigation(container) {
  container.replaceChildren(...availableSettingsSections().map((section) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sidebar-item sidebar-subitem";
    button.dataset.view = "settings";
    button.dataset.settingsSection = section.id;
    const icon = document.createElement("span");
    icon.className = "sidebar-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.append(createIcon(section.icon));
    const label = document.createElement("span");
    label.dataset.i18n = section.labelKey;
    label.textContent = t(section.labelKey, {}, section.id);
    button.append(icon, label);
    return button;
  }));
}

export function setSettingsGroupExpanded(expanded) {
  const toggle = document.querySelector("#settings-navigation-toggle");
  toggle.setAttribute("aria-expanded", String(expanded));
  document.querySelector("#settings-navigation-items").hidden = !expanded;
  renderIcon(
    document.querySelector("#settings-navigation-toggle .sidebar-group-chevron"),
    expanded ? "chevron-down" : "chevron-right",
  );
}
