import { api } from "./api.js";
import { t } from "./i18n.js";
import { showView } from "./navigation.js";

const CATEGORY_KEYS = Object.freeze({
  "getting-started": "help.categories.getting_started",
  vpn: "help.categories.vpn",
  wireguard: "help.categories.wireguard",
  diagnostics: "help.categories.diagnostics",
  security: "help.categories.security",
  "appliance-management": "help.categories.appliance_management",
});

let indexData = null;
let indexRequest = null;
let activeDocument = null;

function documentLabel(document) {
  return t(`help.documents.${document.slug}`, {}, document.title);
}

function categoryLabel(category) {
  return t(CATEGORY_KEYS[category] || "help.categories.other", {}, category);
}

function setError(message = "") {
  const error = document.querySelector("#help-error");
  error.hidden = !message;
  error.textContent = message;
}

function requestedSlug() {
  const parts = window.location.hash.replace(/^#/, "").split("/");
  const slug = (parts[1] || "").split("#", 1)[0];
  return parts[0] === "help" && /^[a-z0-9-]+$/.test(slug)
    ? slug
    : null;
}

function navigateToDocument(slug) {
  window.history.pushState(null, "", `#help/${encodeURIComponent(slug)}`);
  showView("help", { historyMode: "none" });
}

function showIndex({ replaceHistory = false } = {}) {
  if (replaceHistory) window.history.replaceState(null, "", "#help");
  else if (window.location.hash !== "#help") window.history.pushState(null, "", "#help");
  document.querySelector("#help-index").hidden = false;
  document.querySelector("#help-document").hidden = true;
  activeDocument = null;
  setError();
  loadIndex().catch(() => {});
}

export function safeDocumentationHref(href) {
  if (/^#help\/[a-z0-9-]+(?:#[a-z0-9-]+)?$/.test(href)) return href;
  try {
    const url = new URL(href);
    if (url.protocol === "https:" && !url.username && !url.password) return url.href;
  } catch {
    // Invalid links stay visible as text.
  }
  return null;
}

function appendInline(container, tokens) {
  for (const token of tokens || []) {
    if (["strong", "emphasis", "deleted"].includes(token.type)) {
      const tag = { strong: "strong", emphasis: "em", deleted: "del" }[token.type];
      const element = document.createElement(tag);
      element.textContent = token.text || "";
      container.append(element);
      continue;
    }
    if (token.type === "code") {
      const code = document.createElement("code");
      code.textContent = token.text || "";
      container.append(code);
      continue;
    }
    if (token.type === "link") {
      const href = safeDocumentationHref(token.href || "");
      if (href) {
        const link = document.createElement("a");
        link.href = href;
        link.textContent = token.text || href;
        if (token.external) {
          link.target = "_blank";
          link.rel = "noopener noreferrer";
        }
        container.append(link);
        continue;
      }
    }
    container.append(document.createTextNode(token.text || ""));
  }
}

function renderBlock(block) {
  if (block.type === "heading") {
    if (block.level === 1) return null;
    const heading = document.createElement(`h${Math.min(6, Number(block.level) + 1)}`);
    heading.id = block.id || "section";
    heading.textContent = block.text || "";
    return heading;
  }
  if (block.type === "code") {
    const pre = document.createElement("pre");
    const code = document.createElement("code");
    if (block.language) code.dataset.language = block.language;
    code.textContent = block.text || "";
    pre.append(code);
    return pre;
  }
  if (block.type === "list") {
    const list = document.createElement(block.ordered ? "ol" : "ul");
    if (block.ordered && Number(block.start) > 1) list.start = Number(block.start);
    for (const item of block.items || []) {
      const listItem = document.createElement("li");
      appendInline(listItem, item);
      list.append(listItem);
    }
    return list;
  }
  if (block.type === "table") {
    const wrapper = document.createElement("div");
    wrapper.className = "documentation-table-wrap";
    const table = document.createElement("table");
    for (const [rowIndex, row] of (block.rows || []).entries()) {
      const section = rowIndex === 0 ? document.createElement("thead") : table.querySelector("tbody") || document.createElement("tbody");
      const tableRow = document.createElement("tr");
      for (const cell of row) {
        const element = document.createElement(rowIndex === 0 ? "th" : "td");
        element.textContent = cell;
        tableRow.append(element);
      }
      section.append(tableRow);
      if (!section.parentElement) table.append(section);
    }
    wrapper.append(table);
    return wrapper;
  }
  const paragraph = document.createElement(block.type === "notice" ? "aside" : "p");
  if (block.type === "notice") paragraph.className = "documentation-notice";
  appendInline(paragraph, block.content);
  return paragraph;
}

function renderIndex(payload) {
  const categories = document.querySelector("#help-categories");
  categories.replaceChildren();
  for (const category of payload.categories || []) {
    const card = document.createElement("section");
    card.className = "help-category-card";
    const heading = document.createElement("h2");
    heading.textContent = categoryLabel(category);
    const list = document.createElement("ul");
    for (const entry of (payload.documents || []).filter((item) => item.category === category)) {
      const item = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.className = "help-document-link";
      button.textContent = documentLabel(entry);
      button.addEventListener("click", () => navigateToDocument(entry.slug));
      item.append(button);
      list.append(item);
    }
    card.append(heading, list);
    categories.append(card);
  }
  document.querySelector("#help-loading").hidden = true;
}

async function loadIndex() {
  if (indexData) {
    renderIndex(indexData);
    return indexData;
  }
  if (!indexRequest) indexRequest = api("/api/help/documents");
  try {
    indexData = await indexRequest;
    renderIndex(indexData);
    return indexData;
  } catch {
    setError(t("help.errors.index", {}, "Documentation could not be loaded."));
    throw new Error("documentation_index_unavailable");
  } finally {
    indexRequest = null;
  }
}

async function loadDocument(slug) {
  setError();
  document.querySelector("#help-index").hidden = true;
  const article = document.querySelector("#help-document");
  article.hidden = false;
  const content = document.querySelector("#help-document-content");
  content.replaceChildren();
  try {
    const payload = await api(`/api/help/documents/${encodeURIComponent(slug)}`);
    activeDocument = payload;
    document.querySelector("#help-document-title").textContent = documentLabel(payload);
    document.querySelector("#help-document-category").textContent = categoryLabel(payload.category);
    document.querySelector("#help-document-source").textContent = payload.source;
    for (const block of payload.blocks || []) {
      const element = renderBlock(block);
      if (element) content.append(element);
    }
    article.focus({ preventScroll: true });
    const fragment = window.location.hash.split("#")[2];
    if (fragment) document.getElementById(fragment)?.scrollIntoView?.();
  } catch {
    activeDocument = null;
    article.hidden = true;
    document.querySelector("#help-index").hidden = false;
    setError(t("help.errors.document", {}, "This document could not be loaded."));
  }
}

function activateHelpRoute() {
  const slug = requestedSlug();
  if (slug) loadDocument(slug).catch(() => {});
  else showIndex({ replaceHistory: window.location.hash !== "#help" });
}

export function initialiseDocumentation() {
  document.querySelector('[data-view="help"]').addEventListener("click", () => {
    if (window.location.hash !== "#help") window.history.pushState(null, "", "#help");
  });
  document.querySelector("#help-back").addEventListener("click", () => {
    window.history.pushState(null, "", "#help");
    showIndex();
  });
  document.querySelectorAll("[data-help-document]").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      navigateToDocument(link.dataset.helpDocument);
    });
  });
  document.querySelector("#help-document-content").addEventListener("click", (event) => {
    const link = event.target.closest?.('a[href^="#help/"]');
    if (!link) return;
    event.preventDefault();
    window.history.pushState(null, "", link.getAttribute("href"));
    showView("help", { historyMode: "none" });
  });
  window.addEventListener("exitlane:viewchange", (event) => {
    if (event.detail.view === "help") activateHelpRoute();
  });
  window.addEventListener("exitlane:languagechange", () => {
    if (indexData) renderIndex(indexData);
    if (!document.querySelector("#help-document").hidden && activeDocument) {
      document.querySelector("#help-document-title").textContent = documentLabel(activeDocument);
      document.querySelector("#help-document-category").textContent = categoryLabel(
        activeDocument.category,
      );
    }
  });
}
