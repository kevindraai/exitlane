import json
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import exitlane.core as core
import exitlane.main as main
from exitlane.html import HtmlCompositionError, PARTIALS, STATIC_DIR, render_index

FIXTURE = Path(__file__).parent / "fixtures" / "index_contract.json"
CRITICAL_IDS = {
    "logout-button",
    "api-status",
    "app-version",
    "sidebar",
    "login-panel",
    "login-form",
    "wizard-panel",
    "wizard-steps",
    "wizard-error",
    "step-1",
    "step-2",
    "step-3",
    "step-4",
    "step-5",
    "diagnostics-button",
    "admin-form",
    "provider-next",
    "wireguard-form",
    "wireguard-next",
    "complete-button",
    "dashboard-panel",
    "view-vpn",
    "view-wireguard",
    "view-activity",
    "view-security",
    "view-settings",
    "toast-region",
}
OPTIONAL_LEGACY_SELECTORS = {
    "color-scheme-current",
    "color-scheme-options",
    "color-scheme-trigger",
    "language-current",
    "language-options",
    "language-trigger",
}


class MarkupParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def parse(html: str) -> MarkupParser:
    parser = MarkupParser()
    parser.feed(html)
    return parser


def values(parser: MarkupParser, attribute: str) -> list[str]:
    return [value for _, attrs in parser.elements if (value := attrs.get(attribute)) is not None]


@pytest.fixture
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    database = data / "exitlane.db"
    monkeypatch.setattr(core, "DATA", data)
    monkeypatch.setattr(core, "DB", database)
    monkeypatch.setattr(core, "WG_DIR", data / "wireguard")
    monkeypatch.setattr(main, "DB", database)
    monkeypatch.setattr(main, "WG_DIR", data / "wireguard")
    with TestClient(main.app, raise_server_exceptions=False) as test_client:
        yield test_client


def test_index_response_is_one_complete_document(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    parser = parse(html)
    tags = Counter(tag for tag, _ in parser.elements)
    classes = [set((attrs.get("class") or "").split()) for _, attrs in parser.elements]
    assert tags["html"] == tags["head"] == tags["body"] == 1
    assert sum("app-header" in value for value in classes) == 1
    assert sum("app-shell" in value for value in classes) == 1
    for element_id in ("sidebar", "toast-region"):
        assert html.count(f'id="{element_id}"') == 1
    assert html.count('src="/assets/js/app.js"') == 1
    assert html.count('href="/assets/style.css"') == 1
    assert "EXITLANE_PARTIAL:" not in html


def test_composed_markup_matches_the_monolith_contract_fixture():
    parser = parse(render_index())
    expected = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for attribute in (
        "id",
        "data-view",
        "data-view-panel",
        "data-step",
        "data-step-name",
        "data-back",
        "data-i18n",
        "data-i18n-aria-label",
    ):
        actual = values(parser, attribute)
        assert sorted(set(actual)) == expected[attribute]
        if attribute == "id":
            assert len(actual) == len(set(actual))
            assert CRITICAL_IDS <= set(actual)

    forms = sorted(attrs["id"] for tag, attrs in parser.elements if tag == "form")
    scripts = [attrs.get("src") for tag, attrs in parser.elements if tag == "script"]
    styles = [
        attrs.get("href")
        for tag, attrs in parser.elements
        if tag == "link" and "stylesheet" in (attrs.get("rel") or "")
    ]
    assert forms == expected["forms"]
    assert scripts == expected["script_sources"]
    assert styles == expected["stylesheet_urls"]


def test_navigation_wizard_and_accessibility_references_are_complete():
    parser = parse(render_index())
    ids = set(values(parser, "id"))
    views = values(parser, "data-view")
    panels = values(parser, "data-view-panel")
    # Provider navigation entries are created from authenticated registry
    # metadata, so the static provider panel deliberately has no fixed button.
    assert Counter(views) == Counter(panel for panel in panels if panel != "vpn-provider")
    assert all(count == 1 for count in Counter(panels).values())
    assert {f"step-{number}" for number in range(1, 6)} <= ids
    assert all(f"step-{target}" in ids for target in values(parser, "data-back"))
    for _, attrs in parser.elements:
        if target := attrs.get("for"):
            assert target in ids
        for attribute in ("aria-labelledby", "aria-describedby"):
            for target in (attrs.get(attribute) or "").split():
                assert target in ids
    assert len(values(parser, "aria-live")) == 11


def test_javascript_static_id_selectors_exist_in_composed_markup():
    ids = set(values(parse(render_index()), "id"))
    selectors = set()
    pattern = re.compile(r"(?:select|querySelector)\(\s*['\"]#([A-Za-z0-9_-]+)")
    for path in (STATIC_DIR / "js").glob("*.js"):
        selectors.update(pattern.findall(path.read_text(encoding="utf-8")))
    assert selectors - OPTIONAL_LEGACY_SELECTORS <= ids
    assert selectors - ids == OPTIONAL_LEGACY_SELECTORS


def test_partials_are_passive_markup_fragments():
    assert len(PARTIALS) == 16
    for relative_path in PARTIALS.values():
        html = (STATIC_DIR / relative_path).read_text(encoding="utf-8")
        lowered = html.lower()
        assert "<!doctype" not in lowered
        assert not re.search(r"<\/?(?:html|head|body)\b", lowered)
        assert "<script" not in lowered
        assert not re.search(r"<link\b[^>]*stylesheet", lowered)
        assert "EXITLANE_PARTIAL:" not in html
        assert "app-shell" not in html
        assert "app-content" not in html


def test_forms_do_not_fall_back_to_sensitive_get_queries():
    parser = parse(render_index())
    forms = [attrs for tag, attrs in parser.elements if tag == "form"]
    assert forms
    assert all(attrs.get("method") == "post" for attrs in forms)


def test_missing_partial_and_invalid_marker_fail_clearly(tmp_path):
    index = tmp_path / "index.html"
    index.write_text("<!-- EXITLANE_PARTIAL:header -->", encoding="utf-8")
    with pytest.raises(HtmlCompositionError, match="Static HTML could not be composed"):
        render_index(index, tmp_path)

    index.write_text("no markers", encoding="utf-8")
    with pytest.raises(HtmlCompositionError, match="Expected one static HTML marker"):
        render_index(index, STATIC_DIR)


def test_composition_failure_returns_safe_500(client, monkeypatch):
    def fail_rendering():
        raise HtmlCompositionError("sensitive/filesystem/path")

    monkeypatch.setattr(main, "render_index", fail_rendering)
    response = client.get("/")
    assert response.status_code == 500
    assert "sensitive" not in response.text
    assert "filesystem" not in response.text


def test_static_assets_and_passive_partials_remain_available(client):
    for path in (
        "/assets/style.css",
        "/assets/js/app.js",
        "/assets/icons/favicon.svg",
        "/assets/icons/site.webmanifest",
        "/assets/partials/header.html",
    ):
        assert client.get(path).status_code == 200
