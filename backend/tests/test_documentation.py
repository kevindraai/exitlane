from pathlib import Path

import pytest

from exitlane.documentation import (
    CATEGORIES,
    DOCUMENTS,
    DocumentationError,
    DocumentDefinition,
    documentation_document,
    documentation_index,
    inline_tokens,
    parse_markdown,
    safe_link,
)

DOCS_ROOT = Path(__file__).resolve().parents[2] / "docs"


def test_documentation_catalog_uses_only_existing_allowlisted_markdown_sources():
    payload = documentation_index(DOCS_ROOT)
    assert payload["categories"] == list(CATEGORIES)
    assert {item["slug"] for item in payload["documents"]} == {
        definition.slug for definition in DOCUMENTS
    }
    assert all(item["source"].startswith("docs/") for item in payload["documents"])
    assert all((DOCS_ROOT / definition.path).is_file() for definition in DOCUMENTS)


def test_document_projection_is_structured_and_contains_no_rendered_html():
    payload = documentation_document("diagnostics", DOCS_ROOT)
    assert payload["title"] == "Connection diagnostics"
    assert any(block["type"] == "code" for block in payload["blocks"])
    assert any(block["type"] == "heading" for block in payload["blocks"])
    assert "html" not in repr(payload).lower()


def test_markdown_projection_keeps_hostile_markup_as_text_and_rejects_unsafe_urls():
    source = DocumentDefinition("diagnostics", "diagnostics", "diagnostics.md")
    blocks = parse_markdown(
        "# Guide\n\n<script>alert(1)</script> [bad](javascript:alert(1)) "
        "[data](data:text/html,boom) [good](https://example.com/path)",
        source,
    )
    paragraph = next(block for block in blocks if block["type"] == "paragraph")
    assert "<script>alert(1)</script>" in repr(paragraph)
    assert "javascript:" not in repr(paragraph)
    assert "data:text" not in repr(paragraph)
    links = [token for token in paragraph["content"] if token["type"] == "link"]
    assert links == [
        {"type": "link", "text": "good", "href": "https://example.com/path", "external": True}
    ]


def test_document_links_resolve_only_to_catalog_routes_or_safe_https_sources():
    source = DocumentDefinition("authentication", "security", "authentication.md")
    assert safe_link("security/mfa.md", source) == {"href": "#help/mfa", "external": False}
    assert safe_link("#session-model", source) == {
        "href": "#help/authentication#session-model",
        "external": False,
    }
    assert safe_link("https://example.com", source) == {
        "href": "https://example.com",
        "external": True,
    }
    for target in ("http://example.com", "//example.com", "/etc/passwd", "../../secret.md"):
        assert safe_link(target, source) is None


def test_inline_image_syntax_never_creates_an_image_or_external_request():
    source = DocumentDefinition("deployment", "getting-started", "deployment.md")
    tokens = inline_tokens("Before ![alt](https://example.com/tracker.png) after", source)
    assert tokens == [
        {"type": "text", "text": "Before "},
        {"type": "text", "text": "alt"},
        {"type": "text", "text": " after"},
    ]


def test_wrapped_list_items_stay_together_and_ordered_lists_keep_their_start():
    source = DocumentDefinition("diagnostics", "diagnostics", "diagnostics.md")
    blocks = parse_markdown(
        "- First item wraps\n  onto a second line.\n- Second item.\n\n"
        "3. Third step wraps\n   before its code.\n\n```bash\ntrue\n```",
        source,
    )
    assert blocks[0] == {
        "type": "list",
        "ordered": False,
        "items": [
            [{"type": "text", "text": "First item wraps onto a second line."}],
            [{"type": "text", "text": "Second item."}],
        ],
    }
    assert blocks[1] == {
        "type": "list",
        "ordered": True,
        "start": 3,
        "items": [[{"type": "text", "text": "Third step wraps before its code."}]],
    }
    assert blocks[2]["type"] == "code"


def test_documentation_reader_rejects_oversized_files(tmp_path):
    path = tmp_path / "diagnostics.md"
    path.write_bytes(b"x" * (256 * 1024 + 1))
    with pytest.raises(DocumentationError, match="size limit"):
        documentation_document("diagnostics", tmp_path)
