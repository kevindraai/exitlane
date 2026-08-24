from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_DOCUMENT_BYTES = 256 * 1024
GITHUB_DOCS_BASE = "https://github.com/kevindraai/exitlane/blob/main/"


@dataclass(frozen=True)
class DocumentDefinition:
    slug: str
    category: str
    path: str


DOCUMENTS = (
    DocumentDefinition("deployment", "getting-started", "deployment.md"),
    DocumentDefinition("proxmox-lxc", "getting-started", "proxmox-lxc.md"),
    DocumentDefinition("router-integrations", "getting-started", "router-integrations.md"),
    DocumentDefinition("killswitch", "vpn", "killswitch.md"),
    DocumentDefinition("wireguard-configuration", "wireguard", "wireguard-configuration.md"),
    DocumentDefinition("diagnostics", "diagnostics", "diagnostics.md"),
    DocumentDefinition("authentication", "security", "authentication.md"),
    DocumentDefinition("mfa", "security", "security/mfa.md"),
    DocumentDefinition("hardening-guide", "security", "security/hardening-guide.md"),
    DocumentDefinition("reverse-proxy", "security", "deployment/reverse-proxy.md"),
    DocumentDefinition("backup-and-restore", "appliance-management", "backup-and-restore.md"),
    DocumentDefinition("upgrade-and-recovery", "appliance-management", "upgrade-and-recovery.md"),
    DocumentDefinition("activity-log", "appliance-management", "activity-log.md"),
)
DOCUMENT_BY_SLUG = {document.slug: document for document in DOCUMENTS}
SLUG_BY_PATH = {document.path: document.slug for document in DOCUMENTS}
CATEGORIES = (
    "getting-started",
    "vpn",
    "wireguard",
    "diagnostics",
    "security",
    "appliance-management",
)


class DocumentationError(RuntimeError):
    """Raised when the fixed local documentation catalog cannot be read safely."""


def documentation_root() -> Path:
    candidates = (
        Path(__file__).resolve().parents[2] / "docs",
        Path("/opt/exitlane/docs"),
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise DocumentationError("Documentation directory is unavailable")


def _document_path(definition: DocumentDefinition, root: Path) -> Path:
    resolved_root = root.resolve()
    path = (resolved_root / definition.path).resolve()
    if not path.is_relative_to(resolved_root):
        raise DocumentationError("Documentation path is outside the catalog root")
    return path


def _read_document(definition: DocumentDefinition, root: Path) -> str:
    path = _document_path(definition, root)
    try:
        with path.open("rb") as source_file:
            payload = source_file.read(MAX_DOCUMENT_BYTES + 1)
        if len(payload) > MAX_DOCUMENT_BYTES:
            raise DocumentationError("Documentation file exceeds the size limit")
        return payload.decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise DocumentationError("Documentation file is unavailable") from error


def _plain_text(value: str) -> str:
    value = re.sub(r"!\[([^]]*)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", value)
    return re.sub(r"[*_~`]", "", value).strip()


def _heading_id(value: str) -> str:
    identifier = re.sub(r"[^a-z0-9]+", "-", _plain_text(value).lower()).strip("-")
    return identifier[:80] or "section"


def _relative_document_link(target: str, source: DocumentDefinition) -> str | None:
    path_part, separator, fragment = target.partition("#")
    if not path_part:
        suffix = f"#{_heading_id(fragment)}" if separator and fragment else ""
        return f"#help/{source.slug}{suffix}"
    source_parent = Path(source.path).parent
    candidate = (source_parent / path_part).as_posix()
    normalized = posixpath.normpath(candidate)
    if normalized == ".." or normalized.startswith("../"):
        return None
    slug = SLUG_BY_PATH.get(normalized)
    if slug:
        suffix = f"#{_heading_id(fragment)}" if separator and fragment else ""
        return f"#help/{slug}{suffix}"
    if normalized.endswith(".md") and not target.startswith(("/", "\\")):
        suffix = f"#{_heading_id(fragment)}" if separator and fragment else ""
        return f"{GITHUB_DOCS_BASE}docs/{normalized}{suffix}"
    return None


def safe_link(target: str, source: DocumentDefinition) -> dict[str, object] | None:
    candidate = target.strip().strip("<>")
    parsed = urlsplit(candidate)
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
            return None
        return {"href": candidate, "external": True}
    if parsed.netloc or candidate.startswith(("//", "/", "\\")):
        return None
    href = _relative_document_link(candidate, source)
    if href is None:
        return None
    return {"href": href, "external": href.startswith("https://")}


INLINE_PATTERN = re.compile(
    r"(`[^`\n]+`|!?\[[^]\n]+\]\([^)\n]+\)|\*\*[^*\n]+\*\*|~~[^~\n]+~~|(?<!\*)\*[^*\n]+\*(?!\*))"
)
LINK_PATTERN = re.compile(r"(!?)\[([^]]+)\]\(([^)\s]+)(?:\s+['\"][^'\"]*['\"])?\)")


def inline_tokens(value: str, source: DocumentDefinition) -> list[dict[str, object]]:
    tokens: list[dict[str, object]] = []
    position = 0
    for match in INLINE_PATTERN.finditer(value):
        if match.start() > position:
            tokens.append({"type": "text", "text": value[position : match.start()]})
        raw = match.group(0)
        if raw.startswith("`"):
            tokens.append({"type": "code", "text": raw[1:-1]})
        elif raw.startswith("**"):
            tokens.append({"type": "strong", "text": raw[2:-2]})
        elif raw.startswith("~~"):
            tokens.append({"type": "deleted", "text": raw[2:-2]})
        elif raw.startswith("*"):
            tokens.append({"type": "emphasis", "text": raw[1:-1]})
        else:
            link_match = LINK_PATTERN.fullmatch(raw)
            if not link_match:
                tokens.append({"type": "text", "text": raw})
            else:
                image, label, target = link_match.groups()
                link = safe_link(target, source)
                if image or link is None:
                    tokens.append({"type": "text", "text": label})
                else:
                    tokens.append({"type": "link", "text": label, **link})
        position = match.end()
    if position < len(value):
        tokens.append({"type": "text", "text": value[position:]})
    return tokens or [{"type": "text", "text": ""}]


def _is_block_start(line: str, next_line: str = "") -> bool:
    stripped = line.strip()
    return bool(
        not stripped
        or stripped.startswith(("#", "```", "> "))
        or re.match(r"^[-*+]\s+", stripped)
        or re.match(r"^\d+[.)]\s+", stripped)
        or ("|" in stripped and re.match(r"^\s*\|?\s*:?-{3,}", next_line))
    )


def parse_markdown(source_text: str, source: DocumentDefinition) -> list[dict[str, object]]:
    lines = source_text.replace("\r\n", "\n").split("\n")
    blocks: list[dict[str, object]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue

        if stripped.startswith("```"):
            language = stripped[3:].strip()[:32]
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            if index < len(lines):
                index += 1
            blocks.append({"type": "code", "language": language, "text": "\n".join(code_lines)})
            continue

        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            text = _plain_text(heading.group(2))
            blocks.append(
                {
                    "type": "heading",
                    "level": len(heading.group(1)),
                    "text": text,
                    "id": _heading_id(text),
                }
            )
            index += 1
            continue

        if stripped.startswith("> "):
            quote_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith(">"):
                quote_lines.append(lines[index].strip().removeprefix(">").strip())
                index += 1
            blocks.append(
                {"type": "notice", "content": inline_tokens(" ".join(quote_lines), source)}
            )
            continue

        list_match = re.match(r"^([-*+]|\d+[.)])\s+(.+)$", stripped)
        if list_match:
            ordered = list_match.group(1)[0].isdigit()
            start = int(re.match(r"\d+", list_match.group(1)).group()) if ordered else None
            items: list[list[dict[str, object]]] = []
            while index < len(lines):
                item_match = re.match(r"^([-*+]|\d+[.)])\s+(.+)$", lines[index].strip())
                if not item_match or item_match.group(1)[0].isdigit() != ordered:
                    break
                item_lines = [item_match.group(2)]
                index += 1
                while index < len(lines):
                    continuation = lines[index].strip()
                    lookahead = lines[index + 1] if index + 1 < len(lines) else ""
                    if (
                        not continuation
                        or continuation.startswith(("#", "```", "> "))
                        or re.match(r"^[-*+]\s+", continuation)
                        or re.match(r"^\d+[.)]\s+", continuation)
                        or ("|" in continuation and re.match(r"^\s*\|?\s*:?-{3,}", lookahead))
                    ):
                        break
                    item_lines.append(continuation)
                    index += 1
                items.append(inline_tokens(" ".join(item_lines), source))
            block: dict[str, object] = {"type": "list", "ordered": ordered, "items": items}
            if start is not None:
                block["start"] = start
            blocks.append(block)
            continue

        if (
            index + 1 < len(lines)
            and "|" in stripped
            and re.match(r"^\s*\|?\s*:?-{3,}", lines[index + 1])
        ):
            rows: list[list[str]] = []
            rows.append([_plain_text(cell) for cell in stripped.strip("|").split("|")])
            index += 2
            while index < len(lines) and "|" in lines[index] and lines[index].strip():
                rows.append(
                    [_plain_text(cell) for cell in lines[index].strip().strip("|").split("|")]
                )
                index += 1
            blocks.append({"type": "table", "rows": rows})
            continue

        paragraph = [stripped]
        index += 1
        while index < len(lines):
            next_line = lines[index]
            lookahead = lines[index + 1] if index + 1 < len(lines) else ""
            if _is_block_start(next_line, lookahead):
                break
            paragraph.append(next_line.strip())
            index += 1
        blocks.append({"type": "paragraph", "content": inline_tokens(" ".join(paragraph), source)})
    return blocks


def documentation_index(root: Path | None = None) -> dict[str, object]:
    docs_root = (root or documentation_root()).resolve()
    documents = []
    for definition in DOCUMENTS:
        text = _read_document(definition, docs_root)
        title_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        documents.append(
            {
                "slug": definition.slug,
                "category": definition.category,
                "title": _plain_text(title_match.group(1)) if title_match else definition.slug,
                "source": f"docs/{definition.path}",
            }
        )
    return {"categories": list(CATEGORIES), "documents": documents}


def documentation_document(slug: str, root: Path | None = None) -> dict[str, object]:
    definition = DOCUMENT_BY_SLUG.get(slug)
    if definition is None:
        raise KeyError(slug)
    docs_root = (root or documentation_root()).resolve()
    source_text = _read_document(definition, docs_root)
    blocks = parse_markdown(source_text, definition)
    title = next(
        (
            str(block["text"])
            for block in blocks
            if block["type"] == "heading" and block["level"] == 1
        ),
        definition.slug,
    )
    return {
        "slug": definition.slug,
        "category": definition.category,
        "title": title,
        "source": f"docs/{definition.path}",
        "blocks": blocks,
    }
