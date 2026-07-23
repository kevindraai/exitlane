from __future__ import annotations

from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"
PARTIALS = {
    "header": "partials/header.html",
    "sidebar": "partials/sidebar.html",
    "login": "partials/login.html",
    "wizard/shell": "partials/wizard/shell.html",
    "wizard/system": "partials/wizard/system.html",
    "wizard/administrator": "partials/wizard/administrator.html",
    "wizard/provider": "partials/wizard/provider.html",
    "wizard/wireguard": "partials/wizard/wireguard.html",
    "wizard/finish": "partials/wizard/finish.html",
    "views/dashboard": "partials/views/dashboard.html",
    "views/vpn-overview": "partials/views/vpn-overview.html",
    "views/vpn": "partials/views/vpn.html",
    "views/wireguard": "partials/views/wireguard.html",
    "views/activity": "partials/views/activity.html",
    "views/settings": "partials/views/settings.html",
}


class HtmlCompositionError(RuntimeError):
    """Raised when trusted static markup cannot be composed."""


def render_index(index_file: Path = INDEX_FILE, static_dir: Path = STATIC_DIR) -> str:
    """Compose the complete frontend DOM from fixed UTF-8 partials."""
    try:
        html = index_file.read_text(encoding="utf-8")
        for name, relative_path in PARTIALS.items():
            marker = f"<!-- EXITLANE_PARTIAL:{name} -->"
            if html.count(marker) != 1:
                raise HtmlCompositionError(f"Expected one static HTML marker for {name}")
            partial = (static_dir / relative_path).read_text(encoding="utf-8").rstrip("\n")
            html = html.replace(marker, partial)
    except OSError as error:
        raise HtmlCompositionError("Static HTML could not be composed") from error

    if "EXITLANE_PARTIAL:" in html:
        raise HtmlCompositionError("Static HTML contains an unresolved partial marker")
    return html
