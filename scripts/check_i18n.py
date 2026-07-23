#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = ROOT / "backend" / "exitlane" / "static"
LOCALES_DIR = STATIC_DIR / "locales"
INDEX_FILE = STATIC_DIR / "index.html"
PARTIALS_DIR = STATIC_DIR / "partials"
JS_DIR = STATIC_DIR / "js"

REFERENCE_LANGUAGE = "en"

PLACEHOLDER_PATTERN = re.compile(r"\{([A-Za-z0-9_]+)\}")
JS_TRANSLATION_PATTERN = re.compile(
    r"""\bt\(\s*["']([^"']+)["']""",
    re.MULTILINE,
)


def flatten_messages(
    value: dict[str, Any],
    prefix: str = "",
) -> dict[str, str]:
    flattened: dict[str, str] = {}

    for key, child in value.items():
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(child, dict):
            flattened.update(
                flatten_messages(
                    child,
                    full_key,
                )
            )
        elif isinstance(child, str):
            flattened[full_key] = child
        else:
            raise ValueError(
                f"Translation key '{full_key}' must contain a string or object."
            )

    return flattened


class TranslationAttributeParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.keys: set[str] = set()

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del tag

        for name, value in attrs:
            if not value:
                continue

            if name == "data-i18n" or name.startswith("data-i18n-"):
                self.keys.add(value)


def load_locales() -> dict[str, dict[str, str]]:
    locale_files = sorted(LOCALES_DIR.glob("*.json"))

    if not locale_files:
        raise RuntimeError(f"No locale files found in {LOCALES_DIR}")

    locales: dict[str, dict[str, str]] = {}

    for path in locale_files:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Invalid JSON in {path}: {error}") from error

        if not isinstance(raw, dict):
            raise RuntimeError(f"Locale {path} must contain a JSON object.")

        locales[path.stem] = flatten_messages(raw)

    return locales


def collect_html_keys() -> set[str]:
    parser = TranslationAttributeParser()
    html_files = [INDEX_FILE, *sorted(PARTIALS_DIR.rglob("*.html"))]
    for path in html_files:
        parser.feed(path.read_text(encoding="utf-8"))
    return parser.keys


def collect_javascript_keys() -> set[str]:
    keys: set[str] = set()

    for path in sorted(JS_DIR.glob("*.js")):
        content = path.read_text(encoding="utf-8")

        keys.update(JS_TRANSLATION_PATTERN.findall(content))

    return keys


def placeholders(value: str) -> set[str]:
    return set(PLACEHOLDER_PATTERN.findall(value))


def main() -> int:
    errors: list[str] = []

    try:
        locales = load_locales()
    except RuntimeError as error:
        print(f"ERROR: {error}")
        return 1

    reference = locales.get(REFERENCE_LANGUAGE)

    if reference is None:
        print(f"ERROR: Reference locale '{REFERENCE_LANGUAGE}.json' is missing.")
        return 1

    reference_keys = set(reference)

    for language, messages in locales.items():
        language_keys = set(messages)

        missing = sorted(reference_keys - language_keys)
        additional = sorted(language_keys - reference_keys)

        for key in missing:
            errors.append(f"{language}.json is missing key: {key}")

        for key in additional:
            errors.append(
                f"{language}.json contains key not present "
                f"in {REFERENCE_LANGUAGE}.json: {key}"
            )

        for key in sorted(reference_keys & language_keys):
            expected = placeholders(reference[key])
            actual = placeholders(messages[key])

            if expected != actual:
                errors.append(
                    f"Placeholder mismatch for '{key}' in "
                    f"{language}.json: expected "
                    f"{sorted(expected)}, got "
                    f"{sorted(actual)}"
                )

    referenced_keys = collect_html_keys() | collect_javascript_keys()

    for key in sorted(referenced_keys):
        for language, messages in locales.items():
            if key not in messages:
                errors.append(
                    f"Referenced translation key '{key}' "
                    f"is missing from {language}.json"
                )

    if errors:
        print("i18n validation failed:\n")

        for error in errors:
            print(f"- {error}")

        return 1

    print(
        "i18n validation passed: "
        f"{len(locales)} locales, "
        f"{len(reference_keys)} keys and "
        f"{len(referenced_keys)} referenced keys."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
