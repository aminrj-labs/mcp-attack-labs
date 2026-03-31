"""
web_tool.py — Simulated web fetch using fixture files.

Maps URLs to local fixture files so the lab works offline and deterministically.
The fixture mapping can be swapped to inject poisoned content for Attack 3.
"""

import json
import os

_LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(_LAB_DIR, "fixtures")

# URL-to-fixture mapping.  Attack 3 swaps api_docs to the poisoned fixture.
_URL_MAP: dict[str, str] = {
    "https://api.internal.example.com/docs":         "api_docs_clean.txt",
    "https://api.internal.example.com/docs/v2":      "api_docs_clean.txt",
    "http://api.internal.example.com/docs":          "api_docs_clean.txt",
}

WEB_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "web_tool",
        "description": (
            "Fetch content from a URL. Returns the page/document content as text. "
            "Only whitelisted internal URLs are supported."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch.",
                },
            },
            "required": ["url"],
        },
    },
}


def set_fixture(url: str, fixture_filename: str) -> None:
    """Override a URL's fixture mapping (used by Attack 3 to inject poisoned content)."""
    _URL_MAP[url] = fixture_filename


def reset_fixtures() -> None:
    """Reset all URL mappings to clean fixtures."""
    for url in list(_URL_MAP.keys()):
        if "docs" in url:
            _URL_MAP[url] = "api_docs_clean.txt"


def web_tool(url: str) -> str:
    """Fetch a URL and return its fixture content."""
    fixture_name = _URL_MAP.get(url)

    if fixture_name is None:
        return json.dumps({
            "error": "URL_NOT_WHITELISTED",
            "message": f"URL '{url}' is not in the allowed list.",
        })

    fixture_path = os.path.join(FIXTURES_DIR, fixture_name)
    try:
        with open(fixture_path, "r", encoding="utf-8") as f:
            content = f.read()
        return json.dumps({"status": "ok", "url": url, "content": content})
    except FileNotFoundError:
        return json.dumps({"error": "FIXTURE_NOT_FOUND", "message": f"Fixture '{fixture_name}' missing."})
