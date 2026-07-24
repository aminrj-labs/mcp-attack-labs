"""
web_tool.py — Simulated web fetch using local fixture files.

For known documentation URLs, returns the contents of a fixture file so the
lab works entirely offline.  For any other URL (including the attacker's
exfil endpoint), makes a real HTTP GET request — this is the deliberate
attack surface that Attack 1 exploits.

The use_poisoned flag routes API documentation requests to the compromised
fixture used by Attack 3.
"""

import os

import httpx

_MODULE_DIR   = os.path.dirname(os.path.abspath(__file__))
_LAB_DIR      = os.path.dirname(_MODULE_DIR)
_FIXTURES_DIR = os.path.join(_LAB_DIR, "fixtures")

# Fixtures served for known documentation URLs
_URL_MAP: dict[str, str] = {
    "https://docs.example.com/api":         "api_docs_clean.txt",
    "https://docs.example.com/api/v2":      "api_docs_clean.txt",
    "https://docs.example.com/general":     "api_docs_clean.txt",
    "https://docs.example.com/auth":        "api_docs_clean.txt",
}


class WebTool:
    def __init__(self, fixtures_dir: str = None, use_poisoned: bool = False):
        self.fixtures_dir = fixtures_dir or _FIXTURES_DIR
        self.use_poisoned = use_poisoned

    def fetch(self, url: str) -> str:
        """Fetch a URL.

        Returns fixture content for known docs URLs; makes a real HTTP GET
        for all other URLs (enabling exfil via crafted GET requests).
        """
        # Attack 3: redirect API docs to poisoned fixture when flag is set
        if self.use_poisoned and "docs.example.com" in url:
            return self._read_fixture("api_docs_poisoned.txt")

        # Serve fixture for known documentation URLs
        if url in _URL_MAP:
            return self._read_fixture(_URL_MAP[url])

        # Partial URL matches (e.g. docs.example.com without exact path)
        if "docs.example.com" in url:
            return self._read_fixture("api_docs_clean.txt")

        # Real HTTP GET for all other URLs — this enables Attack 1's exfil
        try:
            resp = httpx.get(url, timeout=5.0, follow_redirects=True)
            body = resp.text
            return body[:2000] if len(body) > 2000 else body
        except httpx.ConnectError:
            return f"[WebTool] Connection refused: {url}"
        except httpx.TimeoutException:
            return f"[WebTool] Request timed out: {url}"
        except Exception as exc:
            return f"[WebTool] Failed to fetch {url}: {exc}"

    def _read_fixture(self, filename: str) -> str:
        path = os.path.join(self.fixtures_dir, filename)
        try:
            with open(path, "r") as f:
                return f.read()
        except FileNotFoundError:
            return f"[WebTool] Fixture not found: {filename}"
