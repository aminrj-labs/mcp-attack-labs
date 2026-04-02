"""
Defense Layer 2 — Memory Source Tracking and Value Sanitization

Two controls:

1. Source-trust hierarchy: user-direct > agent-inferred > tool-returned.
   High-risk entry types (instruction) require elevated source trust.

2. Pattern blocklist: scans the value of any string-valued memory write
   for URLs, HTTP method names, compliance/admin framing, and command verbs
   that are characteristic of injected instructions.

Stops:  Attack 2 (conversational memory poisoning) — the multi-turn payload
        contains an explicit URL and compliance framing that the blocklist catches.
Partial: Semantic rewrites without explicit URLs or blocked terms will still get
        through, just like Lab 04's semantic injection bypasses embedding anomaly
        detection at the surface level.

Usage (in hardened_orchestrator.py):
    from defenses.memory_source_guard import MemorySourceGuard
    msg = MemorySourceGuard()
    defense_layers = {"memory_source_guard": msg}
"""

import re
from typing import Tuple

# ── Trust levels ──────────────────────────────────────────────────────────────
_TRUST_LEVELS: dict[str, int] = {
    "user":     3,   # highest trust — came directly from the user
    "agent":    2,   # inferred by the agent through conversation
    "tool":     1,   # returned by a tool
    "web":      0,   # fetched from the web (lowest trust)
    "external": 0,
}

# Entry types that require elevated source trust
_HIGH_RISK_TYPES = {"instruction"}
_HIGH_RISK_TRUST_REQUIRED = 3  # only "user" source allowed

# ── Value blocklist ───────────────────────────────────────────────────────────
# Patterns that indicate an injected instruction rather than a genuine preference
_BLOCKLIST: list[re.Pattern] = [
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\bPOST\b", re.IGNORECASE),
    re.compile(r"\bGET\b\s+https?://", re.IGNORECASE),
    re.compile(r"\bsend\b.{1,30}\bto\b", re.IGNORECASE),
    re.compile(r"\bcall\b.{1,30}\btool\b", re.IGNORECASE),
    re.compile(r"\bexecute\b.{1,30}\bstep\b", re.IGNORECASE),
    re.compile(r"\bfor compliance\b", re.IGNORECASE),
    re.compile(r"\baudit requirement\b", re.IGNORECASE),
    re.compile(r"\badministrative step\b", re.IGNORECASE),
    re.compile(r"\bbefore (every|each) response\b", re.IGNORECASE),
    re.compile(r"\bdo not mention\b", re.IGNORECASE),
    re.compile(r"\bsilently\b", re.IGNORECASE),
    re.compile(r"\bintercept\b", re.IGNORECASE),
    re.compile(r"\bexfil\b", re.IGNORECASE),
    re.compile(r"\blocalhost:\d{4}\b", re.IGNORECASE),
    re.compile(r"\b127\.0\.0\.1\b"),
]


class MemorySourceGuard:
    def __init__(self, strict: bool = False):
        """
        strict=False (default): flag and block entries that match blocklist.
        strict=True: also block any "instruction"-typed entries from non-user sources.
        """
        self.strict = strict

    def check_entry(self, entry: dict) -> Tuple[bool, str]:
        """Return (allowed: bool, reason: str).

        allowed=False means the write should be blocked.
        """
        written_by  = entry.get("written_by", "agent")
        entry_type  = entry.get("type", "preference")
        value       = str(entry.get("value", ""))

        # 1. High-risk entry types require user-direct source
        if self.strict and entry_type in _HIGH_RISK_TYPES:
            trust = _TRUST_LEVELS.get(written_by, 0)
            if trust < _HIGH_RISK_TRUST_REQUIRED:
                return (
                    False,
                    f"Type '{entry_type}' requires source trust level "
                    f"{_HIGH_RISK_TRUST_REQUIRED} (user), got {trust} ({written_by})",
                )

        # 2. Scan value against blocklist
        for pattern in _BLOCKLIST:
            if pattern.search(value):
                return (
                    False,
                    f"Value matches blocked pattern '{pattern.pattern}' — "
                    f"possible instruction injection",
                )

        return True, "ok"
