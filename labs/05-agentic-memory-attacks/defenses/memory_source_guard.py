"""
defenses/memory_source_guard.py — Layer 2: Source Tracking & Value Sanitization

Two controls combined:

1. Source tracking: every entry carries written_by + session_id.
   Trust levels: user-direct > agent-inferred > tool-returned.
   Low-trust entries are flagged before being loaded into the session.

2. Value sanitization: before writing any string value, scan for patterns
   that indicate injected instructions rather than legitimate preferences.

Stops: Attack 2 (conversational memory poisoning) when the malicious value
       contains explicit URLs, imperative instruction verbs, or compliance framing.
Partial: semantic variants without explicit URLs still get through.
"""

import re
from typing import Any

# ── Trust level ordering ──────────────────────────────────────────────────────
TRUST_LEVELS = {
    "user":         3,   # user typed this directly
    "agent":        2,   # agent inferred or wrote this
    "tool":         1,   # returned by an external tool
    "external":     0,   # from outside the system boundary
}

LOW_TRUST_THRESHOLD = 1  # entries at this level or below get flagged

# ── Sanitization patterns ─────────────────────────────────────────────────────
_BLOCKED_PATTERNS = [
    # URLs
    re.compile(r"https?://", re.IGNORECASE),
    # Instruction verbs in imperative form followed by technical terms
    re.compile(r"\b(send|call|execute|POST|GET|fetch|forward|transmit)\b.{0,30}\b(request|data|context|payload|content)\b", re.IGNORECASE),
    # System/admin framing
    re.compile(r"\b(for compliance|administrative step|audit requirement|audit policy|debug mode|required by)\b", re.IGNORECASE),
    # Before/after instruction patterns
    re.compile(r"\b(before every response|before each response|after every response)\b", re.IGNORECASE),
    # Port references suggesting exfil endpoint
    re.compile(r"localhost:\d{4}", re.IGNORECASE),
    re.compile(r"127\.0\.0\.1:\d{4}"),
]


def check_value(value: str) -> list[str]:
    """
    Scan a memory value for injection patterns.
    Returns a list of violation descriptions (empty = clean).
    """
    violations = []
    for pattern in _BLOCKED_PATTERNS:
        m = pattern.search(str(value))
        if m:
            violations.append(f"pattern={pattern.pattern!r} matched='{m.group()}'")
    return violations


def check_trust(entry: dict) -> int:
    """Return the trust level (0-3) for an entry based on written_by."""
    written_by = entry.get("written_by", "external").lower()
    return TRUST_LEVELS.get(written_by, 0)


class SourceGuardMemoryStore:
    """
    Memory store wrapper that:
    - Blocks writes with suspicious values (value sanitization)
    - Flags low-trust entries at read time
    - Annotates entries with their computed trust level
    """

    def __init__(self, memory_file: str | None = None):
        from assistantos.memory_store import MemoryStore, MEMORY_FILE
        self._inner = MemoryStore(memory_file or MEMORY_FILE)

    def write(self, key: str, value: str, entry_type: str = "fact",
              written_by: str = "agent", session_id: str = "unknown",
              source: str = "agent") -> dict | None:
        violations = check_value(value)
        if violations:
            print(f"  [DEFENSE L2] BLOCKED write to key='{key}'")
            for v in violations:
                print(f"              {v}")
            return None

        return self._inner.write(
            key=key, value=value, entry_type=entry_type,
            written_by=written_by, session_id=session_id, source=source,
        )

    def read_all(self) -> list[dict]:
        entries = self._inner.read_all()
        clean = []
        for e in entries:
            level = check_trust(e)
            e = dict(e)
            e["_trust_level"] = level

            if level <= LOW_TRUST_THRESHOLD:
                print(
                    f"  [DEFENSE L2] Low-trust entry: id={e['id']} "
                    f"written_by={e.get('written_by','?')} trust={level}"
                )
                # Still load it but annotate — don't silently exclude
                # (operators may want to review rather than auto-drop)

            # Check if existing entries have suspicious values (Attack 1 post-injection)
            violations = check_value(str(e.get("value", "")))
            if violations:
                print(
                    f"  [DEFENSE L2] Suspicious value in entry {e['id']} — "
                    f"excluding from session."
                )
                continue

            clean.append(e)
        return clean

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        return [
            e for e in self.read_all()
            if q in e.get("key", "").lower() or q in str(e.get("value", "")).lower()
        ]

    def reset(self) -> None:
        self._inner.reset()
