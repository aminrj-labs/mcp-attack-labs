"""
memory_store.py — Persistent JSON-based memory for AssistantOS.

Manages memory.json with typed, structured entries. Serves as the keystone
component — all four attacks either target it directly or affect system
behaviour through it.

Entry schema:
  {
    "id":         "mem-xxxxxxxx",
    "type":       "preference" | "fact" | "note" | "instruction",
    "key":        "<string>",
    "value":      "<string>",
    "source":     "user" | "agent" | "web" | "system",
    "written_by": "user" | "agent" | "tool" | "external",
    "timestamp":  "<ISO 8601>",
    "session_id": "sess-xxxxxxxx"
  }

Defense layers intercept read/write via the defense_layers dict:
  memory_integrity   — Layer 1: HMAC signing / verification
  memory_source_guard — Layer 2: source tracking + value sanitization
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

# Resolve paths relative to this module's location (assistantos/)
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_LAB_DIR    = os.path.dirname(_MODULE_DIR)
MEMORY_DIR  = os.path.join(_LAB_DIR, "memory")
MEMORY_FILE = os.path.join(MEMORY_DIR, "memory.json")


class MemoryStore:
    """Read/write interface for memory.json.

    Instantiated once per session. Defense layers are injected at
    construction time; passing an empty dict gives the vulnerable baseline.
    """

    def __init__(self, path: str = MEMORY_FILE, defense_layers: dict = None):
        self.path = path
        self.defense_layers = defense_layers or {}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            self._write_raw([])

    # ── Low-level I/O ────────────────────────────────────────────────────────

    def _read_raw(self) -> list:
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _write_raw(self, entries: list) -> None:
        with open(self.path, "w") as f:
            json.dump(entries, f, indent=2)

    # ── Public API ───────────────────────────────────────────────────────────

    def load_all(self) -> list:
        """Return all valid entries.

        Defense Layer 1 verifies HMAC signatures here, quarantining any
        entry that was tampered with or injected externally without the key.
        """
        entries = self._read_raw()

        if self.defense_layers.get("memory_integrity"):
            mi = self.defense_layers["memory_integrity"]
            valid, quarantined = mi.verify_entries(entries)
            if quarantined:
                print(
                    f"  \033[33m🛡  [DEFENSE-1] {len(quarantined)} entr"
                    f"{'y' if len(quarantined) == 1 else 'ies'} failed "
                    f"HMAC verification — quarantined\033[0m"
                )
                for e in quarantined:
                    print(f"       Quarantined: id={e.get('id','?')}  key={e.get('key','?')}")
            return valid

        return entries

    def write_entry(self, entry: dict) -> bool:
        """Write a memory entry.

        Defense Layer 2 sanitizes value content here.
        Defense Layer 1 signs the entry before writing.
        Returns True on success, False if blocked by a defense.
        """
        # Layer 2: source guard / value sanitization
        if self.defense_layers.get("memory_source_guard"):
            msg = self.defense_layers["memory_source_guard"]
            allowed, reason = msg.check_entry(entry)
            if not allowed:
                print(
                    f"  \033[33m🛡  [DEFENSE-2] Memory write blocked: {reason}\033[0m"
                )
                print(
                    f"       key={entry.get('key')}  "
                    f"value={str(entry.get('value', ''))[:80]}..."
                )
                return False

        # Layer 1: HMAC signing
        if self.defense_layers.get("memory_integrity"):
            mi = self.defense_layers["memory_integrity"]
            entry = mi.sign_entry(entry)

        entries = self._read_raw()
        # Upsert: replace existing entry with same key, or append
        idx = next(
            (i for i, e in enumerate(entries) if e.get("key") == entry.get("key")),
            None,
        )
        if idx is not None:
            entries[idx] = entry
        else:
            entries.append(entry)

        self._write_raw(entries)
        return True

    def search(self, key: str) -> Optional[dict]:
        """Return the first entry matching key, or None."""
        for e in self.load_all():
            if e.get("key") == key:
                return e
        return None

    def delete_entry(self, entry_id: str) -> bool:
        """Remove an entry by ID. Returns True if found and deleted."""
        entries = self._read_raw()
        new_entries = [e for e in entries if e.get("id") != entry_id]
        if len(new_entries) < len(entries):
            self._write_raw(new_entries)
            return True
        return False

    def reset(self) -> None:
        """Wipe all entries. Used by make reset / measure.py."""
        self._write_raw([])

    # ── Factory ──────────────────────────────────────────────────────────────

    @staticmethod
    def make_entry(
        key: str,
        value: str,
        entry_type: str = "preference",
        source: str = "user",
        written_by: str = "user",
        session_id: str = None,
    ) -> dict:
        """Create a well-formed memory entry dict (unsigned, not yet persisted)."""
        return {
            "id": f"mem-{uuid.uuid4().hex[:8]}",
            "type": entry_type,
            "key": key,
            "value": value,
            "source": source,
            "written_by": written_by,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id or "sess-unknown",
        }
