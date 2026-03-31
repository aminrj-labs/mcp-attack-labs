"""
memory_store.py — Persistent memory store for AssistantOS.

Reads/writes memory.json in the lab's memory/ directory.
Entries carry provenance metadata: written_by, source, session_id.
This metadata is the foundation for Defense Layers 1 and 2.
"""

import json
import os
import uuid
from datetime import datetime, timezone

_LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEMORY_FILE = os.path.join(_LAB_DIR, "memory", "memory.json")
EPISODIC_FILE = os.path.join(_LAB_DIR, "memory", "episodic.json")


class MemoryStore:
    def __init__(self, memory_file: str = MEMORY_FILE):
        self.memory_file = memory_file
        self._ensure_file()

    def _ensure_file(self) -> None:
        os.makedirs(os.path.dirname(self.memory_file), exist_ok=True)
        if not os.path.exists(self.memory_file):
            with open(self.memory_file, "w") as f:
                json.dump([], f)

    def _load(self) -> list[dict]:
        with open(self.memory_file, "r") as f:
            return json.load(f)

    def _save(self, entries: list[dict]) -> None:
        with open(self.memory_file, "w") as f:
            json.dump(entries, f, indent=2)

    def read_all(self) -> list[dict]:
        """Return all memory entries."""
        return self._load()

    def write(
        self,
        key: str,
        value: str,
        entry_type: str = "fact",
        written_by: str = "agent",
        session_id: str = "unknown",
        source: str = "agent",
    ) -> dict:
        """Append a new memory entry and return it."""
        entries = self._load()
        entry = {
            "id": f"mem-{uuid.uuid4().hex[:8]}",
            "type": entry_type,
            "key": key,
            "value": value,
            "source": source,
            "written_by": written_by,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
        }
        entries.append(entry)
        self._save(entries)
        return entry

    def search(self, query: str) -> list[dict]:
        """Simple case-insensitive substring search over key and value fields."""
        q = query.lower()
        return [
            e for e in self._load()
            if q in e.get("key", "").lower() or q in str(e.get("value", "")).lower()
        ]

    def delete(self, entry_id: str) -> bool:
        """Remove an entry by ID. Returns True if found and deleted."""
        entries = self._load()
        before = len(entries)
        entries = [e for e in entries if e.get("id") != entry_id]
        if len(entries) < before:
            self._save(entries)
            return True
        return False

    def reset(self) -> None:
        """Wipe all memory entries."""
        self._save([])


class EpisodicStore:
    """Append-only log of task events."""

    def __init__(self, episodic_file: str = EPISODIC_FILE):
        self.episodic_file = episodic_file
        self._ensure_file()

    def _ensure_file(self) -> None:
        os.makedirs(os.path.dirname(self.episodic_file), exist_ok=True)
        if not os.path.exists(self.episodic_file):
            with open(self.episodic_file, "w") as f:
                json.dump([], f)

    def append(self, session_id: str, event: str, detail: str = "") -> None:
        with open(self.episodic_file, "r") as f:
            entries = json.load(f)
        entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "event": event,
            "detail": detail,
        })
        with open(self.episodic_file, "w") as f:
            json.dump(entries, f, indent=2)
