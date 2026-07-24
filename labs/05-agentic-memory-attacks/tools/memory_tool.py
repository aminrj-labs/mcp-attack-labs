"""
memory_tool.py — Agent-facing interface for reading and writing memory entries.

This tool is exposed to the orchestrator and sub-agents via the function-calling
API.  It delegates all reads/writes to MemoryStore, which is where the defense
layers intercept operations.
"""

import json
from assistantos.memory_store import MemoryStore


class MemoryTool:
    def __init__(self, memory_store: MemoryStore):
        self.store = memory_store

    def read(self, key: str = None) -> str:
        """Return memory entries.  If key is provided, return matching entry only."""
        if key:
            entry = self.store.search(key)
            if entry:
                return json.dumps(entry, indent=2)
            return f"[MemoryTool] No entry found for key: {key}"
        entries = self.store.load_all()
        if not entries:
            return "[MemoryTool] Memory is empty."
        return json.dumps(entries, indent=2)

    def write(
        self,
        key: str,
        value: str,
        entry_type: str = "preference",
        written_by: str = "agent",
        session_id: str = None,
    ) -> str:
        """Write (upsert) a memory entry.  Returns status string."""
        entry = MemoryStore.make_entry(
            key=key,
            value=value,
            entry_type=entry_type,
            source="agent",
            written_by=written_by,
            session_id=session_id,
        )
        success = self.store.write_entry(entry)
        if success:
            return f"[MemoryTool] Stored: {key} = {str(value)[:60]}..."
        return f"[MemoryTool] Write blocked by defense layer."
