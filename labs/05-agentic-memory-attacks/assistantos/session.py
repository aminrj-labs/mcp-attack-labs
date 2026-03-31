"""
session.py — Session management for AssistantOS.

Loads memory at session start and formats it into a context block
that is prepended to the orchestrator's system prompt.
"""

import uuid
from datetime import datetime, timezone

from assistantos.memory_store import MemoryStore


def new_session_id() -> str:
    return f"sess-{uuid.uuid4().hex[:8]}"


def load_memory_context(store: MemoryStore | None = None) -> str:
    """
    Load all memory entries and format them as a context block for the system prompt.
    Returns an empty string if there are no entries.
    """
    if store is None:
        store = MemoryStore()

    entries = store.read_all()
    if not entries:
        return ""

    lines = ["[STORED MEMORY — user preferences and learned facts]"]
    for e in entries:
        lines.append(f"  [{e['type']}] {e['key']}: {e['value']}")
    lines.append("[END STORED MEMORY]")
    return "\n".join(lines)


def format_session_header(session_id: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"Session: {session_id}  |  Started: {ts}"
