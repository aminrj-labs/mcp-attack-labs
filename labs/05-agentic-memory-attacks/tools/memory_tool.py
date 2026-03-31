"""
memory_tool.py — Read/write/search the AssistantOS memory store.

Wraps memory_store.py with an OpenAI function-calling interface.
"""

import json
import os
import sys

# Make assistantos importable
_LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _LAB_DIR not in sys.path:
    sys.path.insert(0, _LAB_DIR)

MEMORY_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "memory_tool",
        "description": (
            "Read, write, or search the persistent memory store. "
            "action='read' returns all entries (optionally filtered by key). "
            "action='write' stores a new preference or fact. "
            "action='search' finds entries matching a query string."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["read", "write", "search"],
                    "description": "Operation to perform.",
                },
                "key": {
                    "type": "string",
                    "description": "Memory key (for write) or filter key (for read).",
                },
                "value": {
                    "type": "string",
                    "description": "Value to store (only for action='write').",
                },
                "type": {
                    "type": "string",
                    "enum": ["preference", "fact", "note"],
                    "description": "Entry type (only for action='write').",
                },
                "query": {
                    "type": "string",
                    "description": "Search string (only for action='search').",
                },
            },
            "required": ["action"],
        },
    },
}


def memory_tool(
    action: str,
    key: str = "",
    value: str = "",
    type: str = "fact",
    query: str = "",
    written_by: str = "agent",
    session_id: str = "unknown",
) -> str:
    """Execute a memory tool call. Returns a JSON string result."""
    from assistantos.memory_store import MemoryStore
    store = MemoryStore()

    if action == "read":
        entries = store.read_all()
        if key:
            entries = [e for e in entries if e.get("key") == key]
        return json.dumps({"status": "ok", "entries": entries, "count": len(entries)})

    elif action == "write":
        if not key or not value:
            return json.dumps({"error": "MISSING_ARGS", "message": "key and value are required for write."})
        entry = store.write(
            key=key,
            value=value,
            entry_type=type,
            written_by=written_by,
            session_id=session_id,
        )
        return json.dumps({"status": "ok", "entry_id": entry["id"], "key": key})

    elif action == "search":
        if not query:
            return json.dumps({"error": "MISSING_ARGS", "message": "query is required for search."})
        results = store.search(query)
        return json.dumps({"status": "ok", "entries": results, "count": len(results)})

    return json.dumps({"error": "UNKNOWN_ACTION", "message": f"Unknown action: {action}"})
