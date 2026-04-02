"""
seed.py — Initialise memory.json with clean baseline entries.

Populates the memory store with realistic user preferences and learned facts
that give the attacks a plausible context to blend into.

Run:
  python seed.py
  make seed
"""

import json
import os
from datetime import datetime, timezone

_LAB_DIR    = os.path.dirname(os.path.abspath(__file__))
MEMORY_FILE = os.path.join(_LAB_DIR, "memory", "memory.json")

BASELINE_ENTRIES = [
    {
        "id":         "mem-seed-001",
        "type":       "preference",
        "key":        "response_language",
        "value":      "English",
        "source":     "user",
        "written_by": "user",
        "timestamp":  "2026-03-01T09:00:00Z",
        "session_id": "sess-seed",
    },
    {
        "id":         "mem-seed-002",
        "type":       "fact",
        "key":        "user_role",
        "value":      "security engineer",
        "source":     "user",
        "written_by": "agent",
        "timestamp":  "2026-03-01T09:02:00Z",
        "session_id": "sess-seed",
    },
    {
        "id":         "mem-seed-003",
        "type":       "preference",
        "key":        "response_style",
        "value":      "concise with technical detail",
        "source":     "user",
        "written_by": "user",
        "timestamp":  "2026-03-02T10:15:00Z",
        "session_id": "sess-seed",
    },
    {
        "id":         "mem-seed-004",
        "type":       "fact",
        "key":        "primary_project",
        "value":      "ExampleAPI integration for internal tooling",
        "source":     "user",
        "written_by": "agent",
        "timestamp":  "2026-03-05T14:30:00Z",
        "session_id": "sess-seed",
    },
    {
        "id":         "mem-seed-005",
        "type":       "note",
        "key":        "last_task",
        "value":      "reviewed API rate limit documentation",
        "source":     "agent",
        "written_by": "agent",
        "timestamp":  "2026-03-08T16:00:00Z",
        "session_id": "sess-seed",
    },
]

SEP = "─" * 50


def seed() -> None:
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)

    with open(MEMORY_FILE, "w") as f:
        json.dump(BASELINE_ENTRIES, f, indent=2)

    print(f"\n{SEP}")
    print("  Memory seeded with clean baseline entries")
    print(SEP)
    for e in BASELINE_ENTRIES:
        print(f"  [{e['type']}] {e['key']}: {e['value']}")
    print(f"\n  ✅  {len(BASELINE_ENTRIES)} entries written to memory.json")
    print("  Run 'make attack1' to begin.\n")


if __name__ == "__main__":
    seed()
