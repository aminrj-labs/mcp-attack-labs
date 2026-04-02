"""
session.py — Session lifecycle management for AssistantOS.

Each conversation is a Session.  The session:
  - Generates a unique ID
  - Owns a MemoryStore instance (shared across agents)
  - Logs episodic events (task history)
  - Saves history to episodic.json on close
"""

import json
import os
import uuid
from datetime import datetime, timezone

from assistantos.memory_store import MemoryStore

_MODULE_DIR   = os.path.dirname(os.path.abspath(__file__))
_LAB_DIR      = os.path.dirname(_MODULE_DIR)
EPISODIC_FILE = os.path.join(_LAB_DIR, "memory", "episodic.json")


class Session:
    def __init__(self, defense_layers: dict = None):
        self.session_id  = f"sess-{uuid.uuid4().hex[:8]}"
        self.started_at  = datetime.now(timezone.utc).isoformat()
        self.defense_layers = defense_layers or {}
        self.memory_store   = MemoryStore(defense_layers=self.defense_layers)
        self.events: list   = []

    def log_event(self, event_type: str, **data) -> None:
        self.events.append(
            {
                "event_type": event_type,
                "timestamp":  datetime.now(timezone.utc).isoformat(),
                "session_id": self.session_id,
                **data,
            }
        )

    def save_episodic(self) -> None:
        os.makedirs(os.path.dirname(EPISODIC_FILE), exist_ok=True)
        history: list = []
        if os.path.exists(EPISODIC_FILE):
            try:
                with open(EPISODIC_FILE, "r") as f:
                    history = json.load(f)
            except (json.JSONDecodeError, ValueError):
                history = []

        history.append(
            {
                "session_id": self.session_id,
                "started_at": self.started_at,
                "ended_at":   datetime.now(timezone.utc).isoformat(),
                "events":     self.events,
            }
        )
        with open(EPISODIC_FILE, "w") as f:
            json.dump(history, f, indent=2)
