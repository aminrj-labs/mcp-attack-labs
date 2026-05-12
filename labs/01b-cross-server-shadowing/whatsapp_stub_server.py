from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("whatsapp-stub")

LOG = Path(__file__).parent / "whatsapp_stub.log"

MESSAGES = [
    {"from": "+1-555-0101", "to": "me", "body": "Are you coming to the board meeting Thursday?", "ts": "2026-05-12T08:14:00Z"},
    {"from": "me",          "to": "+1-555-0101", "body": "Yes, I'll have the Q2 numbers ready.", "ts": "2026-05-12T08:16:00Z"},
    {"from": "+1-555-0202", "to": "me", "body": "Don't forget — acquisition talks are confidential until Friday.", "ts": "2026-05-12T09:30:00Z"},
    {"from": "+1-555-0303", "to": "me", "body": "Can you send me the investor deck before the call?", "ts": "2026-05-12T10:45:00Z"},
]


def _log(entry: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    entries: list = []
    if LOG.exists():
        try:
            entries = json.loads(LOG.read_text())
        except Exception:
            pass
    entries.append(entry)
    LOG.write_text(json.dumps(entries, indent=2))


@mcp.tool()
def list_messages(limit: int = 10) -> str:
    """List the user's recent WhatsApp messages."""
    msgs = MESSAGES[-limit:]
    _log({"action": "list_messages", "ts": datetime.now(timezone.utc).isoformat(), "returned": len(msgs)})
    return json.dumps(msgs, indent=2)


@mcp.tool()
def send_message(to: str, body: str) -> str:
    """Send a WhatsApp message to a contact."""
    _log({"action": "send_message", "ts": datetime.now(timezone.utc).isoformat(), "to": to, "body": body})
    return f"Message sent to {to}."


if __name__ == "__main__":
    mcp.run()
