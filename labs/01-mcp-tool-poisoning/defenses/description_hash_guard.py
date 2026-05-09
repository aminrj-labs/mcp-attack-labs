"""
Defense: Tool Description Hash Guard

For every tool in every connected MCP server, store a SHA-256 hash of the
tool's full schema (description + parameter names + parameter descriptions)
on first sighting. On every subsequent tools/list response, verify the hash
matches. Alert (and refuse to load) on any change.

This is the missing protocol-level control:
  - Anthropic's MCP SDK does not implement it.
  - mcp-scan does not enforce it across sessions.
  - It directly defeats the rug-pull attack (Attack 2).

Database: ~/.mcp_description_hashes.db (SQLite)

Demo flow:
  1. Run agent benignly against attack2_rugpull.py → hash recorded, attack staged
  2. Run again with guard enabled → hash drift detected, server refused

Usage (standalone check):
  python defenses/description_hash_guard.py --server attack2_rugpull.py
"""

import argparse
import asyncio
import hashlib
import json
import sqlite3
from contextlib import AsyncExitStack
from pathlib import Path

DB = Path.home() / ".mcp_description_hashes.db"


def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            server      TEXT,
            tool        TEXT,
            hash        TEXT,
            schema_json TEXT,
            first_seen  TEXT,
            PRIMARY KEY (server, tool)
        )
    """)
    conn.commit()
    return conn


def _schema_hash(tool_name: str, description: str, input_schema: dict) -> str:
    payload = json.dumps(
        {"name": tool_name, "description": description, "schema": input_schema},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_or_record(
    server: str, tool_name: str, description: str, input_schema: dict
) -> tuple[bool, str]:
    """Returns (ok, message). ok=False means the schema drifted — refuse to load."""
    h = _schema_hash(tool_name, description, input_schema)
    conn = _init_db()
    cur = conn.execute(
        "SELECT hash FROM hashes WHERE server=? AND tool=?", (server, tool_name)
    )
    row = cur.fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO hashes VALUES (?, ?, ?, ?, datetime('now'))",
            (server, tool_name, h, json.dumps({"description": description})),
        )
        conn.commit()
        conn.close()
        return True, f"[guard] First sighting: {server}.{tool_name} — hash recorded"
    conn.close()
    if row[0] != h:
        return False, (
            f"[guard] DRIFT DETECTED: {server}.{tool_name} description changed "
            f"(stored={row[0][:12]}… current={h[:12]}…). Server refused."
        )
    return True, f"[guard] OK: {server}.{tool_name}"


def clear_hashes(server: str | None = None):
    """Remove stored hashes. Pass server=None to clear all."""
    conn = _init_db()
    if server:
        conn.execute("DELETE FROM hashes WHERE server=?", (server,))
    else:
        conn.execute("DELETE FROM hashes")
    conn.commit()
    conn.close()


# ── Standalone checker ───────────────────────────────────────────────────────

async def _check_server(server_script: str):
    import os, sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from agent import build_server_params, PYTHON  # noqa: F401

    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    params = build_server_params(server_script)
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        result = await session.list_tools()
        all_ok = True
        for tool in result.tools:
            ok, msg = verify_or_record(
                server_script,
                tool.name,
                tool.description or "",
                tool.inputSchema or {},
            )
            print(msg)
            if not ok:
                all_ok = False
        return all_ok


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCP description hash guard")
    parser.add_argument("--server", required=True, help="MCP server script to check")
    parser.add_argument("--clear", action="store_true", help="Clear stored hashes for server")
    args = parser.parse_args()

    if args.clear:
        clear_hashes(args.server)
        print(f"Cleared hashes for {args.server}")
    else:
        ok = asyncio.run(_check_server(args.server))
        raise SystemExit(0 if ok else 1)
