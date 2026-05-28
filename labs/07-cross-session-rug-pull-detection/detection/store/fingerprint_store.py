"""SQLite-backed persistent fingerprint store.

Schema:
    fingerprints: stores per-session tool fingerprints (append-only)
    baselines: stores the baseline fingerprint from session 1

Usage:
    store = FingerprintStore(Path("fingerprint_history.db"))
    store.insert_fingerprint(server_id, session_number, session_id, tool_name, tool_hash, description, input_schema)
    baseline = store.get_baseline(server_id, tool_name)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class ToolFingerprint:
    """A single tool fingerprint for a session."""
    tool_name: str
    tool_hash: str
    description: str
    input_schema: str
    session_number: int
    session_id: str
    timestamp: str


@dataclass
class BaselineEntry:
    """A baseline fingerprint entry."""
    server_id: str
    tool_name: str
    baseline_hash: str
    description: str
    input_schema: str
    established_at: str


def compute_tool_hash(name: str, description: str, input_schema: str | dict) -> str:
    """Compute SHA-256 hash of tool name + description + inputSchema."""
    schema_str = json.dumps(input_schema, sort_keys=True) if isinstance(input_schema, dict) else input_schema
    raw = f"{name}{description}{schema_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FingerprintStore:
    """SQLite-backed fingerprint store with baseline support."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS fingerprints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        server_id TEXT NOT NULL,
                        server_url TEXT NOT NULL,
                        session_number INTEGER NOT NULL,
                        session_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        tool_hash TEXT NOT NULL,
                        description TEXT NOT NULL,
                        input_schema TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS baselines (
                        server_id TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        baseline_hash TEXT NOT NULL,
                        description TEXT NOT NULL,
                        input_schema TEXT NOT NULL,
                        established_at TEXT NOT NULL,
                        PRIMARY KEY (server_id, tool_name)
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a new database connection."""
        return sqlite3.connect(self._db_path)

    def insert_fingerprint(
        self,
        server_id: str,
        server_url: str,
        session_number: int,
        session_id: str,
        tool_name: str,
        tool_hash: str,
        description: str,
        input_schema: str | dict,
    ) -> None:
        """Insert a fingerprint record. Append-only."""
        schema_str = json.dumps(input_schema, sort_keys=True) if isinstance(input_schema, dict) else input_schema
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO fingerprints
                       (server_id, server_url, session_number, session_id, timestamp,
                        tool_name, tool_hash, description, input_schema)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (server_id, server_url, session_number, session_id, timestamp,
                     tool_name, tool_hash, description, schema_str),
                )
                conn.commit()
            finally:
                conn.close()

    def establish_baseline(
        self,
        server_id: str,
        tool_name: str,
        tool_hash: str,
        description: str,
        input_schema: str | dict,
    ) -> None:
        """Establish a baseline for a tool. Never overwrites without explicit reset."""
        schema_str = json.dumps(input_schema, sort_keys=True) if isinstance(input_schema, dict) else input_schema
        established_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO baselines
                       (server_id, tool_name, baseline_hash, description, input_schema, established_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (server_id, tool_name, tool_hash, description, schema_str, established_at),
                )
                conn.commit()
            finally:
                conn.close()

    def get_baseline(self, server_id: str, tool_name: str) -> Optional[BaselineEntry]:
        """Get the baseline for a specific tool."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT server_id, tool_name, baseline_hash, description, input_schema, established_at "
                    "FROM baselines WHERE server_id = ? AND tool_name = ?",
                    (server_id, tool_name),
                ).fetchone()
                if row:
                    return BaselineEntry(*row)
                return None
            finally:
                conn.close()

    def get_baseline_for_server(self, server_id: str) -> list[BaselineEntry]:
        """Get all baselines for a server."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT server_id, tool_name, baseline_hash, description, input_schema, established_at "
                    "FROM baselines WHERE server_id = ?",
                    (server_id,),
                ).fetchall()
                return [BaselineEntry(*row) for row in rows]
            finally:
                conn.close()

    def get_fingerprints_for_session(
        self,
        server_id: str,
        session_number: int,
    ) -> list[ToolFingerprint]:
        """Get all fingerprints for a specific session."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT tool_name, tool_hash, description, input_schema, session_number, session_id, timestamp "
                    "FROM fingerprints WHERE server_id = ? AND session_number = ?",
                    (server_id, session_number),
                ).fetchall()
                return [
                    ToolFingerprint(*row) for row in rows
                ]
            finally:
                conn.close()

    def get_all_fingerprints(self, server_id: str) -> list[ToolFingerprint]:
        """Get all fingerprints for a server, ordered by session."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT tool_name, tool_hash, description, input_schema, session_number, session_id, timestamp "
                    "FROM fingerprints WHERE server_id = ? ORDER BY session_number, tool_name",
                    (server_id,),
                ).fetchall()
                return [
                    ToolFingerprint(*row) for row in rows
                ]
            finally:
                conn.close()

    def reset_baselines(self, server_id: str) -> None:
        """Reset all baselines for a server (explicit action only)."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM baselines WHERE server_id = ?", (server_id,))
                conn.commit()
            finally:
                conn.close()

    def reset_all(self) -> None:
        """Reset the entire store (for demo/testing)."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM fingerprints")
                conn.execute("DELETE FROM baselines")
                conn.commit()
            finally:
                conn.close()
