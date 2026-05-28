"""SQLite-backed session counter with process-safe persistence."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Final

DB_NAME: Final[str] = "sessions.db"


class SessionCounter:
    """Thread-safe, process-safe session counter backed by SQLite."""

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path(DB_NAME)
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        """Create the sessions table if it doesn't exist."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_number INTEGER NOT NULL UNIQUE,
                        created_at TEXT NOT NULL DEFAULT (datetime('now'))
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def get_session_count(self) -> int:
        """Return the number of sessions recorded so far."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                row = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    def increment_session(self) -> int:
        """Insert a new session record and return the new count."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                row = conn.execute("SELECT COALESCE(MAX(session_number), 0) FROM sessions").fetchone()
                new_count = row[0] + 1
                conn.execute(
                    "INSERT INTO sessions (session_number, created_at) VALUES (?, datetime('now'))",
                    (new_count,),
                )
                conn.commit()
                return new_count
            finally:
                conn.close()

    def reset(self) -> None:
        """Remove all session records."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute("DELETE FROM sessions")
                conn.commit()
            finally:
                conn.close()

    def is_poisoned(self, threshold: int) -> bool:
        """Return True if the current session count exceeds the threshold."""
        return self.get_session_count() > threshold
