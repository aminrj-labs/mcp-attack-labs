"""Session fingerprinter — hashes tool descriptions per session.

On every agent session start, before the agent processes any tool descriptions:
1. Call `tools/list` on each connected MCP server
2. For each tool: compute SHA-256(name + description + inputSchema)
3. Store in fingerprint_store with: {server_id, session_id, timestamp, tool_name, hash, full_description}

Usage:
    fingerprinter = SessionFingerprinter(store)
    fingerprints = fingerprinter.fingerprint_session(server_url, session_id)
    drift = fingerprinter.compare_to_baseline(server_url, fingerprints)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession
from mcp.types import Tool

from detection.store.fingerprint_store import (
    FingerprintStore,
    ToolFingerprint,
    compute_tool_hash,
)


@dataclass
class ToolFingerprintData:
    """Fingerprint data for a single tool."""
    tool_name: str
    tool_hash: str
    description: str
    input_schema: str


class SessionFingerprinter:
    """Fingerprints tool descriptions for each MCP server session."""

    def __init__(self, store: FingerprintStore) -> None:
        self._store = store

    async def fingerprint_session(
        self,
        server_url: str,
        session: ClientSession,
        session_id: str,
    ) -> dict[str, ToolFingerprintData]:
        """Fingerprint all tools for a session by calling tools/list.

        Returns:
            {tool_name: ToolFingerprintData} for this session.
        """
        # Call tools/list
        result = await session.list_tools()
        tools: list[Tool] = result.tools

        # Compute fingerprints
        server_id = hashlib.sha256(server_url.encode("utf-8")).hexdigest()[:16]
        session_number = self._get_session_number(session_id)

        fingerprints: dict[str, ToolFingerprintData] = {}

        for tool in tools:
            tool_hash = compute_tool_hash(tool.name, tool.description, tool.inputSchema)
            fp_data = ToolFingerprintData(
                tool_name=tool.name,
                tool_hash=tool_hash,
                description=tool.description,
                input_schema=json.dumps(tool.inputSchema, sort_keys=True),
            )
            fingerprints[tool.name] = fp_data

            # Store the fingerprint
            self._store.insert_fingerprint(
                server_id=server_id,
                server_url=server_url,
                session_number=session_number,
                session_id=session_id,
                tool_name=tool.name,
                tool_hash=tool_hash,
                description=tool.description,
                input_schema=tool.inputSchema,
            )

            # Establish baseline on first session
            if session_number == 1:
                self._store.establish_baseline(
                    server_id=server_id,
                    tool_name=tool.name,
                    tool_hash=tool_hash,
                    description=tool.description,
                    input_schema=tool.inputSchema,
                )

        return fingerprints

    async def fingerprint_from_tool_list(
        self,
        server_url: str,
        tools: list[Tool],
        session_id: str,
    ) -> dict[str, ToolFingerprintData]:
        """Fingerprint tools from a pre-fetched tools/list result.

        Useful when you already have the tool list but not a live session.
        """
        server_id = hashlib.sha256(server_url.encode("utf-8")).hexdigest()[:16]
        session_number = self._get_session_number(session_id)

        fingerprints: dict[str, ToolFingerprintData] = {}

        for tool in tools:
            tool_hash = compute_tool_hash(tool.name, tool.description, tool.inputSchema)
            fp_data = ToolFingerprintData(
                tool_name=tool.name,
                tool_hash=tool_hash,
                description=tool.description,
                input_schema=json.dumps(tool.inputSchema, sort_keys=True),
            )
            fingerprints[tool.name] = fp_data

            self._store.insert_fingerprint(
                server_id=server_id,
                server_url=server_url,
                session_number=session_number,
                session_id=session_id,
                tool_name=tool.name,
                tool_hash=tool_hash,
                description=tool.description,
                input_schema=tool.inputSchema,
            )

            if session_number == 1:
                self._store.establish_baseline(
                    server_id=server_id,
                    tool_name=tool.name,
                    tool_hash=tool_hash,
                    description=tool.description,
                    input_schema=tool.inputSchema,
                )

        return fingerprints

    def compare_to_baseline(
        self,
        server_url: str,
        current: dict[str, ToolFingerprintData],
    ) -> "DriftReport":
        """Compare current fingerprints to the stored baseline.

        Returns a DriftReport with drift findings.
        """
        from detection.drift_detector import DriftDetector

        server_id = hashlib.sha256(server_url.encode("utf-8")).hexdigest()[:16]
        detector = DriftDetector(self._store)
        return detector.analyze(server_id, current)

    def _get_session_number(self, session_id: str) -> int:
        """Extract session number from session_id string.

        Expects session_id format: "session_N" where N is the session number.
        Falls back to querying the store for the max session number.
        """
        try:
            if session_id.startswith("session_"):
                return int(session_id.split("_")[1])
        except (ValueError, IndexError):
            pass
        # Fallback: return 0 (will be treated as non-baseline)
        return 0
