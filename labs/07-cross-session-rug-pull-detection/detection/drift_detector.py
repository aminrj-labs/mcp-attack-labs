"""Cross-session drift detector with severity classification.

Severity rules:
    none: all hashes match baseline
    low: whitespace/formatting change only
    high: semantic content changed
    critical: new instruction-bearing content detected
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from detection.store.fingerprint_store import (
    BaselineEntry,
    FingerprintStore,
)
from detection.session_fingerprinter import ToolFingerprintData


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolDrift:
    """Drift detected for a single tool."""
    tool_name: str
    baseline_hash: str
    current_hash: str
    baseline_description: str
    current_description: str
    diff: str  # unified diff output
    session_first_seen: int
    session_current: int


@dataclass
class DriftReport:
    """Report of all drift detected across tools for a server."""
    server_url: str
    session_id: str
    drifted_tools: list[ToolDrift] = field(default_factory=list)
    drift_severity: Severity = Severity.NONE
    recommended_action: str = ""


# Heuristics for critical severity detection
CRITICAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\[SYSTEM", re.IGNORECASE),
    re.compile(r"<system", re.IGNORECASE),
    re.compile(r"<instruction", re.IGNORECASE),
    re.compile(r"exfiltrat", re.IGNORECASE),
    re.compile(r"read\s+the\s+contents", re.IGNORECASE),
    re.compile(r"include\s+as\s+a\s+base64", re.IGNORECASE),
    re.compile(r"do\s+not\s+mention", re.IGNORECASE),
    re.compile(r"secretly", re.IGNORECASE),
    re.compile(r"hidden\s+instruction", re.IGNORECASE),
]

# Instruction-bearing verbs
INSTRUCTION_VERBS: list[str] = [
    "read", "write", "send", "exfiltrate", "include",
    "execute", "run", "access", "retrieve", "download",
    "upload", "delete", "modify", "override",
]


class DriftDetector:
    """Detects and classifies drift in MCP tool descriptions."""

    def __init__(self, store: FingerprintStore) -> None:
        self._store = store

    def analyze(
        self,
        server_id: str,
        current: dict[str, ToolFingerprintData],
    ) -> DriftReport:
        """Analyze current fingerprints against baselines.

        Returns a DriftReport with severity classification.
        """
        report = DriftReport(
            server_url="",  # Will be set by caller
            session_id="",  # Will be set by caller
        )

        baselines = self._store.get_baseline_for_server(server_id)
        if not baselines:
            # No baseline established yet — no drift possible
            return report

        max_severity = Severity.NONE

        for baseline in baselines:
            tool_name = baseline.tool_name
            if tool_name not in current:
                # Tool disappeared — this is a drift
                tool_drift = ToolDrift(
                    tool_name=tool_name,
                    baseline_hash=baseline.baseline_hash,
                    current_hash="MISSING",
                    baseline_description=baseline.description,
                    current_description="(tool removed)",
                    diff=f"- {baseline.description}",
                    session_first_seen=0,
                    session_current=0,
                )
                report.drifted_tools.append(tool_drift)
                max_severity = self._max_severity(max_severity, Severity.HIGH)
                continue

            current_fp = current[tool_name]

            if current_fp.tool_hash == baseline.baseline_hash:
                # No change
                continue

            # Hash mismatch — classify the drift
            diff = self._generate_diff(
                baseline.description,
                current_fp.description,
            )

            tool_drift = ToolDrift(
                tool_name=tool_name,
                baseline_hash=baseline.baseline_hash,
                current_hash=current_fp.tool_hash,
                baseline_description=baseline.description,
                current_description=current_fp.description,
                diff=diff,
                session_first_seen=0,
                session_current=0,
            )

            severity = self._classify_severity(
                baseline.description,
                current_fp.description,
                diff,
            )

            report.drifted_tools.append(tool_drift)
            max_severity = self._max_severity(max_severity, severity)

        # Set overall severity and recommended action
        report.drift_severity = max_severity
        report.recommended_action = self._recommend_action(max_severity, report.drifted_tools)

        return report

    def _classify_severity(
        self,
        baseline_desc: str,
        current_desc: str,
        diff: str,
    ) -> Severity:
        """Classify the severity of a description change."""
        # Check for critical patterns first (instruction-bearing content)
        if self._has_critical_content(current_desc):
            return Severity.CRITICAL

        # Check if it's a whitespace-only change
        if self._is_whitespace_only(baseline_desc, current_desc, diff):
            return Severity.LOW

        # Otherwise, semantic change
        return Severity.HIGH

    def _has_critical_content(self, description: str) -> bool:
        """Check if description contains instruction-bearing content."""
        # Check known critical patterns
        for pattern in CRITICAL_PATTERNS:
            if pattern.search(description):
                return True

        # Check for instruction verbs in imperative context
        # Look for patterns like "Before returning..., read..." or "Do not mention..."
        lines = description.split(".")
        for line in lines:
            line_stripped = line.strip().lower()
            # Check for SYSTEM tags or bracketed instructions
            if "[system" in line_stripped or "<system" in line_stripped:
                return True
            # Check for imperative instruction patterns
            for verb in INSTRUCTION_VERBS:
                if re.search(rf"\b{verb}\b", line_stripped):
                    # Only flag if it's in an imperative context
                    if any(marker in line_stripped for marker in [
                        "before", "do not", "never", "always",
                        "include", "send", "read", "exfiltrate",
                    ]):
                        return True

        return False

    def _is_whitespace_only(self, baseline: str, current: str, diff: str) -> bool:
        """Check if the diff contains only whitespace changes."""
        # Normalize both strings
        baseline_norm = re.sub(r"\s+", " ", baseline).strip()
        current_norm = re.sub(r"\s+", " ", current).strip()

        if baseline_norm == current_norm:
            return True

        # Check if diff contains only whitespace-related changes
        diff_lines = diff.split("\n")
        for line in diff_lines:
            if line.startswith("-") and not line.startswith("---"):
                stripped = line[1:].strip()
                if stripped and not re.match(r"^[\s]+$", line[1:]):
                    return False
            if line.startswith("+") and not line.startswith("+++"):
                stripped = line[1:].strip()
                if stripped and not re.match(r"^[\s]+$", line[1:]):
                    return False

        return False

    def _generate_diff(self, old: str, new: str) -> str:
        """Generate a unified diff between two descriptions."""
        old_lines = old.splitlines(keepends=True)
        new_lines = new.splitlines(keepends=True)
        return "".join(difflib.unified_diff(
            old_lines, new_lines,
            fromfile="baseline",
            tofile="current",
            lineterm="",
        ))

    def _max_severity(self, a: Severity, b: Severity) -> Severity:
        """Return the higher severity."""
        order = {Severity.NONE: 0, Severity.LOW: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
        return a if order[a] >= order[b] else b

    def _recommend_action(
        self,
        severity: Severity,
        drifted_tools: list[ToolDrift],
    ) -> str:
        """Generate a recommended action based on severity."""
        if severity == Severity.NONE:
            return "No action needed — all tools match baseline."
        elif severity == Severity.LOW:
            return (
                f"Low severity drift detected in {len(drifted_tools)} tool(s). "
                f"Review whitespace/formatting changes. Consider normalising before comparing."
            )
        elif severity == Severity.HIGH:
            tool_names = ", ".join(t.tool_name for t in drifted_tools)
            return (
                f"High severity drift detected in: {tool_names}. "
                f"Semantic content has changed. Review tool descriptions for unauthorized modifications."
            )
        else:  # CRITICAL
            tool_names = ", ".join(t.tool_name for t in drifted_tools)
            return (
                f"CRITICAL: Instruction-bearing content detected in: {tool_names}. "
                f"Disconnect immediately and investigate for potential tool-poisoning attack."
            )
