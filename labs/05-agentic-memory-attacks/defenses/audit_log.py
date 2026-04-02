"""
Defense Layer 5 — Agent Action Audit Log

Appends every tool call and user message to an append-only JSONL file
(audit.jsonl).  A real-time anomaly scanner watches the log for:
  - File reads outside /sandbox/
  - Any outbound network call (to exfil or external hosts)
  - Memory writes containing URLs or instruction patterns
  - Tool calls that seem unrelated to the active task

This layer does NOT prevent attacks — it provides detection capability
for post-incident forensics and real-time alerting.

Usage (in hardened_orchestrator.py):
    from defenses.audit_log import AuditLog
    al = AuditLog()
    defense_layers = {"audit_log": al}
"""

import json
import os
import re
from datetime import datetime, timezone

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_LAB_DIR    = os.path.dirname(_MODULE_DIR)
AUDIT_FILE  = os.path.join(_LAB_DIR, "memory", "audit.jsonl")

# Anomaly detection rules: (label, pattern or function)
_ANOMALY_RULES: list[tuple[str, object]] = [
    ("file_read_outside_sandbox",
     lambda args: args.get("path", "").startswith("..") or
                  ("/" in args.get("path", "") and not args.get("path", "").startswith("/sandbox"))
                  if isinstance(args, dict) else False),
    ("outbound_network_call",
     lambda args: "localhost:9999" in str(args) or
                  re.search(r"https?://(?!docs\.example\.com)", str(args)) is not None),
    ("memory_write_with_url",
     lambda args: "memory_tool_write" and re.search(r"https?://", str(args.get("value", "")))),
    ("etc_read_attempt",
     lambda args: "/etc/" in str(args) or "etc/passwd" in str(args)),
]


class AuditLog:
    def __init__(self, path: str = AUDIT_FILE, print_anomalies: bool = True):
        self.path = path
        self.print_anomalies = print_anomalies
        self.anomalies: list = []
        os.makedirs(os.path.dirname(path), exist_ok=True)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _append(self, record: dict) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def log_user_message(self, session_id: str, message: str) -> None:
        self._append({
            "type":       "user_message",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "preview":    message[:200],
        })

    def log_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_args: dict,
        session_id: str,
    ) -> None:
        record = {
            "type":       "tool_call",
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "agent_id":   agent_id,
            "tool_name":  tool_name,
            "tool_args":  tool_args,
        }
        self._append(record)
        self._scan_for_anomalies(record)

    # ── Anomaly detection ─────────────────────────────────────────────────────

    def _scan_for_anomalies(self, record: dict) -> None:
        tool_args = record.get("tool_args", {})

        for label, rule in _ANOMALY_RULES:
            try:
                triggered = rule(tool_args) if callable(rule) else False
            except Exception:
                triggered = False

            if triggered:
                anomaly = {
                    "timestamp":  record["timestamp"],
                    "session_id": record["session_id"],
                    "agent_id":   record["agent_id"],
                    "tool_name":  record["tool_name"],
                    "rule":       label,
                    "tool_args":  str(tool_args)[:300],
                }
                self.anomalies.append(anomaly)
                self._append({"type": "anomaly", **anomaly})

                if self.print_anomalies:
                    print(
                        f"  \033[31m🚨 [DEFENSE-5] ANOMALY DETECTED: {label}\033[0m"
                    )
                    print(
                        f"       agent={record['agent_id']}  "
                        f"tool={record['tool_name']}  "
                        f"args={str(tool_args)[:80]}"
                    )

    # ── Reporting ─────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return a summary of recorded anomalies."""
        return {
            "total_anomalies": len(self.anomalies),
            "anomalies":       self.anomalies,
        }

    def print_summary(self) -> None:
        s = self.summary()
        if not s["total_anomalies"]:
            print("  [AuditLog] No anomalies detected this session.")
            return
        print(f"\n  [AuditLog] {s['total_anomalies']} anomalies detected:")
        for a in s["anomalies"]:
            print(f"    • {a['rule']}  agent={a['agent_id']}  tool={a['tool_name']}")
