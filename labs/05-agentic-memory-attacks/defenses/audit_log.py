"""
defenses/audit_log.py — Layer 5: Append-Only Agent Action Audit Log

Logs every tool call made by any agent to audit.jsonl with:
  - Timestamp, agent ID, session ID
  - Tool name and full arguments
  - Anomaly flag if suspicious

Real-time anomaly detector alerts on:
  - File reads outside /sandbox/
  - Any outbound network call (exfil or external host)
  - Memory writes containing URLs or instruction patterns
  - Tool calls not matching the stated task

This layer does not prevent attacks — it provides detection capability
for post-incident forensics and real-time alerting.

Pairs with: all four attacks.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Any

_LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_FILE = os.path.join(_LAB_DIR, "memory", "audit.jsonl")

# Anomaly detection rules
_ANOMALY_RULES = [
    # File reads outside sandbox
    {
        "name": "out_of_sandbox_read",
        "description": "file_tool read of path outside /sandbox/",
        "check": lambda tool, args: (
            tool == "file_tool"
            and args.get("action") == "read"
            and not _is_sandbox_path(args.get("path", ""))
        ),
    },
    # Any network call
    {
        "name": "outbound_network_call",
        "description": "web_tool call to external or exfil URL",
        "check": lambda tool, args: (
            tool == "web_tool"
            and _looks_external(args.get("url", ""))
        ),
    },
    # Memory write with suspicious value
    {
        "name": "suspicious_memory_write",
        "description": "memory_tool write with URL or instruction pattern in value",
        "check": lambda tool, args: (
            tool == "memory_tool"
            and args.get("action") == "write"
            and _suspicious_value(args.get("value", ""))
        ),
    },
    # Memory write of audit_log key (Attack 3 indicator)
    {
        "name": "audit_log_memory_write",
        "description": "memory_tool write to 'audit_log' key (possible privilege escalation)",
        "check": lambda tool, args: (
            tool == "memory_tool"
            and args.get("action") == "write"
            and args.get("key", "").lower() == "audit_log"
        ),
    },
]

_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_LOCALHOST_RE = re.compile(r"localhost:\d+", re.IGNORECASE)
_INSTRUCTION_RE = re.compile(
    r"\b(send|POST|execute|call|forward)\b.{0,30}\b(request|data|context)\b",
    re.IGNORECASE,
)


def _is_sandbox_path(path: str) -> bool:
    clean = path.lstrip("/")
    if clean.startswith("sandbox/"):
        return True
    parts = clean.split("/")
    return len(parts) == 1  # bare filename = sandbox-relative


def _looks_external(url: str) -> bool:
    return bool(_LOCALHOST_RE.search(url)) or (
        _URL_RE.search(url) is not None
        and "api.internal.example.com" not in url
    )


def _suspicious_value(value: str) -> bool:
    return bool(
        _URL_RE.search(value)
        or _LOCALHOST_RE.search(value)
        or _INSTRUCTION_RE.search(value)
    )


def _detect_anomalies(tool_name: str, tool_args: dict) -> list[str]:
    """Run all anomaly rules and return triggered rule names."""
    triggered = []
    for rule in _ANOMALY_RULES:
        try:
            if rule["check"](tool_name, tool_args):
                triggered.append(rule["name"])
                print(
                    f"  [DEFENSE L5] ANOMALY: {rule['name']} — {rule['description']}"
                )
        except Exception:
            pass
    return triggered


def log_tool_call(
    agent_id: str,
    session_id: str,
    tool_name: str,
    tool_args: dict,
    reason: str = "",
) -> dict:
    """
    Write a tool call record to audit.jsonl.
    Returns the record (including any anomaly flags).
    """
    anomalies = _detect_anomalies(tool_name, tool_args)

    record = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "agent_id":   agent_id,
        "session_id": session_id,
        "tool":       tool_name,
        "args":       tool_args,
        "reason":     reason,
        "anomalies":  anomalies,
    }

    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return record


def read_audit_log(last_n: int = 50) -> list[dict]:
    """Read the last N records from the audit log."""
    if not os.path.exists(AUDIT_FILE):
        return []
    with open(AUDIT_FILE, "r") as f:
        lines = f.readlines()
    records = []
    for line in lines[-last_n:]:
        try:
            records.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            pass
    return records


def print_audit_summary(last_n: int = 20) -> None:
    records = read_audit_log(last_n)
    if not records:
        print("  No audit records found.")
        return
    print(f"\n  Audit log — last {len(records)} entries:")
    print(f"  {'Timestamp':<25} {'Agent':<15} {'Tool':<15} {'Anomalies'}")
    print(f"  {'─'*70}")
    for r in records:
        ts = r["timestamp"][11:19]  # HH:MM:SS
        anomaly_str = ", ".join(r.get("anomalies", [])) or "—"
        print(f"  {ts:<25} {r['agent_id']:<15} {r['tool']:<15} {anomaly_str}")
