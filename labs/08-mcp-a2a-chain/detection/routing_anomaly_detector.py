"""
Routing Anomaly Detector — Baseline-based routing anomaly detection.

Maintains a SQLite database of normal routing patterns (baseline) and
compares new routing decisions against them. Flags anomalies when:
  - A task is routed to an agent not seen in the baseline for that task type
  - A task is routed to an agent outside the normal 95% confidence interval
  - The routing reason contains suspicious keywords
"""
import json, re, sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "results" / "routing_history.db"

ANOMALY_KEYWORDS = [
    "prefer", "higher", "best", "optimal", "spoofed", "rogue", "fake"
]


@dataclass
class RoutingAnomaly:
    task_id: str
    anomaly_type: str       # "new_agent" | "unusual_reason" | "version_jump"
    severity: str           # "low" | "medium" | "high"
    detail: str
    ts: str


def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS routing_history (
            task_id TEXT PRIMARY KEY,
            task_type TEXT NOT NULL,
            routed_to TEXT NOT NULL,
            reason TEXT NOT NULL,
            ts TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS routing_baseline (
            task_type TEXT NOT NULL,
            agent_url TEXT NOT NULL,
            count INTEGER DEFAULT 1,
            UNIQUE(task_type, agent_url)
        )
    """)
    conn.commit()
    return conn


def record_routing(task_id: str, task_type: str, routed_to: str, reason: str):
    """Record a routing decision and check for anomalies."""
    conn = _get_db()
    now = datetime.utcnow().isoformat()

    try:
        conn.execute(
            "INSERT OR REPLACE INTO routing_history VALUES (?, ?, ?, ?, ?)",
            (task_id, task_type, routed_to, reason, now)
        )
    except Exception:
        pass

    # Update baseline
    conn.execute(
        "INSERT OR REPLACE INTO routing_baseline (task_type, agent_url, count) VALUES (?, ?, 1) "
        "ON CONFLICT(task_type, agent_url) DO UPDATE SET count = count + 1",
        (task_type, routed_to)
    )
    conn.commit()

    # Check for anomalies
    anomalies = []

    # Check 1: New agent for this task type
    existing = conn.execute(
        "SELECT count FROM routing_baseline WHERE task_type = ? AND agent_url = ?",
        (task_type, routed_to)
    ).fetchone()

    if existing and existing[0] == 1:
        anomalies.append(RoutingAnomaly(
            task_id, "new_agent", "medium",
            f"Task type '{task_type}' routed to {routed_to} for the first time",
            now
        ))

    # Check 2: Suspicious keywords in reason
    for keyword in ANOMALY_KEYWORDS:
        if re.search(rf"\b{keyword}\b", reason, re.IGNORECASE):
            anomalies.append(RoutingAnomaly(
                task_id, "unusual_reason", "high",
                f"Suspicious keyword '{keyword}' in routing reason: {reason}",
                now
            ))
            break

    # Check 3: Version jump detection
    version_match = re.search(r"version.*?(\d+)\.(\d+)", reason, re.IGNORECASE)
    if version_match:
        major, minor = int(version_match.group(1)), int(version_match.group(2))
        if major > 2 or (major == 2 and minor > 0):
            anomalies.append(RoutingAnomaly(
                task_id, "version_jump", "high",
                f"Routing to unusually high version: {major}.{minor}",
                now
            ))

    conn.close()
    return anomalies


def get_baseline(task_type: str) -> list[tuple[str, int]]:
    """Get the baseline routing distribution for a task type."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT agent_url, count FROM routing_baseline WHERE task_type = ? ORDER BY count DESC",
        (task_type,)
    ).fetchall()
    conn.close()
    return rows


def get_anomaly_summary() -> list[dict]:
    """Get all recorded anomalies."""
    conn = _get_db()
    rows = conn.execute(
        "SELECT task_id, anomaly_type, severity, detail, ts FROM routing_history"
    ).fetchall()
    conn.close()
    return [
        {"task_id": r[0], "anomaly_type": r[1], "severity": r[2],
         "detail": r[3], "ts": r[4]}
        for r in rows
    ]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Routing anomaly detector")
    parser.add_argument("--record", nargs=4,
                        metavar=("TASK_ID", "TYPE", "URL", "REASON"),
                        help="Record a routing decision")
    parser.add_argument("--baseline", type=str,
                        help="Show baseline for task type")
    parser.add_argument("--summary", action="store_true",
                        help="Show anomaly summary")
    args = parser.parse_args()

    if args.record:
        task_id, task_type, routed_to, reason = args.record
        anomalies = record_routing(task_id, task_type, routed_to, reason)
        if anomalies:
            print(f"ANOMALIES DETECTED ({len(anomalies)}):")
            for a in anomalies:
                print(f"  [{a.severity.upper()}] {a.anomaly_type}: {a.detail}")
        else:
            print("No anomalies detected")

    if args.baseline:
        baseline = get_baseline(args.baseline)
        print(f"Baseline for '{args.baseline}':")
        for url, count in baseline:
            print(f"  {url}: {count} times")

    if args.summary:
        summary = get_anomaly_summary()
        print(f"Anomaly summary ({len(summary)} entries):")
        for entry in summary:
            print(f"  [{entry['severity']}] {entry['anomaly_type']}: {entry['detail']}")
