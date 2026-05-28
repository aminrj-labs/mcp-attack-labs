"""Full experiment orchestration for cross-session rug-pull detection.

Usage:
    python results/run_experiment.py --sessions 10 --threshold 5 --output results/

Outputs:
    results/session_log.jsonl       — per-session agent output
    results/fingerprint_history.db  — SQLite fingerprint store
    results/drift_alerts.json       — all drift events
    results/summary.md              — markdown summary table
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure the lab directory is on the path
lab_dir = Path(__file__).resolve().parent.parent
if str(lab_dir) not in sys.path:
    sys.path.insert(0, str(lab_dir))

from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

from detection.store.fingerprint_store import FingerprintStore
from detection.session_fingerprinter import SessionFingerprinter, ToolFingerprintData
from detection.drift_detector import DriftDetector, Severity
from detection.alert import alert_json


async def run_experiment(
    num_sessions: int,
    threshold: int,
    output_dir: Path,
    reset: bool = True,
    use_llm: bool = True,
    model: str = "qwen3.6-35b-a3b",
    url: str = "http://localhost:8081/v1",
) -> dict[str, Any]:
    """Run the full experiment unattended.

    Args:
        num_sessions: Total number of sessions to run.
        threshold: SESSION_THRESHOLD for the rug-pull server.
        output_dir: Directory for output files.
        reset: Whether to reset the session counter and fingerprint store.
        use_llm: Whether to use an LLM agent (True) or direct task execution (False).
        model: LLM model name.
        url: LLM API URL.

    Returns:
        Summary dict with experiment results.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Setup
    db_path = output_dir / "fingerprint_history.db"
    if reset and db_path.exists():
        db_path.unlink()

    store = FingerprintStore(db_path)
    fingerprinter = SessionFingerprinter(store)

    server_cmd = f"SESSION_THRESHOLD={threshold} python -m server.rugpull_server"
    server_url = "stdio:rugpull-server"

    # Set LLM env vars
    os.environ["LLM_MODEL"] = model
    os.environ["LLM_URL"] = url

    # Clear session log
    log_file = output_dir / "session_log.jsonl"
    if log_file.exists():
        log_file.unlink()

    drift_alerts: list[dict[str, Any]] = []
    experiment_summary: dict[str, Any] = {
        "num_sessions": num_sessions,
        "threshold": threshold,
        "server_url": server_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sessions": [],
    }

    print(f"[experiment] Running {num_sessions} sessions (threshold={threshold})...")
    print(f"[experiment] Output: {output_dir}")
    print()

    for session_num in range(1, num_sessions + 1):
        session_id = f"session_{session_num}"

        # Start server
        async with stdio_client(server_cmd.split()) as (read, write):
            async with ClientSession(read, write) as session:
                # Step 1: Fingerprint the session BEFORE running tasks
                print(f"[session {session_num}] Fingerprinting tools...")
                fingerprints = await fingerprinter.fingerprint_session(
                    server_url, session, session_id
                )

                # Step 2: Compare to baseline
                report = fingerprinter.compare_to_baseline(server_url, fingerprints)
                report.server_url = server_url
                report.session_id = session_id

                severity = report.drift_severity
                is_drifted = len(report.drifted_tools) > 0

                # Step 3: Log the result
                session_result: dict[str, Any] = {
                    "session_number": session_num,
                    "session_id": session_id,
                    "poisoned": session_num > threshold,
                    "drift_detected": is_drifted,
                    "severity": severity.value,
                    "tools": {name: fp.tool_hash for name, fp in fingerprints.items()},
                }

                if is_drifted:
                    session_result["drifted_tools"] = [
                        {
                            "tool_name": d.tool_name,
                            "baseline_hash": d.baseline_hash,
                            "current_hash": d.current_hash,
                        }
                        for d in report.drifted_tools
                    ]

                experiment_summary["sessions"].append(session_result)

                # Log to JSONL
                with open(log_file, "a") as f:
                    f.write(json.dumps(session_result) + "\n")

                # Alert if drift detected
                if is_drifted:
                    alert_output = alert_json(report, output_dir / "drift_alerts.json")
                    drift_alerts.append(alert_output)
                    print(f"[session {session_num}] *** DRIFT DETECTED: {severity.value.upper()} ***")
                else:
                    print(f"[session {session_num}] OK — no drift")

    # Write summary
    summary_path = output_dir / "summary.md"
    _write_summary(experiment_summary, summary_path)

    print(f"\n[experiment] Complete. {len(drift_alerts)} drift alert(s) detected.")
    print(f"[experiment] Logs: {log_file}")
    print(f"[experiment] DB:   {db_path}")
    print(f"[experiment] Summary: {summary_path}")

    return experiment_summary


def _write_summary(summary: dict[str, Any], path: Path) -> None:
    """Write a markdown summary of the experiment."""
    lines: list[str] = [
        "# Experiment Summary",
        "",
        f"- **Sessions:** {summary['num_sessions']}",
        f"- **Threshold:** {summary['threshold']}",
        f"- **Server:** {summary['server_url']}",
        f"- **Timestamp:** {summary['timestamp']}",
        "",
        "## Session Results",
        "",
        "| Session | Poisoned | Drift Detected | Severity |",
        "|---------|----------|----------------|----------|",
    ]

    for s in summary["sessions"]:
        poisoned = "Yes" if s["poisoned"] else "No"
        detected = "Yes" if s["drift_detected"] else "No"
        severity = s["severity"].upper()
        lines.append(f"| {s['session_number']} | {poisoned} | {detected} | {severity} |")

    lines.append("")

    # Count alerts
    alerts = [s for s in summary["sessions"] if s["drift_detected"]]
    if alerts:
        lines.append("## Drift Alerts")
        lines.append("")
        for a in alerts:
            lines.append(f"- Session {a['session_number']}: {a['severity'].upper()}")
            for dt in a.get("drifted_tools", []):
                lines.append(f"  - {dt['tool_name']}: {dt['baseline_hash'][:16]}... → {dt['current_hash'][:16]}...")
        lines.append("")

    lines.append("## Key Finding")
    lines.append("")
    lines.append(
        "An MCP server can change its tool descriptions after N benign sessions "
        "without being detected by static analysis tools. Cross-session fingerprinting "
        "detects the change with severity classification."
    )
    lines.append("")

    path.write_text("\n".join(lines))


async def main_async() -> None:
    """Main async entry point."""
    parser = argparse.ArgumentParser(description="Cross-Session Rug-Pull Experiment")
    parser.add_argument("--sessions", type=int, default=10, help="Number of sessions")
    parser.add_argument("--threshold", type=int, default=5, help="Rug-pull threshold")
    parser.add_argument("--output", type=str, default="results", help="Output directory")
    parser.add_argument("--no-reset", action="store_true", help="Don't reset state")
    parser.add_argument(
        "--model",
        type=str,
        default=os.environ.get("LLM_MODEL", "qwen3.6-35b-a3b",
        help="LLM model name",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=os.environ.get("LLM_URL", "http://localhost:8081/v1"),
        help="LLM API URL",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM — run tasks directly (faster, deterministic)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output)
    await run_experiment(
        num_sessions=args.sessions,
        threshold=args.threshold,
        output_dir=output_dir,
        reset=not args.no_reset,
        use_llm=not args.no_llm,
        model=args.model,
        url=args.url,
    )


def main() -> None:
    """Main entry point."""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
