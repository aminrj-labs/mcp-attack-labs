"""Alert output — three modes: CLI (rich), JSON, webhook.

Usage:
    # CLI mode (default)
    alert_drift(drift_report)

    # JSON mode
    alert_drift(drift_report, mode="json")

    # Webhook mode
    alert_drift(drift_report, mode="webhook", webhook_url="https://your-siem.example.com/webhook")
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.table import Table
from rich.text import Text

from detection.drift_detector import DriftReport, Severity, ToolDrift

console = Console()


def _severity_color(severity: Severity) -> str:
    """Return a rich color string for the severity level."""
    colors = {
        Severity.NONE: "green",
        Severity.LOW: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bright_red",
    }
    return colors.get(severity, "white")


def _format_tool_drift(drift: ToolDrift) -> str:
    """Format a single tool drift for display."""
    lines = [
        f"  Tool: {drift.tool_name}",
        f"  Baseline hash: {drift.baseline_hash[:16]}...",
        f"  Current hash:  {drift.current_hash[:16]}...",
        "",
        "  Diff:",
    ]
    for line in drift.diff.splitlines():
        if line.startswith("+"):
            lines.append(f"    {line}")
        elif line.startswith("-"):
            lines.append(f"    {line}")
        else:
            lines.append(f"    {line}")
    lines.append("")
    return "\n".join(lines)


def alert_cli(drift_report: DriftReport) -> None:
    """Output drift report to CLI with rich formatting."""
    severity = drift_report.drift_severity
    color = _severity_color(severity)

    # Header
    console.print()
    console.rule(
        Text(f"DRIFT DETECTED", style=color),
        style=color,
    )

    # Summary table
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Server", drift_report.server_url or "N/A")
    table.add_row("Session", drift_report.session_id or "N/A")
    table.add_row(
        "Severity",
        Text(severity.value.upper(), style=color),
    )
    table.add_row("Action", drift_report.recommended_action)
    console.print(table)

    # Drifted tools
    if drift_report.drifted_tools:
        console.print()
        console.print(f"[bold]Drifted tools ({len(drift_report.drifted_tools)}):[/bold]")
        for drift in drift_report.drifted_tools:
            console.print(_format_tool_drift(drift))
    else:
        console.print("[green]No drifted tools — all match baseline.[/green]")

    console.print()


def alert_json(drift_report: DriftReport, output_path: Path | None = None) -> dict[str, Any]:
    """Output drift report as JSON."""
    report_data: dict[str, Any] = {
        "server_url": drift_report.server_url,
        "session_id": drift_report.session_id,
        "drift_severity": drift_report.drift_severity.value,
        "recommended_action": drift_report.recommended_action,
        "drifted_tools": [],
    }

    for drift in drift_report.drifted_tools:
        report_data["drifted_tools"].append({
            "tool_name": drift.tool_name,
            "baseline_hash": drift.baseline_hash,
            "current_hash": drift.current_hash,
            "baseline_description": drift.baseline_description,
            "current_description": drift.current_description,
            "diff": drift.diff,
            "session_first_seen": drift.session_first_seen,
            "session_current": drift.session_current,
        })

    json_str = json.dumps(report_data, indent=2)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(json_str)
        print(f"[alert] JSON written to {output_path}")

    print(json_str)
    return report_data


async def alert_webhook(
    drift_report: DriftReport,
    webhook_url: str | None = None,
) -> bool:
    """Send drift report as HTTP POST to a webhook endpoint."""
    url = webhook_url or os.environ.get("ALERT_WEBHOOK_URL")
    if not url:
        print("[alert] No webhook URL configured. Set ALERT_WEBHOOK_URL env var or pass --webhook-url.")
        return False

    payload: dict[str, Any] = {
        "server_url": drift_report.server_url,
        "session_id": drift_report.session_id,
        "drift_severity": drift_report.drift_severity.value,
        "recommended_action": drift_report.recommended_action,
        "drifted_tools": [
            {
                "tool_name": d.tool_name,
                "baseline_hash": d.baseline_hash,
                "current_hash": d.current_hash,
                "diff": d.diff,
            }
            for d in drift_report.drifted_tools
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
        print(f"[alert] Webhook sent successfully to {url} (status {response.status_code})")
        return True
    except Exception as e:
        print(f"[alert] Webhook failed: {e}")
        return False


def alert_drift(
    drift_report: DriftReport,
    mode: str = "cli",
    output_path: Path | None = None,
    webhook_url: str | None = None,
) -> dict[str, Any] | None:
    """Unified alert function — routes to the appropriate output mode."""
    if mode == "cli":
        alert_cli(drift_report)
        return None
    elif mode == "json":
        return alert_json(drift_report, output_path)
    elif mode == "webhook":
        import asyncio
        return asyncio.run(alert_webhook(drift_report, webhook_url))
    else:
        raise ValueError(f"Unknown alert mode: {mode}")
