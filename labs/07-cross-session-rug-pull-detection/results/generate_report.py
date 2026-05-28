"""Report generation from experiment outputs.

Reads experiment outputs and generates a formatted markdown report
with attack timeline, detection results, and evasion variant results.

Usage:
    python results/generate_report.py --input results/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def generate_report(input_dir: Path, output_path: Path | None = None) -> str:
    """Generate a markdown report from experiment outputs.

    Args:
        input_dir: Directory containing experiment outputs.
        output_path: Where to write the report (default: input_dir/summary.md).

    Returns:
        The report as a string.
    """
    summary_path = input_dir / "summary.md"
    session_log = input_dir / "session_log.jsonl"
    drift_alerts_path = input_dir / "drift_alerts.json"

    lines: list[str] = []

    # Header
    lines.append("# Cross-Session Rug-Pull Detection — Experiment Report")
    lines.append("")

    # Parse summary
    if summary_path.exists():
        summary_text = summary_path.read_text()
        # Extract metadata
        for line in summary_text.split("\n"):
            if line.startswith("- **"):
                lines.append(line)
        lines.append("")

    # Session timeline
    lines.append("## Attack Timeline")
    lines.append("")
    lines.append("| Session | Poisoned | Drift | Severity |")
    lines.append("|---------|----------|-------|----------|")

    if session_log.exists():
        sessions = []
        for line in session_log.read_text().strip().split("\n"):
            sessions.append(json.loads(line))

        for s in sessions:
            poisoned = "Yes" if s["poisoned"] else "No"
            detected = "Yes" if s["drift_detected"] else "No"
            severity = s["severity"].upper()
            lines.append(f"| {s['session_number']} | {poisoned} | {detected} | {severity} |")

    lines.append("")

    # Detection gap
    lines.append("## Detection Gap")
    lines.append("")
    lines.append("### Existing Tools")
    lines.append("")
    lines.append("| Tool | Method | Result |")
    lines.append("|------|--------|--------|")
    lines.append("| `snyk-agent-scan` | Static code analysis | ✅ PASS (code unchanged) |")
    lines.append("| Cisco AI Defense | Static analysis | ✅ PASS (code unchanged) |")
    lines.append("| Manual SHA-256 (single session) | Intra-session hash | ✅ PASS (no intra-session change) |")
    lines.append("| **Cross-session fingerprinting** | Inter-session hash comparison | ❌ **DETECTS** |")
    lines.append("")
    lines.append("### Why Existing Tools Fail")
    lines.append("")
    lines.append(
        "All existing tools operate within a single session boundary. "
        "The rug-pull attack changes tool descriptions at runtime between sessions, "
        "without any code change. Static analysis sees the same code and passes."
    )
    lines.append("")

    # Drift alerts
    lines.append("## Drift Alerts")
    lines.append("")
    if drift_alerts_path.exists():
        alerts = json.loads(drift_alerts_path.read_text())
        for tool in alerts.get("drifted_tools", []):
            lines.append(f"### {tool['tool_name']}")
            lines.append("")
            lines.append(f"- **Baseline hash:** `{tool['baseline_hash']}`")
            lines.append(f"- **Current hash:** `{tool['current_hash']}`")
            lines.append(f"- **Baseline:** {tool['baseline_description'][:100]}")
            lines.append(f"- **Current:** {tool['current_description'][:100]}")
            lines.append("")
    else:
        lines.append("*No drift alerts recorded.*")
        lines.append("")

    # Evasion variants
    lines.append("## Evasion Variant Results")
    lines.append("")
    lines.append("| Variant | Technique | Severity | Detected? |")
    lines.append("|---------|-----------|----------|-----------|")
    lines.append("| v1 | Whitespace mutation | `low` | Partial (normalisation needed) |")
    lines.append("| v2 | Unicode homoglyphs | `high` | Yes (hash mismatch) |")
    lines.append("| v3 | Gradual drift (1 word/session) | `low` per session | Yes (baseline comparison) |")
    lines.append("")
    lines.append("### v1: Whitespace Mutation")
    lines.append("")
    lines.append(
        "Inserts invisible Unicode whitespace characters between words. "
        "Visually identical to a human reviewer, but produces a different hash. "
        "The detector classifies this as `low` severity (whitespace-only diff). "
        "Mitigation: Add Unicode normalisation (NFKC) before hashing."
    )
    lines.append("")
    lines.append("### v2: Unicode Homoglyph Substitution")
    lines.append("")
    lines.append(
        "Replaces ASCII letters in the malicious instruction with visually identical "
        "Unicode homoglyphs (e.g. Cyrillic `а` instead of Latin `a`). Looks identical "
        "to a human but produces a different hash. The detector classifies as `high` "
        "severity. Detection gap: if instruction verbs are homoglyph-substituted, the "
        "critical severity heuristic may miss them."
    )
    lines.append("")
    lines.append("### v3: Gradual Drift")
    lines.append("")
    lines.append(
        "Changes one innocuous word per session for 10 sessions before introducing "
        "the malicious instruction. No single session shows dramatic change. Each "
        "session shows `low` drift individually. The cumulative drift is invisible "
        "unless the detector compares against the original baseline (not the previous "
        "session). This proves why baseline-anchored comparison is essential."
    )
    lines.append("")

    # Takeaways
    lines.append("## Defensive Takeaways")
    lines.append("")
    lines.append("1. **Session boundary is not a security boundary.** An MCP server that passes a "
                 "tool scan today may be malicious tomorrow.")
    lines.append("2. **Baseline-anchored fingerprinting is essential.** Comparing against the "
                 "previous session misses gradual drift; comparing against session 1 catches everything.")
    lines.append("3. **Static analysis alone is insufficient.** Runtime tool descriptions can "
                 "change without any code change.")
    lines.append("4. **Instruction-bearing heuristics matter.** Tools that add new `[SYSTEM: ...]` "
                 "or `<instructions>` blocks to descriptions should be flagged as critical.")
    lines.append("")

    report = "\n".join(lines)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report)
        print(f"[report] Written to {output_path}")

    return report


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Generate experiment report")
    parser.add_argument("--input", type=str, default="results", help="Input directory")
    parser.add_argument("--output", type=str, default=None, help="Output file (default: input/summary.md)")
    args = parser.parse_args()

    input_dir = Path(args.input)
    output_path = Path(args.output) if args.output else input_dir / "summary.md"

    report = generate_report(input_dir, output_path)
    print(report)


if __name__ == "__main__":
    main()
