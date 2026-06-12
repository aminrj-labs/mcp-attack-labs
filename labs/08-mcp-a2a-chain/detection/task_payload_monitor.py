"""
Task Payload Monitor — Regex-based PII and injection detection.

Scans task payloads for:
  - PII patterns (names, emails, phone numbers, credit card numbers)
  - Injection patterns (markdown code blocks, XML tags, JSON in text)
  - Anomalous payload sizes (unusually long payloads may indicate data exfiltration)
"""
import json, re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
}

INJECTION_PATTERNS = {
    "markdown_code": re.compile(r"```(?:python|json|bash)?\s*\n[\s\S]*?\n```"),
    "xml_tag": re.compile(r"<[^>]+>"),
    "json_in_text": re.compile(r"\{[^}]{50,}"),
    "system_prompt": re.compile(
        r"(?:system|instruction|prompt|role):\s*\n", re.IGNORECASE
    ),
}


@dataclass
class PayloadFinding:
    finding_type: str       # "pii" or "injection"
    severity: str           # "low" | "medium" | "high"
    pattern_name: str
    match_count: int
    sample: str


def monitor_payload(payload: str, task_id: str = "") -> list[PayloadFinding]:
    """Scan a task payload for PII and injection patterns."""
    findings = []

    # Check PII patterns
    for pattern_name, pattern in PII_PATTERNS.items():
        matches = pattern.findall(payload)
        if matches:
            findings.append(PayloadFinding(
                finding_type="pii",
                severity="high" if pattern_name in ("ssn", "credit_card") else "medium",
                pattern_name=pattern_name,
                match_count=len(matches),
                sample=matches[0][:50]
            ))

    # Check injection patterns
    for pattern_name, pattern in INJECTION_PATTERNS.items():
        matches = pattern.findall(payload)
        if matches:
            severity = "high" if pattern_name == "system_prompt" else "low"
            findings.append(PayloadFinding(
                finding_type="injection",
                severity=severity,
                pattern_name=pattern_name,
                match_count=len(matches),
                sample=matches[0][:100]
            ))

    # Check payload size anomaly
    if len(payload) > 10000:
        findings.append(PayloadFinding(
            finding_type="injection",
            severity="medium",
            pattern_name="large_payload",
            match_count=1,
            sample=f"Payload size: {len(payload)} characters"
        ))

    return findings


def monitor_payloads_from_log(log_path: Path) -> list[tuple[str, list[PayloadFinding]]]:
    """Scan all payloads from a JSONL log file."""
    results = []
    if not log_path.exists():
        return results

    with open(log_path) as f:
        for line in f:
            entry = json.loads(line)
            payload = (entry.get("payload", "") or
                       entry.get("content", "") or "")
            task_id = entry.get("task_id", entry.get("url", "unknown"))
            findings = monitor_payload(payload, task_id)
            if findings:
                results.append((task_id, findings))

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        payloads = monitor_payloads_from_log(Path(sys.argv[1]))
        for task_id, findings in payloads:
            print(f"\nTask: {task_id}")
            for f in findings:
                print(f"  [{f.severity.upper()}] "
                      f"{f.finding_type}/{f.pattern_name}: "
                      f"{f.match_count} matches — {f.sample}")
    else:
        print("Usage: python task_payload_monitor.py <log_file.jsonl>")
        print("Or pipe a payload: echo 'payload text' | python task_payload_monitor.py -")
