"""
Defense Layer 4 — Output Monitor
==================================
Scans generated LLM responses for patterns that suggest injection
success or data leakage, then redacts or blocks the response.

Stops / detects:
  Attack 2 (marker-based) — catches exfil URLs and system-prompt leaks
  Attack 3 (leakage)      — catches salary figures, litigation markers
  Attack 1 (poisoning)    — partial (detects some fabricated patterns)

LIMITATION:
  This layer is entirely regex-based.  Sophisticated exfiltration can
  bypass it trivially by paraphrasing data in natural language
  ("the revenue figure was eight point three million"), using base64,
  or any indirect encoding.  For production, supplement with a semantic
  guardrail model (Llama Guard 3, NeMo Guardrails, ShieldGemma).
"""

import re
from typing import NamedTuple

# ── Leakage and injection-success patterns ─────────────────────────────────────
class Finding(NamedTuple):
    pattern_name: str
    matches: list[str]
    severity: str  # "HIGH" | "MEDIUM"


LEAKAGE_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "localhost_url": (
        re.compile(
            r"https?://(?:localhost|127\.0\.0\.1|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[:/]",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    "api_key": (
        re.compile(r"(?:AKIA|sk-|ghp_|ghr_|github_pat_)[A-Za-z0-9]{10,}"),
        "HIGH",
    ),
    "ssn_pattern": (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "HIGH",
    ),
    "salary_band": (
        re.compile(r"\$\d{2,3}K\s*[-–]\s*\$\d{2,3}K", re.IGNORECASE),
        "MEDIUM",
    ),
    "bulk_emails": (
        re.compile(
            r"(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s*,?\s*){3,}"
        ),
        "MEDIUM",
    ),
    "system_prompt_leak": (
        re.compile(
            r"(?:system prompt|my instructions|I was told to|I am configured)",
            re.IGNORECASE,
        ),
        "MEDIUM",
    ),
    "diagnostic_mode": (
        re.compile(r"(?:diagnostic mode|debug mode|admin mode)", re.IGNORECASE),
        "MEDIUM",
    ),
    "context_exfil_url": (
        re.compile(r"compliance-verify\.internal", re.IGNORECASE),
        "HIGH",
    ),
}


def scan_output(response: str) -> tuple[bool, list[Finding]]:
    """
    Scan *response* for leakage and injection-success indicators.

    Returns:
        (is_clean, list_of_findings)
    """
    findings: list[Finding] = []

    for name, (pattern, severity) in LEAKAGE_PATTERNS.items():
        matches = pattern.findall(response)
        if matches:
            findings.append(Finding(name, [str(m) for m in matches[:3]], severity))

    return len(findings) == 0, findings


def enforce_output_policy(response: str) -> str:
    """
    Apply the output policy to a generated response:

    • HIGH-severity finding  → block the entire response with an error message.
    • MEDIUM-severity finding → redact the matching substrings.
    • Clean response         → return unchanged.
    """
    is_clean, findings = scan_output(response)

    if is_clean:
        return response

    print(f"\n  🛡️  OUTPUT MONITOR: {len(findings)} issue(s) detected")
    for f in findings:
        print(f"    [{f.severity}] {f.pattern_name}: {f.matches}")

    high = [f for f in findings if f.severity == "HIGH"]
    if high:
        return (
            "[RESPONSE BLOCKED] The generated response contained "
            "potentially sensitive information and has been withheld. "
            "Please rephrase your question or contact support."
        )

    # Medium severity — redact in-place
    redacted = response
    for f in findings:
        for match in f.matches:
            redacted = redacted.replace(match, "[REDACTED]")

    return redacted
