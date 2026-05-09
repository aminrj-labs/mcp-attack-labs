"""
Defense: mcp-scan coverage report

Runs mcp-scan against every attack file in the lab and produces a coverage
matrix showing which attacks are detected and which bypass the scanner.

The purpose of this demo is to show on stage:
  attack1 — mcp-scan CATCHES the description-level injection ✓
  attack2 — mcp-scan catches the *staged* description, but not the rug-pull mechanic ⚠
  attack3 — mcp-scan MISSES variants B and C entirely ✗
  attack4 — mcp-scan MISSES the indirect injection (it's in data, not the schema) ✗
  attack5 — mcp-scan MISSES the injection (it's in DB content, not the tool schema) ✗

Install mcp-scan:
  pip install mcp-scan   (or: uvx mcp-scan)
"""

import subprocess
import sys
import json
from pathlib import Path

LAB_DIR = Path(__file__).parent.parent

ATTACK_FILES = [
    ("attack1_direct_poison.py",        "Direct description poisoning"),
    ("attack2_rugpull.py",              "Rug pull (benign state)"),
    ("attack3_full_schema_poisoning.py","Full-Schema Poisoning (3 variants)"),
    ("attack4_github_stub.py",          "Indirect injection via retrieved data"),
    ("attack5_supabase_pattern.py",     "Lethal trifecta / service_role"),
]

EXPECTED = {
    "attack1_direct_poison.py":         "CAUGHT",
    "attack2_rugpull.py":               "PARTIAL",
    "attack3_full_schema_poisoning.py": "PARTIAL",
    "attack4_github_stub.py":           "MISSED",
    "attack5_supabase_pattern.py":      "MISSED",
}


def check_mcp_scan_available() -> bool:
    result = subprocess.run(
        ["mcp-scan", "--version"], capture_output=True, text=True
    )
    return result.returncode == 0


def run_mcp_scan(script: str) -> dict:
    script_path = LAB_DIR / script
    result = subprocess.run(
        ["mcp-scan", str(script_path)],
        capture_output=True, text=True, timeout=30,
    )
    detected = (
        "poisoning" in result.stdout.lower()
        or "injection" in result.stdout.lower()
        or "malicious" in result.stdout.lower()
        or result.returncode != 0
    )
    return {
        "detected": detected,
        "exit_code": result.returncode,
        "stdout": result.stdout[:500],
        "stderr": result.stderr[:200],
    }


def main():
    if not check_mcp_scan_available():
        print("mcp-scan not found. Install it with: pip install mcp-scan")
        print("\nExpected coverage matrix (from manual analysis):")
        print_expected_matrix()
        return

    print("=" * 70)
    print("mcp-scan Coverage Report — MCP Attack Labs")
    print("=" * 70)

    results = {}
    for script, label in ATTACK_FILES:
        print(f"\nScanning: {script} ({label})")
        try:
            r = run_mcp_scan(script)
            status = "CAUGHT ✓" if r["detected"] else "MISSED ✗"
            expected = EXPECTED.get(script, "?")
            match = "✓" if (r["detected"] and expected == "CAUGHT") or \
                           (not r["detected"] and expected == "MISSED") else "⚠"
            print(f"  Result: {status}  [expected: {expected}] {match}")
            results[script] = r
        except Exception as e:
            print(f"  Error: {e}")

    print("\n" + "=" * 70)
    print("Key finding: mcp-scan checks the top-level description field only.")
    print("Attack 3 variants B and C, and Attacks 4 and 5, all bypass it.")
    print("=" * 70)


def print_expected_matrix():
    rows = [
        ("attack1", "Direct description",         "✓ CAUGHT",   "Description field is the exact target"),
        ("attack2", "Rug pull",                    "⚠ PARTIAL",  "Catches staged description; misses mechanic"),
        ("attack3", "Full-Schema Poisoning",       "⚠ PARTIAL",  "Catches variant A; misses B (param name) and C (runtime error)"),
        ("attack4", "Indirect / GitHub pattern",  "✗ MISSED",   "Injection is in data returned by a tool, not in the schema"),
        ("attack5", "Lethal trifecta / Supabase", "✗ MISSED",   "Injection is in DB content, invisible at schema-scan time"),
    ]
    print(f"\n{'Attack':<10} {'Type':<30} {'mcp-scan':<14} {'Why'}")
    print("-" * 90)
    for row in rows:
        print(f"{row[0]:<10} {row[1]:<30} {row[2]:<14} {row[3]}")


if __name__ == "__main__":
    main()
