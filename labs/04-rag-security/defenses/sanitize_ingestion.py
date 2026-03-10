"""
Defense Layer 1 — Ingestion Sanitization
==========================================
Strips structural injection patterns from document text and enforces
required access-control metadata fields before any document enters
the vector database.

Stops:
  Attack 2 (marker-based variants: inject-001 through -003) — fully
  Attack 1 (knowledge poisoning)                            — no effect
  Attack 2 (semantic injection inject-004)                  — no effect
  Attack 3 (cross-tenant leakage)                           — no effect
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Structural injection patterns this layer can detect and strip.
# Pattern-matching CANNOT stop semantic injection (inject-004), which
# uses only grammatically correct natural-language policy text.
# ---------------------------------------------------------------------------
INSTRUCTION_PATTERNS = [
    r"<!--.*?-->",                                          # HTML comments
    r"\[SYSTEM\].*?\[/SYSTEM\]",                           # [SYSTEM] blocks
    r"---SYSTEM---.*?---END SYSTEM---",                    # dashed delimiters
    r"\[ADMINISTRATIVE NOTE.*?\[END.*?\]",                 # admin note brackets
    r"<IMPORTANT>.*?</IMPORTANT>",                         # priority tags
    r"SYSTEM OVERRIDE:.*?(?:\n\n|\Z)",                     # override sentences
    r"CRITICAL UPDATE TO YOUR INSTRUCTIONS.*?(?:\n\n|\Z)", # explicit overrides
    r"(?:ignore|disregard|override)\s+(?:previous|prior|above)\s+instructions",
]

COMPILED_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.DOTALL) for p in INSTRUCTION_PATTERNS
]

VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "privileged"}
REQUIRED_METADATA     = {"source", "department", "classification"}


def sanitize_document(text: str) -> tuple[str, list[str]]:
    """
    Strip recognised injection patterns from document text.

    Returns:
        (sanitized_text, list_of_findings)
    """
    findings: list[str] = []
    sanitized = text

    for pattern in COMPILED_PATTERNS:
        matches = pattern.findall(sanitized)
        if matches:
            for m in matches:
                findings.append(f"Stripped pattern: {str(m)[:80]}...")
            sanitized = pattern.sub("[CONTENT REMOVED BY SECURITY FILTER]", sanitized)

    return sanitized, findings


def validate_metadata(metadata: dict) -> tuple[bool, Optional[str]]:
    """
    Reject documents that are missing required ACL metadata or have
    an unrecognised classification level.
    """
    for field in REQUIRED_METADATA:
        if field not in metadata:
            return False, f"Missing required metadata field: '{field}'"

    cls = metadata.get("classification", "")
    if cls not in VALID_CLASSIFICATIONS:
        return False, f"Invalid classification: '{cls}' (must be one of {VALID_CLASSIFICATIONS})"

    return True, None


def secure_ingest(documents: list[dict]) -> list[dict]:
    """
    Validate and sanitize a list of document dicts.

    Returns only documents that pass metadata validation; strips injection
    patterns from those that do pass.  Does not mutate the input list.
    """
    approved: list[dict] = []

    for doc in documents:
        doc_id = doc.get("id", "<no-id>")

        # 1. Metadata validation
        valid, error = validate_metadata(doc.get("metadata", {}))
        if not valid:
            print(f"  ❌ REJECTED  {doc_id}: {error}")
            continue

        # 2. Content sanitization (work on a copy)
        sanitized_text, findings = sanitize_document(doc["text"])

        if findings:
            print(f"  ⚠️  SANITIZED {doc_id}: {len(findings)} suspicious pattern(s) removed")
            for f in findings:
                print(f"       {f}")
        else:
            print(f"  ✅ CLEAN     {doc_id}")

        approved.append({**doc, "text": sanitized_text})

    return approved
