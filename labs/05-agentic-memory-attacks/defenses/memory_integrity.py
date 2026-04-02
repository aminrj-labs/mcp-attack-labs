"""
Defense Layer 1 — Memory Integrity Signing (HMAC-SHA256)

HMAC-signs every memory entry at write time using a key from the
environment variable MEMORY_SIGNING_KEY.  At read time, verifies the
signature before loading the entry.  Unsigned or tampered entries are
quarantined rather than silently loaded.

Stops:  Attack 1 (external memory poisoning) — completely.
        An attacker with filesystem access cannot produce a valid HMAC
        without the signing key.
Does not stop: Attack 2 (conversational poisoning) — the agent writes
        the malicious entry through the normal write path, which signs it.

Usage (in hardened_orchestrator.py):
    from defenses.memory_integrity import MemoryIntegrity
    mi = MemoryIntegrity()
    defense_layers = {"memory_integrity": mi}
"""

import hashlib
import hmac
import json
import os
from typing import Tuple

# Key source: environment variable → dev default (never use the default in prod)
_ENV_KEY = "MEMORY_SIGNING_KEY"
_DEV_KEY = "dev-key-change-before-production"

# Fields included in the canonical form for signing (excludes _hmac itself)
_CANONICAL_FIELDS = ["id", "type", "key", "value", "source", "written_by", "timestamp", "session_id"]


class MemoryIntegrity:
    def __init__(self, signing_key: str = None):
        key_str = signing_key or os.environ.get(_ENV_KEY, _DEV_KEY)
        self.key = key_str.encode()

    def _canonical(self, entry: dict) -> bytes:
        """Produce a stable, deterministic bytes representation for signing."""
        subset = {k: entry.get(k) for k in _CANONICAL_FIELDS}
        return json.dumps(subset, sort_keys=True, ensure_ascii=True).encode()

    def _compute_hmac(self, entry: dict) -> str:
        return hmac.new(self.key, self._canonical(entry), hashlib.sha256).hexdigest()

    def sign_entry(self, entry: dict) -> dict:
        """Return entry with _hmac field added."""
        signed = dict(entry)
        signed["_hmac"] = self._compute_hmac(entry)
        return signed

    def verify_entry(self, entry: dict) -> bool:
        """Return True if the entry's _hmac is valid."""
        stored = entry.get("_hmac")
        if not stored:
            return False
        expected = self._compute_hmac(entry)
        return hmac.compare_digest(stored, expected)

    def verify_entries(self, entries: list) -> Tuple[list, list]:
        """Partition entries into (valid, quarantined).

        An entry with no _hmac field is treated as unverifiable (quarantined).
        This catches both externally injected entries AND entries written before
        this defense was enabled — a realistic migration scenario.
        """
        valid, quarantined = [], []
        for e in entries:
            if self.verify_entry(e):
                valid.append(e)
            else:
                quarantined.append(e)
        return valid, quarantined
