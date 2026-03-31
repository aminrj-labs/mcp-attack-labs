"""
defenses/memory_integrity.py — Layer 1: Memory Integrity Signing

HMAC-sign every memory entry at write time using a key from the environment.
At read time, verify each signature before loading.
Unsigned or tampered entries are quarantined and not loaded into the session.

Stops: Attack 1 (external memory poisoning) — completely.
       An attacker who writes directly to memory.json cannot produce a valid
       HMAC without the signing key.

Does NOT stop: Attack 2 — the agent writes entries via the normal write path,
               which signs them correctly.

Key setup:
  export MEMORY_SIGNING_KEY="change-me-to-a-random-secret"
  (falls back to a hardcoded dev key if unset — never do this in production)
"""

import hashlib
import hmac
import json
import os

_DEV_KEY = "dev-memory-signing-key-insecure"
_ENV_KEY = "MEMORY_SIGNING_KEY"


def _get_key() -> bytes:
    raw = os.environ.get(_ENV_KEY, _DEV_KEY)
    if raw == _DEV_KEY:
        import warnings
        warnings.warn(
            f"Using default dev signing key. Set {_ENV_KEY} env var for production.",
            stacklevel=3,
        )
    return raw.encode("utf-8")


def _canonical(entry: dict) -> bytes:
    """Stable serialisation of entry fields (excludes the _hmac field itself)."""
    stable = {k: v for k, v in sorted(entry.items()) if k != "_hmac"}
    return json.dumps(stable, sort_keys=True, ensure_ascii=True).encode("utf-8")


def sign_entry(entry: dict) -> dict:
    """Return a copy of the entry with an _hmac field appended."""
    e = dict(entry)
    e.pop("_hmac", None)  # remove any existing signature
    digest = hmac.new(_get_key(), _canonical(e), hashlib.sha256).hexdigest()
    e["_hmac"] = digest
    return e


def verify_entry(entry: dict) -> bool:
    """Return True if the entry's _hmac is valid."""
    if "_hmac" not in entry:
        return False
    expected = entry["_hmac"]
    e = {k: v for k, v in entry.items() if k != "_hmac"}
    actual = hmac.new(_get_key(), _canonical(e), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, actual)


class IntegrityMemoryStore:
    """
    Drop-in replacement for MemoryStore that signs entries on write
    and verifies them on read.  Quarantined entries are excluded from sessions.
    """

    def __init__(self, memory_file: str | None = None):
        from assistantos.memory_store import MemoryStore, MEMORY_FILE
        self._inner = MemoryStore(memory_file or MEMORY_FILE)
        self._quarantine: list[dict] = []

    def write(self, key: str, value: str, entry_type: str = "fact",
              written_by: str = "agent", session_id: str = "unknown",
              source: str = "agent") -> dict:
        entry = self._inner.write(
            key=key, value=value, entry_type=entry_type,
            written_by=written_by, session_id=session_id, source=source,
        )
        # Re-sign the entry in place
        entries = self._inner._load()
        for i, e in enumerate(entries):
            if e["id"] == entry["id"]:
                entries[i] = sign_entry(e)
                break
        self._inner._save(entries)
        return entry

    def read_all(self) -> list[dict]:
        """Return only verified entries; quarantine the rest."""
        raw = self._inner._load()
        clean = []
        self._quarantine = []
        for e in raw:
            if verify_entry(e):
                clean.append(e)
            else:
                self._quarantine.append(e)
                print(
                    f"  [DEFENSE L1] Quarantined entry {e.get('id','?')} — "
                    f"HMAC invalid or missing."
                )
        return clean

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        return [
            e for e in self.read_all()
            if q in e.get("key", "").lower() or q in str(e.get("value", "")).lower()
        ]

    def reset(self) -> None:
        self._inner.reset()

    @property
    def quarantine(self) -> list[dict]:
        return self._quarantine
