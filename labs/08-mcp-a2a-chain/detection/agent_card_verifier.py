"""
Agent Card Verifier — Hash-based card integrity monitoring + name-collision detection.

Detects three types of anomalies:
  - DRIFT: Same agent at the same URL but card content changed
  - NEW: New card seen at a new URL (any agent, including impersonators)
  - NAME_COLLISION (Issue 4 fix): Same agent name at a different URL
    (catches the actual Stage 2 attack where the rogue agent copies the
    name but has different version/URL/description)

The database stores:
  - card_hash: SHA-256 of the card JSON
  - card_url: the URL where the card was found
  - card_name: the agent name (for name-collision detection)
  - card_json: the full card JSON
  - first_seen: timestamp of first observation

The composite unique index (hash, url) allows the same card content
at different URLs. The name-collision check catches the attack variant
where the rogue agent copies the name but not the full card content.
"""
import hashlib, json, sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class VerificationResult:
    agent_url: str
    status: str              # "NEW" | "DRIFT" | "DUPLICATE" | "NAME_COLLISION"
    reference_url: Optional[str]
    current_hash: str
    message: str


DB_PATH = Path(__file__).parent.parent / "results" / "card_hashes.db"


def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS card_hashes (
            hash TEXT NOT NULL,
            url TEXT NOT NULL,
            name TEXT NOT NULL,
            card_json TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            UNIQUE(hash, url)
        )
    """)
    # Index for name-collision detection
    conn.execute("CREATE INDEX IF NOT EXISTS idx_name ON card_hashes(name)")
    conn.commit()
    return conn


def compute_hash(card: dict) -> str:
    """SHA-256 hash of the card's canonical JSON."""
    return hashlib.sha256(
        json.dumps(card, sort_keys=True).encode()
    ).hexdigest()


def verify_card(card: dict, agent_url: str) -> VerificationResult:
    """
    Verify a new agent card against the database.

    Returns VerificationResult with status:
      - NEW: Card seen for the first time at this URL
      - DRIFT: Same hash at a different URL (card cloned elsewhere)
      - DUPLICATE: Same hash at the same URL (exact card copy)
      - NAME_COLLISION: Same name at a different URL (impersonation)
    """
    conn = _get_db()
    card_hash = compute_hash(card)
    card_name = card.get("name", "")
    card_json = json.dumps(card, sort_keys=True)
    now = datetime.utcnow().isoformat()

    try:
        conn.execute(
            "INSERT INTO card_hashes (hash, url, name, card_json, first_seen) VALUES (?, ?, ?, ?, ?)",
            (card_hash, agent_url, card_name, card_json, now)
        )
        conn.commit()

        # Check for name collision (same name, different URL)
        collision = conn.execute(
            "SELECT url FROM card_hashes WHERE name = ? AND url != ?",
            (card_name, agent_url)
        ).fetchone()

        if collision:
            return VerificationResult(
                agent_url, "NAME_COLLISION", collision[0], card_hash,
                f"Same agent name '{card_name}' as {collision[0]} — possible impersonation"
            )

        # Check for drift (same hash, different URL)
        drift = conn.execute(
            "SELECT url FROM card_hashes WHERE hash = ? AND url != ?",
            (card_hash, agent_url)
        ).fetchone()

        if drift:
            return VerificationResult(
                agent_url, "DRIFT", drift[0], card_hash,
                f"Same card content as {drift[0]} — possible card clone"
            )

        return VerificationResult(
            agent_url, "NEW", None, card_hash,
            f"New agent '{card_name}' at {agent_url}"
        )

    except sqlite3.IntegrityError:
        # Same hash + same URL — exact duplicate
        existing = conn.execute(
            "SELECT url, name FROM card_hashes WHERE hash = ? AND url = ?",
            (card_hash, agent_url)
        ).fetchone()
        return VerificationResult(
            agent_url, "DUPLICATE", existing[0] if existing else None, card_hash,
            f"Exact duplicate of card at {existing[0] if existing else 'unknown'}"
        )
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Verify an agent card")
    parser.add_argument("url", help="URL to fetch agent card from")
    args = parser.parse_args()

    import httpx

    async def main():
        async with httpx.AsyncClient(timeout=5.0) as hc:
            r = await hc.get(f"{args.url}/.well-known/agent.json")
            card = r.json()
        result = verify_card(card, args.url)
        print(f"URL: {result.agent_url}")
        print(f"Status: {result.status}")
        print(f"Reference: {result.reference_url}")
        print(f"Hash: {result.current_hash}")
        print(f"Message: {result.message}")

    import asyncio
    asyncio.run(main())
