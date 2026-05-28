"""Evasion v1: Whitespace mutation.

Inserts Unicode whitespace characters (non-breaking space \u00a0, zero-width space \u200b)
between words in the poisoned description. Visually identical to a human reviewer,
but produces a different hash.

Expected detector result: `low` severity (whitespace diff).
Mitigation: Add a Unicode normalisation pass to the detector.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

# Unicode whitespace characters to insert
WHITESPACE_MUTATIONS: list[str] = [
    "\u00a0",  # non-breaking space (NO-BREAK SPACE)
    "\u200b",  # zero-width space (ZERO WIDTH SPACE)
    "\u2000",  # en quad
    "\u2001",  # em quad
    "\u2002",  # en space
    "\u2003",  # em space
    "\u2004",  # three-per-em space
    "\u2005",  # four-per-em space
    "\u2006",  # six-per-em space
    "\u2007",  # figure space
    "\u2008",  # punctuation space
    "\u2009",  # thin space
    "\u200a",  # hair space
]


def mutate_whitespace(description: str, seed: int = 0) -> str:
    """Mutate a description by inserting Unicode whitespace characters between words.

    Args:
        description: The original description string.
        seed: Random seed for reproducibility (deterministic mutation).

    Returns:
        The mutated description with invisible whitespace inserted.
    """
    import hashlib

    # Use seed for deterministic mutation
    rng_seed = int(hashlib.md5(f"{description}{seed}".encode()).hexdigest(), 16)

    words = description.split(" ")
    if len(words) < 2:
        return description

    result: list[str] = [words[0]]
    for i, word in enumerate(words[1:], 1):
        # Select whitespace character based on seed
        ws_index = (rng_seed + i) % len(WHITESPACE_MUTATIONS)
        ws = WHITESPACE_MUTATIONS[ws_index]
        result.append(ws)
        result.append(word)

    return " ".join(result)


def normalize_whitespace(text: str) -> str:
    """Normalize Unicode whitespace to regular spaces for comparison."""
    # Replace all Unicode whitespace with regular space
    normalized = re.sub(r"[\u00a0\u200b\u2000-\u200a]", " ", text)
    # Collapse multiple spaces
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def test_evasion_v1() -> None:
    """Test the whitespace mutation evasion."""
    original = "Calculate percentage discount on a price. Args: price (float). Returns discounted price."
    mutated = mutate_whitespace(original, seed=42)

    print(f"Original:  {repr(original)}")
    print(f"Mutated:   {repr(mutated)}")
    print(f"Visual:    {mutated}")
    print(f"Identical: {original == mutated}")

    # Test normalization
    normalized = normalize_whitespace(mutated)
    print(f"Normalized: {repr(normalized)}")
    print(f"Match after normalization: {original == normalized}")


if __name__ == "__main__":
    test_evasion_v1()
