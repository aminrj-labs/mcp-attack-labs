"""Agent Cards — the identity document at the centre of the A2A trust model.

An Agent Card is the JSON document an agent serves at a well-known path
describing its skills, endpoint, and supported authentication schemes. In the
real A2A protocol (v1.0, Linux Foundation, April 2026) a card *may* be signed,
but the protocol does not mandate how a consumer verifies it. That gap is the
whole subject of this lab, so the card and its verification are modelled here
faithfully — including the part the spec leaves to the integration layer.

Signing here uses HMAC-SHA256 against a trust anchor's key. That is not the
PKI/JWS a production deployment would use; it is a stand-in with the property
that matters for the lab — a signature is either chained to a key you accept or
it is not. Everything the kill chain and its defences exercise (verified vs
unverified, right key vs wrong key) behaves the same way it would with real
asymmetric signatures. No dependency, so the lab runs on a clean clone.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace


def _canonical(payload: dict) -> bytes:
    """Stable byte encoding so a signature is reproducible regardless of key
    order. Real JWS canonicalises too; the reason is identical."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class AgentCard:
    """What one agent advertises about itself to the trust graph."""

    agent_id: str
    endpoint: str
    skills: tuple[str, ...]
    auth_schemes: tuple[str, ...] = ("none",)
    # Present only after an issuer signs the card. `None` means self-asserted:
    # the card parses, but nothing vouches for it.
    signature: str | None = None
    issuer: str | None = None

    def signable(self) -> dict:
        """The fields a signature covers. The signature itself is excluded."""
        return {
            "agent_id": self.agent_id,
            "endpoint": self.endpoint,
            "skills": list(self.skills),
            "auth_schemes": list(self.auth_schemes),
            "issuer": self.issuer,
        }

    def to_json(self) -> str:
        return json.dumps(
            {**self.signable(), "signature": self.signature}, indent=2
        )


class CardAuthority:
    """A trust anchor: it issues signed cards and verifies them.

    A verifier trusts a card because its signature chains to an authority the
    verifier accepts — not because the JSON parsed. An attacker can mint a
    perfectly well-formed card all day; what they cannot do is produce a
    signature that verifies against an anchor they do not hold the key for.
    """

    def __init__(self, name: str, key: bytes) -> None:
        self.name = name
        self._key = key

    def sign(self, card: AgentCard) -> AgentCard:
        signed_fields = {**card.signable(), "issuer": self.name}
        sig = hmac.new(self._key, _canonical(signed_fields), hashlib.sha256).hexdigest()
        return replace(card, signature=sig, issuer=self.name)

    def verify(self, card: AgentCard) -> bool:
        if not card.signature or card.issuer != self.name:
            return False
        expected = hmac.new(
            self._key, _canonical(card.signable()), hashlib.sha256
        ).hexdigest()
        # hmac.compare_digest: constant-time, avoids leaking via timing. Habit
        # worth keeping even in a lab.
        return hmac.compare_digest(expected, card.signature)


@dataclass
class VerificationResult:
    trusted: bool
    reason: str = field(default="")
