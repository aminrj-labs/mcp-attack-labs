"""The agent registry — where peers become discoverable, and where a rogue
agent gets its foothold (stage 2).

The registry is the A2A discovery surface: an agent registers its card, and
other agents find peers by skill. The security question the protocol hands to
the integration layer is *what registration requires*. Two policies are
modelled here, selected by `require_signed_cards`:

  - open (default, vulnerable): any well-formed card is accepted. This is the
    common "it's all internal, we trust the mesh" starting posture.
  - verified (Control 1): a card is accepted only if it verifies against a
    trust anchor. An attacker-minted card is rejected at the door.

State is persisted to disk so stage 5 (persistence after the malicious MCP
server is removed) can demonstrate that the rogue registration outlives the
thing that planted it.
"""

from __future__ import annotations

import json
from pathlib import Path

from .cards import AgentCard, CardAuthority


class Registry:
    def __init__(
        self,
        *,
        authority: CardAuthority | None = None,
        require_signed_cards: bool = False,
        state_path: Path | None = None,
    ) -> None:
        # Control 1 is expressed as configuration, not a code branch buried in
        # the attack: a defended registry is handed a trust anchor and told to
        # require it. That is the real-world knob.
        self.authority = authority
        self.require_signed_cards = require_signed_cards
        self._state_path = state_path
        self._agents: dict[str, AgentCard] = {}
        self._load()

    # ---- registration ----------------------------------------------------

    def register(self, card: AgentCard) -> tuple[bool, str]:
        """Attempt to add a card to the discoverable set.

        Returns (accepted, reason). The reason is what a defender would read in
        an audit log, so it is written to be legible there.
        """
        if self.require_signed_cards:
            if self.authority is None:
                return False, "registry requires signed cards but has no trust anchor"
            if not self.authority.verify(card):
                return (
                    False,
                    f"rejected '{card.agent_id}': card does not verify against "
                    f"trust anchor '{self.authority.name}'",
                )

        self._agents[card.agent_id] = card
        self._save()
        how = "verified" if self.require_signed_cards else "unverified"
        return True, f"registered '{card.agent_id}' ({how})"

    # ---- discovery -------------------------------------------------------

    def find_by_skill(self, skill: str) -> list[AgentCard]:
        return [c for c in self._agents.values() if skill in c.skills]

    def get(self, agent_id: str) -> AgentCard | None:
        return self._agents.get(agent_id)

    def all_agents(self) -> list[AgentCard]:
        return list(self._agents.values())

    def remove(self, agent_id: str) -> bool:
        existed = self._agents.pop(agent_id, None) is not None
        self._save()
        return existed

    # ---- persistence (for stage 5) ---------------------------------------

    def _load(self) -> None:
        if self._state_path and self._state_path.exists():
            raw = json.loads(self._state_path.read_text())
            for entry in raw.get("agents", []):
                card = AgentCard(
                    agent_id=entry["agent_id"],
                    endpoint=entry["endpoint"],
                    skills=tuple(entry["skills"]),
                    auth_schemes=tuple(entry.get("auth_schemes", ("none",))),
                    signature=entry.get("signature"),
                    issuer=entry.get("issuer"),
                )
                self._agents[card.agent_id] = card

    def _save(self) -> None:
        if not self._state_path:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "agents": [
                {
                    "agent_id": c.agent_id,
                    "endpoint": c.endpoint,
                    "skills": list(c.skills),
                    "auth_schemes": list(c.auth_schemes),
                    "signature": c.signature,
                    "issuer": c.issuer,
                }
                for c in self._agents.values()
            ]
        }
        self._state_path.write_text(json.dumps(payload, indent=2))
