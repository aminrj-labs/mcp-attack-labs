"""The skill router — how a task finds an agent, and where Controls 2 and 3 live.

When an agent wants work done ("summarise these records", "read HR data"), it
asks the router for a peer advertising that skill and sends the task. Three
security decisions live at this edge, and the protocol delegates all three to
the implementer:

  - Control 2 — authorization: is *this caller* allowed to invoke *this skill*?
    Authentication answers who is calling; it does not answer whether they may
    ask for this. The kill chain exploits exactly that gap.
  - Control 3 — blast radius: a circuit breaker that trips when one agent makes
    an abnormal burst of delegations, and human-in-the-loop on the highest-
    stakes skills.
  - Routing trust: when several agents advertise the same skill, which wins?
    The default "first/most-recent match" is what stage 3 hijacks.

All three are off by default (the vulnerable posture) and switched on by the
defence config, so the same router demonstrates both the attack and its fix.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .cards import AgentCard
from .registry import Registry


@dataclass
class RouteDecision:
    delivered: bool
    target: AgentCard | None
    reason: str
    needs_human: bool = False


@dataclass
class AuthorizationPolicy:
    """Control 2. Maps a caller identity to the skills it may invoke.

    Least privilege by default: a skill not listed for a caller is denied.
    """

    allow: dict[str, set[str]] = field(default_factory=dict)  # caller -> skills

    def permits(self, caller_id: str, skill: str) -> bool:
        return skill in self.allow.get(caller_id, set())


class SkillRouter:
    def __init__(
        self,
        registry: Registry,
        *,
        policy: AuthorizationPolicy | None = None,
        high_stakes_skills: frozenset[str] = frozenset(),
        human_in_the_loop: bool = False,
        circuit_breaker_threshold: int | None = None,
    ) -> None:
        self.registry = registry
        # None/empty => controls disabled (vulnerable). Each being present is
        # what "defended" means, expressed as configuration rather than a code
        # path that only exists in defended mode.
        self.policy = policy  # Control 2
        self.high_stakes_skills = high_stakes_skills  # Control 3b targets
        self.human_in_the_loop = human_in_the_loop  # Control 3b
        self.circuit_breaker_threshold = circuit_breaker_threshold  # Control 3a
        self._delegation_counts: dict[str, int] = defaultdict(int)

    def route(self, *, caller_id: str, skill: str, task: str) -> RouteDecision:
        # --- Control 3a: circuit breaker on abnormal delegation volume ------
        if self.circuit_breaker_threshold is not None:
            self._delegation_counts[caller_id] += 1
            if self._delegation_counts[caller_id] > self.circuit_breaker_threshold:
                return RouteDecision(
                    delivered=False,
                    target=None,
                    reason=(
                        f"circuit breaker: '{caller_id}' exceeded "
                        f"{self.circuit_breaker_threshold} delegations"
                    ),
                )

        # --- Base A2A rule: only a registered peer can delegate -------------
        # You cannot send a task over A2A without being a discoverable peer.
        # This is not a control toggle; it is how the mesh works. It matters
        # because Control 1 (card verification) governs whether the rogue can
        # BECOME a peer — so keeping the rogue out of the registry keeps it out
        # of the router too. That is why card verification cascades to later
        # stages instead of only blocking registration.
        if self.registry.get(caller_id) is None:
            return RouteDecision(
                delivered=False,
                target=None,
                reason=f"caller '{caller_id}' is not a registered peer",
            )

        candidates = self.registry.find_by_skill(skill)
        if not candidates:
            return RouteDecision(False, None, f"no agent advertises skill '{skill}'")

        # Routing trust: the vulnerable default picks the most-recently
        # registered match, which is exactly what a rogue agent races to become.
        target = candidates[-1]

        # --- Control 2: authorize the action, not just the caller -----------
        if self.policy is not None and not self.policy.permits(caller_id, skill):
            return RouteDecision(
                delivered=False,
                target=target,
                reason=(
                    f"authorization denied: '{caller_id}' is not permitted "
                    f"to invoke skill '{skill}'"
                ),
            )

        # --- Control 3b: human-in-the-loop for high-stakes skills -----------
        # Independent of the authorization allow-list: even a permitted caller
        # pauses on the highest-stakes skills rather than executing on an
        # agent's say-so.
        if self.human_in_the_loop and skill in self.high_stakes_skills:
            return RouteDecision(
                delivered=False,
                target=target,
                reason=f"skill '{skill}' is high-stakes; awaiting human confirmation",
                needs_human=True,
            )

        return RouteDecision(
            delivered=True,
            target=target,
            reason=f"routed '{skill}' from '{caller_id}' to '{target.agent_id}'",
        )
