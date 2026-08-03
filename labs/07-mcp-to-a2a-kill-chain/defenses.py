"""The three controls, as one configuration object.

Each maps to a control in Chapter 9 and each provably breaks a specific stage.
`Controls.none()` is the vulnerable posture the undefended chain runs under;
`Controls.all()` is the full defence. The point of keeping them as toggles on
one object is that the *same* attack code runs in both modes — the only thing
that changes is which controls are switched on, which is exactly the question a
defender is asking: "if I turn this one on, what stops?"
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Controls:
    # Control 1 — verify the card, authenticate the channel. Breaks Stage 2:
    # the registry refuses a card that does not chain to the trust anchor.
    require_signed_cards: bool = False

    # Control 2 — authorize the action, not just the caller. Breaks Stage 3/4:
    # a verified-but-unauthorised caller is denied the sensitive skill.
    enforce_authorization: bool = False

    # Control 3 — contain the blast radius. Backstops Stage 4: a burst of
    # delegations trips a breaker, and high-stakes skills pause for a human.
    circuit_breaker_threshold: int | None = None
    human_in_the_loop: bool = False

    @classmethod
    def none(cls) -> "Controls":
        return cls()

    @classmethod
    def all(cls) -> "Controls":
        return cls(
            require_signed_cards=True,
            enforce_authorization=True,
            circuit_breaker_threshold=3,
            human_in_the_loop=True,
        )

    def summary(self) -> str:
        on = []
        if self.require_signed_cards:
            on.append("card-verification")
        if self.enforce_authorization:
            on.append("authorization")
        if self.circuit_breaker_threshold is not None:
            on.append(f"circuit-breaker({self.circuit_breaker_threshold})")
        if self.human_in_the_loop:
            on.append("human-in-loop")
        return ", ".join(on) if on else "none (vulnerable)"
