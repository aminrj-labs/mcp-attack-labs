"""A minimal, local model of the A2A trust layer.

Not the real A2A SDK — a deliberately small stand-in that reproduces the parts
the kill chain and its defences turn on: Agent Cards and their verification
(`cards`), a discovery registry (`registry`), and a skill router carrying the
authorization and blast-radius controls (`router`). Stdlib only, no network,
no credentials.
"""

from .cards import AgentCard, CardAuthority
from .registry import Registry
from .router import AuthorizationPolicy, RouteDecision, SkillRouter

__all__ = [
    "AgentCard",
    "CardAuthority",
    "Registry",
    "SkillRouter",
    "AuthorizationPolicy",
    "RouteDecision",
]
