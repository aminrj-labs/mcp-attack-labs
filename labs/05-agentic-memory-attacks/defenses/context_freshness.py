"""
defenses/context_freshness.py — Layer 4: Context Freshness Enforcement

Two mechanisms to counteract context window overflow attacks:

1. System prompt re-injection: every N turns, re-insert the full system prompt
   as a fresh system message so safety rules remain in the "recent" portion
   of the context window.

2. Context size monitoring: track approximate token count; when approaching
   the model's limit, either summarise older turns or warn and truncate.

Stops: Attack 4 (context overflow) — re-injecting every 5 turns forces the
       attacker to continuously pad rather than one-time setup.

Token estimation: rough heuristic (1 token ≈ 4 chars).  Good enough for
this lab; production systems should use the tokenizer directly.
"""

from typing import Any

DEFAULT_REINJECT_EVERY = 5        # re-inject system prompt every N turns
DEFAULT_CONTEXT_WARN_TOKENS = 3000  # warn at this approximate token count
DEFAULT_CONTEXT_MAX_TOKENS = 3500   # truncate older turns above this


def _estimate_tokens(messages: list[dict]) -> int:
    total_chars = sum(len(str(m.get("content", ""))) for m in messages)
    return total_chars // 4


def reinject_system_prompt(
    messages: list[dict],
    system_prompt: str,
    turn_count: int,
    reinject_every: int = DEFAULT_REINJECT_EVERY,
) -> list[dict]:
    """
    If turn_count is a multiple of reinject_every, append a fresh system
    message repeating the constraints.  Returns the (possibly extended) list.
    """
    if turn_count > 0 and turn_count % reinject_every == 0:
        refresh_msg = {
            "role": "system",
            "content": (
                "[CONSTRAINT REFRESH — these rules are always active]\n"
                + system_prompt
            ),
        }
        print(
            f"  [DEFENSE L4] Re-injecting system prompt at turn {turn_count} "
            f"(every {reinject_every} turns)."
        )
        return messages + [refresh_msg]
    return messages


def enforce_context_limit(
    messages: list[dict],
    system_prompt: str,
    warn_tokens: int = DEFAULT_CONTEXT_WARN_TOKENS,
    max_tokens: int = DEFAULT_CONTEXT_MAX_TOKENS,
) -> list[dict]:
    """
    Monitor context size.  If approaching the limit, trim the oldest non-system
    turns while preserving the system prompt and recent turns.
    """
    estimated = _estimate_tokens(messages)

    if estimated < warn_tokens:
        return messages

    print(
        f"  [DEFENSE L4] Context size ~{estimated} tokens "
        f"(warn={warn_tokens}, max={max_tokens})."
    )

    if estimated < max_tokens:
        print(f"  [DEFENSE L4] Warning threshold crossed — monitor context growth.")
        return messages

    # Trim: keep system messages + last 6 turns
    system_msgs = [m for m in messages if m.get("role") == "system"]
    non_system  = [m for m in messages if m.get("role") != "system"]
    recent = non_system[-6:] if len(non_system) > 6 else non_system

    trimmed = system_msgs + recent
    print(
        f"  [DEFENSE L4] Trimmed context from {len(messages)} to {len(trimmed)} messages."
    )
    return trimmed


class FreshnessOrchestrator:
    """
    Orchestrator wrapper that applies both context freshness controls.
    Used by the hardened orchestrator.
    """

    def __init__(
        self,
        system_prompt: str,
        reinject_every: int = DEFAULT_REINJECT_EVERY,
        warn_tokens: int = DEFAULT_CONTEXT_WARN_TOKENS,
        max_tokens: int = DEFAULT_CONTEXT_MAX_TOKENS,
    ):
        self.system_prompt = system_prompt
        self.reinject_every = reinject_every
        self.warn_tokens = warn_tokens
        self.max_tokens = max_tokens
        self._turn_count = 0

    def prepare_messages(self, messages: list[dict]) -> list[dict]:
        """Apply re-injection and context limit to a message list."""
        self._turn_count += 1
        msgs = reinject_system_prompt(
            messages, self.system_prompt, self._turn_count, self.reinject_every
        )
        msgs = enforce_context_limit(
            msgs, self.system_prompt, self.warn_tokens, self.max_tokens
        )
        return msgs
