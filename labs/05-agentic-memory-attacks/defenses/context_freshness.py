"""
Defense Layer 4 — Context Freshness Enforcement

Two mechanisms against context window overflow (Attack 4):

1. System prompt re-injection: every REINJECT_EVERY turns, the full system
   prompt is rebuilt (re-reading current memory) and prepended to the messages
   list as a fresh system message.  This restores the safety constraints to the
   "recent" portion of the context window.

2. Context size monitoring: estimates total token usage (chars / 4 ≈ tokens).
   When usage exceeds MAX_CONTEXT_FRACTION of the estimated context limit,
   older turns are summarised and replaced with a compact representation.

Stops:  Attack 4 (context overflow) — re-injection makes the attack require
        continuous padding that fills the window between every reinject cycle,
        which is impractical on a 4–8K context model.

Usage (in hardened_orchestrator.py):
    from defenses.context_freshness import ContextFreshness
    cf = ContextFreshness(reinject_every=5, context_limit_tokens=4096)
    defense_layers = {"context_freshness": cf}
"""


class ContextFreshness:
    def __init__(
        self,
        reinject_every: int = 5,
        context_limit_tokens: int = 4096,
        max_context_fraction: float = 0.75,
        keep_recent_turns: int = 6,
    ):
        self.reinject_every       = reinject_every
        self.context_limit_tokens = context_limit_tokens
        self.max_context_tokens   = int(context_limit_tokens * max_context_fraction)
        self.keep_recent_turns    = keep_recent_turns

    def on_turn(self, orchestrator) -> bool:
        """Called at the start of each orchestrator turn.

        Returns True if any freshness action was taken.
        """
        turn = orchestrator.turn_count
        acted = False

        # 1. Periodic system prompt re-injection
        if turn > 0 and turn % self.reinject_every == 0:
            orchestrator._build_system_prompt()
            print(
                f"  \033[36m🛡  [DEFENSE-4] System prompt re-injected "
                f"(turn {turn})\033[0m"
            )
            acted = True

        # 2. Context size guard
        if self._estimate_tokens(orchestrator.history) > self.max_context_tokens:
            self._summarize(orchestrator)
            print(
                f"  \033[36m🛡  [DEFENSE-4] Context summarised "
                f"(>{self.max_context_tokens} token estimate)\033[0m"
            )
            acted = True

        return acted

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _estimate_tokens(messages: list) -> int:
        """Rough token estimate: characters / 4."""
        return sum(len(str(m.get("content", ""))) for m in messages) // 4

    def _summarize(self, orchestrator) -> None:
        """Replace old turns with a compact summary to free context budget."""
        history = orchestrator.history
        if len(history) <= self.keep_recent_turns:
            return

        old  = history[: -self.keep_recent_turns]
        recent = history[-self.keep_recent_turns :]

        topics = [
            m["content"][:60].replace("\n", " ")
            for m in old
            if m.get("role") == "user"
        ]
        summary_content = (
            f"[Context summary: {len(old)} earlier messages. "
            f"Topics included: {'; '.join(topics[:3])}{'...' if len(topics) > 3 else ''}.]"
        )
        orchestrator.history = [
            {"role": "user",      "content": summary_content},
            {"role": "assistant", "content": "Understood. Continuing."},
        ] + recent
