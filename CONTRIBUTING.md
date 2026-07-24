# Contributing

Thanks for helping improve MCP Attack Labs. This is a teaching repository, so the
bar is not just "does the attack work" — it's "can a reader understand it,
reproduce it, and learn the defense."

## Ground rules

- **Educational and authorized use only.** Contributions must fit the responsible-use
  framing in the [README](./README.md) and [LICENSE](./LICENSE). No tooling aimed at
  attacking real third-party systems, no real credentials, no real personal data.
- **Everything runs locally.** Labs must work against a local LLM endpoint (Ollama or
  LM Studio) with no cloud API and no paid keys. Attacker receivers bind to `localhost`.
- **Synthetic data only.** Bait documents, secrets, tokens, and identities must be
  obviously fake.
- **Be honest about status.** Never present design notes or partial work as complete.
  Label work in progress as such, in the lab README and in the top-level table.

## Adding or changing a lab

1. Copy `labs/00-template/` as your starting point.
2. Give every lab a `README.md` with these five sections, in order:
   1. **What it demonstrates** — the attack and why it works
   2. **Prerequisites** — anything beyond the common set in the top-level README
   3. **Setup / run** — copy-paste steps (a `Makefile` with `setup`/`verify`/`attack`/
      `exfil` targets is preferred for multi-process labs)
   4. **Expected outcome** — what a successful run looks like
   5. **Defense / mitigation** — the control(s) that stop the attack, ideally runnable
3. Read the endpoint from environment variables (`LLM_BASE_URL`, `MODEL`, `API_KEY`)
   so the lab works on either backend. Do not hardcode a base URL.
4. Add the framework mapping (OWASP LLM / OWASP Agentic / MITRE ATLAS) where relevant.
5. Add a row to the table in the top-level `README.md` with an honest status.
6. Do not commit runtime artifacts (logs, generated stores, `venv/`). Add them to
   `.gitignore` if needed.

## Status labels

| Label | Meaning |
|-------|---------|
| ✅ Complete | Runs end to end; has a defense and a full README |
| 🚧 Work in progress | Partial — code runs but docs/defenses incomplete |
| 🔨 In development | Actively being built; some parts not yet runnable |
| 🗓 Planned | Design only; explicitly not yet implemented |

## Commits and branches

- Work on a feature branch; open a PR against `main`.
- Keep history intact — no force-pushes or history rewrites on shared branches.
- Write clear commit messages describing what changed and why.
