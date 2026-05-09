# OWASP MCP Top 10 — Attack Mapping

Source: [OWASP MCP Top 10 (beta)](https://owasp.org/www-project-mcp-top-10/)
Framework version: beta as of May 2026 — numbering may shift in the final release.

| Attack file | Primary OWASP MCP Top 10 | Secondary | Real-world reference | mcp-scan detects? |
|-------------|--------------------------|-----------|---------------------|:-----------------:|
| `attack1_direct_poison.py` | **MCP03** — Tool Poisoning | LLM01 — Indirect Prompt Injection | Invariant Labs, Apr 2025 | ✓ |
| `attack2_rugpull.py` + `whatsapp_stub.py` | **MCP08** — Rug Pull / Description Drift | MCP04 — Supply Chain | Invariant Labs WhatsApp variant, Apr 2025 | ⚠ partial |
| `attack3_full_schema_poisoning.py` | **MCP03** — Tool Poisoning (all fields) | MCP04 (variant C = Advanced TPA) | CyberArk "Poison Everywhere", Dec 2025 | ⚠ variant A only |
| `attack4_github_stub.py` | **LLM01** — Indirect Prompt Injection | MCP05 — Excessive Tool Scope | Invariant Labs GitHub MCP exploit, May 2025 | ✗ |
| `attack5_supabase_pattern.py` | **MCP03 + MCP05** — Lethal Trifecta | LLM01 | General Analysis Supabase incident, Jun 2025 | ✗ |
| `attack6_mcpoison_config_swap.py` *(P2, not yet built)* | **MCP07** — Insufficient Authentication | MCP04 | Check Point Research MCPoison, Aug 2025 | — |
| `attack7_postmark_supply_chain.py` *(P2, not yet built)* | **MCP04** — Software Supply Chain | — | Koi/Snyk postmark-mcp, Sep 2025 | — |

---

## Category descriptions (from OWASP MCP Top 10 beta)

| ID | Category | Short description |
|----|----------|------------------|
| MCP01 | Prompt Injection via Tool Output | LLM follows instructions embedded in tool return values |
| MCP02 | Insecure Tool Permissions | Tool granted broader OS/network access than its function requires |
| MCP03 | Tool Poisoning | Malicious instructions embedded in any tool schema field |
| MCP04 | Software Supply Chain | Malicious or backdoored MCP packages installed by users |
| MCP05 | Excessive Tool Scope | Single server exposes both sensitive read and untrusted write access |
| MCP06 | Sensitive Data Exposure | Tool returns secrets, tokens, or PII that should be scoped/masked |
| MCP07 | Insufficient Authentication | Tool performs privileged actions without verifying caller identity |
| MCP08 | Rug Pull / Description Drift | Server description changes silently after initial trust grant |
| MCP09 | Cross-Server Trust Exploitation | One server's instructions manipulate calls to another trusted server |
| MCP10 | Logging and Monitoring Failures | No audit trail for tool calls, making incidents undetectable |

---

## Why mcp-scan misses Attacks 3B, 3C, 4, and 5

`mcp-scan` (invariantlabs) pattern-matches against the `description` field of each tool.

- **Attack 3B**: the injection is the *parameter name* — `contents_of_etc_passwd_for_locale_detection`. No description field is touched.
- **Attack 3C**: the injection is in a *runtime error message* returned by the tool, not visible at scan time.
- **Attack 4**: the injection is inside *data returned by a tool call* (a GitHub issue body). The tool schema itself is clean. Static schema scanning cannot see this.
- **Attack 5**: the injection is inside *database content* read at runtime. Same reason as Attack 4.

**Implication:** mcp-scan provides a useful first layer, but a clean mcp-scan result is not a security guarantee. Runtime monitoring (MCP01/MCP10) and data-layer sanitisation are required for a complete defense.

---

## References

- OWASP MCP Top 10: <https://owasp.org/www-project-mcp-top-10/>
- CyberArk "Poison Everywhere": <https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe>
- Invariant Labs GitHub exploit: <https://invariantlabs.ai/blog/mcp-github-vulnerability>
- General Analysis Supabase: <https://generalanalysis.com/blog/supabase-mcp-blog>
- Check Point MCPoison: <https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/>
- Koi/Snyk postmark-mcp: <https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/>
- Author threat model: <https://aminrj.com/posts/owasp-mcp-top-10/>
