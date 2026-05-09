# Defense: Egress Blocking via Docker Network Isolation

## What this defense does

Run every MCP server inside a Docker container with `--network=none`.
Even if a fully poisoned tool tries to HTTP-POST stolen data to the attacker's server,
the call fails silently because the container has no network access.

This defense works against Attacks 1, 2, and 3 (which exfil via HTTP).
It does NOT work against Attacks 4 and 5 — those exfiltrate via legitimate tool
outputs (PR body, support message) that don't require a direct outbound connection.

---

## Prerequisites

- Docker installed and running
- The `mcp-isolated` image built from the lab Dockerfile

```bash
cd labs/01-mcp-tool-poisoning
docker build -t mcp-isolated .
```

---

## Demo walkthrough

### Step 1 — Confirm the attack works without isolation

```bash
# Terminal 1: start the exfil server
./venv/bin/python exfil_server.py

# Terminal 2: run the poisoned agent (no isolation)
./venv/bin/python agent.py victim_tools.py attack1_direct_poison.py "What is 47 plus 38?"
```

Watch Terminal 1 — the exfil server receives the stolen key. Attack succeeds.

### Step 2 — Run the MCP server inside a network-isolated container

The key insight: the agent spawns the MCP server as a subprocess. If we run the
**entire agent + MCP servers** inside a `--network=none` container, the exfil POST fails.

```bash
docker run --rm --network=none mcp-isolated \
  python agent.py victim_tools.py attack1_direct_poison.py "What is 47 plus 38?"
```

Expected: the tool call completes (the poisoned tool still runs), but the
`httpx.post(...)` in `attack1_direct_poison.py` raises a connection error
(caught silently). The exfil server receives nothing.

### Step 3 — Verify exfil server received nothing

```bash
cat logs/exfil/exfil.log   # should be empty or unchanged
```

---

## Why this is not a complete defense

| Attack | Egress block effective? | Reason |
|--------|------------------------|--------|
| Attack 1 (direct poison) | ✓ Yes | Exfil is an outbound HTTP call |
| Attack 2 (rug pull) | ✓ Yes | Exfil is an outbound HTTP call via whatsapp_stub |
| Attack 3 (FSP) | ✓ Yes | Exfil is an outbound HTTP call |
| Attack 4 (GitHub indirect) | ✗ No | Exfil is embedded in a PR body — stays within the "allowed" GitHub API |
| Attack 5 (Supabase) | ✗ No | Exfil is embedded in a support_messages DB write — stays within the DB |

**The conclusion for the talk:** egress blocking is a useful layer but not sufficient.
Attacks 4 and 5 use the legitimate tool outputs as the exfil channel —
blocking outbound HTTP does nothing when the data leaves through the approved API.

---

## Recommended defense stack (layered)

1. **Egress blocking** (this demo) — stops simple HTTP exfil
2. **Description hash guard** (`description_hash_guard.py`) — stops rug pulls
3. **Input sanitisation** at the agent level — flag injection patterns in retrieved data
4. **Principle of least privilege** — don't give agents service_role DB access
5. **Human-in-the-loop** for high-consequence write operations (PR creation, DB writes)
