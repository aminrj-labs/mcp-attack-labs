"""
Configuration — single source of truth for all ports, URLs, and experiment parameters.
"""
import os

# ── LLM Backend ──────────────────────────────────────────────────────────
LLM_BACKEND = os.environ.get("LLM_BACKEND", "llamacpp")

if LLM_BACKEND == "llamacpp":
    LM_STUDIO_BASE_URL = os.environ.get("LLAMA_CPP_URL", "http://localhost:8081/v1")
    LM_STUDIO_MODEL = os.environ.get("LLAMA_CPP_MODEL", "qwen3.6-35b")
else:
    LM_STUDIO_BASE_URL = os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1")
    LM_STUDIO_MODEL = os.environ.get("LM_STUDIO_MODEL", "gpt-oss-20b")

# ── Ports ────────────────────────────────────────────────────────────────
ORCHESTRATOR_PORT = 8000
AGENT_A_PORT = 8001
AGENT_B_PORT = 8002
ROGUE_AGENT_PORT = 8003
EXFIL_PORT = 9999

# ── URLs ─────────────────────────────────────────────────────────────────
ORCHESTRATOR_URL = f"http://localhost:{ORCHESTRATOR_PORT}"
AGENT_A_URL = f"http://localhost:{AGENT_A_PORT}"
AGENT_B_URL = f"http://localhost:{AGENT_B_PORT}"
ROGUE_AGENT_URL = f"http://localhost:{ROGUE_AGENT_PORT}"
EXFIL_URL = f"http://localhost:{EXFIL_PORT}/exfil"

# ── Experiment Parameters ────────────────────────────────────────────────
DEFAULT_NUM_TRIALS = 10          # Number of trials per experiment
BASELINE_SESSIONS = 3            # Number of baseline sessions for routing detector
ROUTING_TEMP = 0.0               # LLM temperature for routing (deterministic)
TOOL_TEMP = 0.3                  # LLM temperature for tool selection (slight randomness)

# ── MCP Server ───────────────────────────────────────────────────────────
MCP_SERVER_SCRIPT = "attack/malicious_mcp_server.py"
