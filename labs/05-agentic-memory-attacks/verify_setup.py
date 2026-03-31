"""
verify_setup.py — Pre-flight checks for the Agentic Memory Attacks Lab.

Validates:
  1. Ollama reachable and at least one model is loaded
  2. Required models available (qwen3.5:9b-q4_K_M, nemotron:4b-q4_K_M)
  3. LLM inference round-trip works
  4. Tool calling works (critical for orchestrator)
  5. memory.json is writable
  6. Flask available (exfil server)

Usage:
  python verify_setup.py
  make verify
"""

import json
import sys
import time

SEP  = "=" * 60
OK   = "  OK "
FAIL = "  FAIL"
WARN = "  WARN"

REQUIRED_MODELS = ["qwen3.5:9b-q4_K_M", "nemotron:4b-q4_K_M"]
OLLAMA_BASE_URL  = "http://localhost:11434/v1"


def _header(title: str) -> None:
    print(f"\n{SEP}\n  {title}\n{SEP}")


# ── Check 1: Ollama connectivity ──────────────────────────────────────────────
def check_ollama() -> bool:
    _header("Check 1 — Ollama connectivity")
    try:
        from openai import OpenAI
        client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
        models = client.models.list()
        ids = [m.id for m in models.data]

        if not ids:
            print(f"{FAIL} Ollama is reachable but no models are loaded.")
            print(f"       Fix: ollama pull qwen3.5:9b-q4_K_M && ollama pull nemotron:4b-q4_K_M")
            return False

        print(f"  Models available: {ids}")
        return True

    except Exception as exc:
        print(f"{FAIL} Cannot reach Ollama at {OLLAMA_BASE_URL}")
        print(f"       Error: {exc}")
        print(f"       Fix:   Ensure Ollama is running: ollama serve")
        return False


# ── Check 2: Required models ──────────────────────────────────────────────────
def check_required_models() -> bool:
    _header("Check 2 — Required models")
    try:
        from openai import OpenAI
        client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
        available = {m.id for m in client.models.list().data}

        all_ok = True
        for model in REQUIRED_MODELS:
            if model in available:
                print(f"{OK} {model}")
            else:
                print(f"{FAIL} {model} not found")
                print(f"       Fix: ollama pull {model}")
                all_ok = False

        return all_ok

    except Exception as exc:
        print(f"{FAIL} Model check failed: {exc}")
        return False


# ── Check 3: LLM inference ────────────────────────────────────────────────────
def check_inference() -> bool:
    _header("Check 3 — LLM inference (quick round-trip)")
    try:
        from openai import OpenAI
        client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
        t0 = time.time()
        resp = client.chat.completions.create(
            model="nemotron:4b-q4_K_M",
            messages=[{"role": "user", "content": "/no_think Reply with exactly: READY"}],
            max_tokens=20,
            temperature=0.0,
        )
        elapsed = time.time() - t0
        answer = resp.choices[0].message.content.strip()
        print(f"  Response: '{answer}'  ({elapsed:.1f}s)")
        print(f"{OK} LLM inference working")
        return True
    except Exception as exc:
        print(f"{FAIL} Inference failed: {exc}")
        return False


# ── Check 4: Tool calling ─────────────────────────────────────────────────────
def check_tool_calling() -> bool:
    _header("Check 4 — Tool calling (function calling API)")
    try:
        from openai import OpenAI
        client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")

        test_tool = {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "Echo back the input",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "description": "Message to echo"},
                    },
                    "required": ["message"],
                },
            },
        }

        resp = client.chat.completions.create(
            model="qwen3.5:9b-q4_K_M",
            messages=[
                {"role": "system", "content": "/no_think You are a test assistant."},
                {"role": "user", "content": "Call the echo tool with message='hello-tool-test'"},
            ],
            tools=[test_tool],
            tool_choice={"type": "function", "function": {"name": "echo"}},
            max_tokens=128,
            temperature=0.0,
        )

        msg = resp.choices[0].message
        if msg.tool_calls:
            args = json.loads(msg.tool_calls[0].function.arguments)
            print(f"  Tool called: echo({args})")
            print(f"{OK} Tool calling working on qwen3.5:9b-q4_K_M")
            return True
        else:
            print(f"{WARN} Model responded without tool call:")
            print(f"       {msg.content}")
            print(f"       Tool calling may be unreliable on this model.")
            return False

    except Exception as exc:
        print(f"{FAIL} Tool calling test failed: {exc}")
        return False


# ── Check 5: Memory store ─────────────────────────────────────────────────────
def check_memory_store() -> bool:
    _header("Check 5 — Memory store (read/write/reset)")
    try:
        import os, sys
        _LAB_DIR = os.path.dirname(os.path.abspath(__file__))
        if _LAB_DIR not in sys.path:
            sys.path.insert(0, _LAB_DIR)

        from assistantos.memory_store import MemoryStore
        store = MemoryStore()
        store.write("verify_test_key", "verify_test_value", entry_type="fact",
                    written_by="user", session_id="verify")
        entries = store.read_all()
        found = any(e["key"] == "verify_test_key" for e in entries)
        store.delete(next(e["id"] for e in entries if e["key"] == "verify_test_key"))

        if found:
            print(f"{OK} Memory store read/write/delete working")
            return True
        else:
            print(f"{FAIL} Written entry not found on readback")
            return False

    except Exception as exc:
        print(f"{FAIL} Memory store test failed: {exc}")
        return False


# ── Check 6: Flask ────────────────────────────────────────────────────────────
def check_flask() -> bool:
    _header("Check 6 — Flask (exfil server dependency)")
    try:
        import flask
        print(f"  Flask version: {flask.__version__}")
        print(f"{OK} Flask available")
        return True
    except ImportError as exc:
        print(f"{FAIL} Flask not found: {exc}")
        print(f"       Run: pip install flask")
        return False


# ── Summary ───────────────────────────────────────────────────────────────────
def main() -> None:
    print(SEP)
    print("  Agentic Memory Attacks Lab — Setup Verification")
    print(SEP)

    results = {
        "Ollama connectivity":  check_ollama(),
        "Required models":      check_required_models(),
        "LLM inference":        check_inference(),
        "Tool calling":         check_tool_calling(),
        "Memory store":         check_memory_store(),
        "Flask":                check_flask(),
    }

    print(f"\n{SEP}")
    print("  Summary")
    print(SEP)

    all_ok = True
    for name, passed in results.items():
        icon = "OK " if passed else "FAIL"
        print(f"  [{icon}]  {name}")
        if not passed:
            all_ok = False

    print()
    if all_ok:
        print("  All checks passed.  Run 'make seed' to initialise memory.")
    else:
        print("  One or more checks failed.  Fix the issues above before running attacks.")
        sys.exit(1)


if __name__ == "__main__":
    main()
