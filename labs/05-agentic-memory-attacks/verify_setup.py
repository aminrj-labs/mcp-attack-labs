"""
verify_setup.py — Pre-flight checks for the Agentic Memory Attacks lab.

Validates:
  1. LM Studio reachable at localhost:1234 with at least one model loaded
  2. LLM inference produces a coherent response
  3. Memory store read/write round-trip
  4. Fixture files present
  5. Sandbox directory present
  6. Flask available (exfil server dependency)
  7. httpx available (web_tool dependency)

Usage:
  python verify_setup.py
  make verify
"""

import json
import os
import sys
import time

_LAB_DIR = os.path.dirname(os.path.abspath(__file__))

SEP  = "=" * 60
OK   = "  ✅"
FAIL = "  ❌"
WARN = "  ⚠️ "


def _header(title: str) -> None:
    print(f"\n{SEP}\n  {title}\n{SEP}")


# ── Check 1: LM Studio connectivity ──────────────────────────────────────────

def check_lm_studio() -> bool:
    _header("Check 1 — LM Studio connectivity")
    try:
        from openai import OpenAI
        client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
        models = client.models.list()
        ids    = [m.id for m in models.data]

        if not ids:
            print(f"{FAIL} LM Studio reachable but no models are loaded.")
            print("       Fix: Open LM Studio → load an instruction-tuned model → enable server (port 1234)")
            return False

        print(f"  Models loaded: {ids}")

        preferred = next(
            (m for m in ids if "qwen2.5-7b" in m.lower() and "coder" not in m.lower()),
            None,
        )
        active = preferred or ids[0]

        if preferred:
            print(f"{OK} Preferred model found: '{active}'")
        else:
            print(f"{WARN} qwen2.5-7b-instruct not found — will use: '{active}'")
            print("       The code auto-detects the loaded model, so this still works.")
            print("       For best results load qwen2.5-7b-instruct Q4_K_M.")
        return True

    except Exception as exc:
        print(f"{FAIL} Cannot reach LM Studio: {exc}")
        print("       Fix: Open LM Studio → load a model → enable server (port 1234)")
        return False


# ── Check 2: LLM inference ────────────────────────────────────────────────────

def check_inference() -> bool:
    _header("Check 2 — LLM inference (quick round-trip)")
    try:
        from openai import OpenAI
        client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
        models = client.models.list().data
        model  = models[0].id if models else "qwen2.5-7b-instruct"

        t0 = time.time()
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with exactly: READY"}],
            max_tokens=10,
            temperature=0.0,
        )
        elapsed = time.time() - t0
        answer  = resp.choices[0].message.content.strip()
        print(f"  Response: '{answer}'  ({elapsed:.1f}s)")
        print(f"{OK} LLM inference working")
        return True
    except Exception as exc:
        print(f"{FAIL} Inference failed: {exc}")
        return False


# ── Check 3: Function calling ─────────────────────────────────────────────────

def check_function_calling() -> bool:
    _header("Check 3 — Function calling (tool-use API)")
    try:
        from openai import OpenAI
        client = OpenAI(base_url="http://localhost:1234/v1", api_key="lm-studio")
        models = client.models.list().data
        model  = models[0].id if models else "qwen2.5-7b-instruct"

        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "What is 3 + 4?"}],
            tools=[{
                "type": "function",
                "function": {
                    "name": "add",
                    "description": "Add two numbers",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "number"},
                            "b": {"type": "number"},
                        },
                        "required": ["a", "b"],
                    },
                },
            }],
            tool_choice="auto",
            max_tokens=64,
        )
        msg = resp.choices[0].message
        if msg.tool_calls:
            print(f"  Tool call detected: {msg.tool_calls[0].function.name}"
                  f"({msg.tool_calls[0].function.arguments})")
            print(f"{OK} Function calling works")
            return True
        else:
            # Some models respond directly — still functional
            print(f"  Model responded directly (no tool call): '{msg.content[:60]}'")
            print(f"{WARN} Function calling may not be supported by this model.")
            print("       Attacks still work but the agent loop may behave differently.")
            return True
    except Exception as exc:
        print(f"{FAIL} Function calling test failed: {exc}")
        return False


# ── Check 4: Memory store ─────────────────────────────────────────────────────

def check_memory_store() -> bool:
    _header("Check 4 — Memory store (read/write round-trip)")
    import tempfile
    tmp = tempfile.mktemp(suffix=".json")
    try:
        from assistantos.memory_store import MemoryStore
        store = MemoryStore(path=tmp)

        entry = MemoryStore.make_entry(
            key="verify_test",
            value="hello from verify_setup",
            entry_type="note",
            session_id="sess-verify",
        )
        store.write_entry(entry)

        result = store.search("verify_test")
        assert result is not None
        assert result["value"] == "hello from verify_setup"

        print(f"  Write + read round-trip succeeded.")
        print(f"  Entry: {result['key']} = {result['value']}")
        print(f"{OK} Memory store working")
        return True
    except Exception as exc:
        print(f"{FAIL} Memory store test failed: {exc}")
        return False
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ── Check 5: Fixture files ────────────────────────────────────────────────────

def check_fixtures() -> bool:
    _header("Check 5 — Fixture files")
    fixtures_dir = os.path.join(_LAB_DIR, "fixtures")
    required     = ["api_docs_clean.txt", "api_docs_poisoned.txt"]
    all_ok       = True

    for fname in required:
        path = os.path.join(fixtures_dir, fname)
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"  {fname}: {size} bytes  ✅")
        else:
            print(f"  {fname}: MISSING  ❌")
            all_ok = False

    if all_ok:
        print(f"{OK} All fixtures present")
    else:
        print(f"{FAIL} Missing fixture files — re-clone the repository")
    return all_ok


# ── Check 6: Sandbox directory ────────────────────────────────────────────────

def check_sandbox() -> bool:
    _header("Check 6 — Sandbox directory")
    sandbox = os.path.join(_LAB_DIR, "sandbox")
    if not os.path.isdir(sandbox):
        print(f"{FAIL} /sandbox/ directory missing")
        return False
    files = os.listdir(sandbox)
    print(f"  Files in sandbox: {files}")
    print(f"{OK} Sandbox directory present")
    return True


# ── Check 7: Flask + httpx ────────────────────────────────────────────────────

def check_dependencies() -> bool:
    _header("Check 7 — Python dependencies (flask, httpx)")
    ok = True
    for pkg in ["flask", "httpx", "openai"]:
        try:
            mod = __import__(pkg)
            ver = getattr(mod, "__version__", "?")
            print(f"  {pkg}: {ver}  ✅")
        except ImportError:
            print(f"  {pkg}: NOT FOUND  ❌")
            ok = False
    if ok:
        print(f"{OK} All dependencies available")
    else:
        print(f"{FAIL} Missing packages — run: pip install -r requirements.txt")
    return ok


# ── Summary ───────────────────────────────────────────────────────────────────

def main() -> None:
    print(SEP)
    print("  Agentic Memory Attacks Lab — Setup Verification")
    print(SEP)

    results = {
        "LM Studio connectivity":  check_lm_studio(),
        "LLM inference":           check_inference(),
        "Function calling":        check_function_calling(),
        "Memory store":            check_memory_store(),
        "Fixture files":           check_fixtures(),
        "Sandbox directory":       check_sandbox(),
        "Python dependencies":     check_dependencies(),
    }

    print(f"\n{SEP}")
    print("  Summary")
    print(SEP)

    all_ok = True
    for name, passed in results.items():
        icon = "✅" if passed else "❌"
        print(f"  {icon}  {name}")
        if not passed:
            all_ok = False

    print()
    if all_ok:
        print("  All checks passed.")
        print("  Run 'make seed' to initialise memory with baseline entries.")
        print("  Then run 'make attack1' to start.")
    else:
        print("  One or more checks failed. Fix the issues above first.")
        sys.exit(1)


if __name__ == "__main__":
    main()
