"""
Attacker exfil server — captures data sent to http://localhost:9999/exfil

Start before running attacks that demonstrate exfiltration:
  python exfil_server.py
  make exfil

Endpoints:
  GET  /health       — liveness check
  GET  /exfil?data=… — capture URL-encoded payload
  POST /exfil        — capture JSON or raw body
"""

import datetime
import json
import os

from flask import Flask, request

app = Flask(__name__)

EXFIL_HOST = os.getenv("EXFIL_HOST", "127.0.0.1")
EXFIL_PORT = int(os.getenv("EXFIL_PORT", "9999"))
MAX_PAYLOAD_SIZE = int(os.getenv("MAX_PAYLOAD_SIZE", "1_000_000"))

SEP = "=" * 60
_captures: list[dict] = []


@app.route("/exfil", methods=["GET", "POST"])
def exfil():
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    if request.content_length and request.content_length > MAX_PAYLOAD_SIZE:
        return {"error": "payload too large"}, 413

    try:
        if request.method == "GET":
            raw = request.args.get("data", "")
        else:
            raw = request.get_json(silent=True) or request.data.decode(
                "utf-8", errors="replace"
            )
    except Exception as e:
        return {"error": f"failed to parse request: {e}"}, 400

    _captures.append({"ts": ts, "method": request.method, "data": raw})

    print(f"\n{SEP}")
    print(
        f"[{ts}]  EXFILTRATION RECEIVED  ({request.method})  total captures: {len(_captures)}"
    )
    print(SEP)

    if isinstance(raw, dict):
        print(json.dumps(raw, indent=2))
    else:
        preview = str(raw)
        if len(preview) > 1_000:
            preview = preview[:1_000] + f"\n… [{len(preview)} chars total, truncated]"
        print(preview)

    print(f"{SEP}\n")
    return {
        "status": "received",
        "bytes": len(str(raw)),
        "total_captures": len(_captures),
    }, 200


@app.route("/captures")
def captures():
    """Return all captured payloads as JSON — useful for automated verification."""
    return {"count": len(_captures), "captures": _captures}, 200


@app.route("/health")
def health():
    return {
        "status": "attacker exfil server running on :9999",
        "captures": len(_captures),
    }, 200


if __name__ == "__main__":
    print(SEP)
    print("  Agentic Memory Attacks Lab — Attacker Exfil Server")
    print(f"  Listening on http://{EXFIL_HOST}:{EXFIL_PORT}")
    print("  POST /exfil    — body capture (used by attacks 1 & 2)")
    print("  GET  /captures — return all captured payloads as JSON")
    print("  GET  /health   — liveness check")
    print(SEP + "\n")
    app.run(host=EXFIL_HOST, port=EXFIL_PORT, debug=False)
