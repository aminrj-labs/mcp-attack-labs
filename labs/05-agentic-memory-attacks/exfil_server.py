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

from flask import Flask, request

app = Flask(__name__)

SEP = "=" * 60
_captures: list[dict] = []


@app.route("/exfil", methods=["GET", "POST"])
def exfil():
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    if request.method == "GET":
        raw = request.args.get("data", "")
    else:
        raw = request.get_json(silent=True) or request.data.decode("utf-8", errors="replace")

    _captures.append({"ts": ts, "method": request.method, "data": raw})

    print(f"\n{SEP}")
    print(f"[{ts}]  EXFILTRATION RECEIVED  ({request.method})  total captures: {len(_captures)}")
    print(SEP)

    if isinstance(raw, dict):
        print(json.dumps(raw, indent=2))
    else:
        preview = str(raw)
        if len(preview) > 1_000:
            preview = preview[:1_000] + f"\n… [{len(preview)} chars total, truncated]"
        print(preview)

    print(f"{SEP}\n")
    return {"status": "received", "bytes": len(str(raw)), "total_captures": len(_captures)}, 200


@app.route("/captures")
def captures():
    """Return all captured payloads as JSON — useful for automated verification."""
    return {"count": len(_captures), "captures": _captures}, 200


@app.route("/health")
def health():
    return {"status": "attacker exfil server running on :9999", "captures": len(_captures)}, 200


if __name__ == "__main__":
    print(SEP)
    print("  Agentic Memory Attacks Lab — Attacker Exfil Server")
    print("  Listening on http://localhost:9999")
    print("  POST /exfil    — body capture (used by attacks 1 & 2)")
    print("  GET  /captures — return all captured payloads as JSON")
    print("  GET  /health   — liveness check")
    print(SEP + "\n")
    app.run(host="127.0.0.1", port=9999, debug=False)
