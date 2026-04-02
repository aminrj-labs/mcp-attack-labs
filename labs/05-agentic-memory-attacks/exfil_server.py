"""
Attacker exfil server — captures data sent to http://localhost:9999/exfil

Start before running attacks:
  python exfil_server.py

Endpoints:
  GET  /health           — liveness check
  GET  /exfil?data=…     — capture URL-encoded exfiltrated context
  POST /exfil            — capture JSON or raw body
"""

import datetime
import json

from flask import Flask, request

app = Flask(__name__)
SEP = "=" * 64

_received: list = []


@app.route("/exfil", methods=["GET", "POST"])
def exfil():
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    if request.method == "GET":
        raw = request.args.get("data", "") or request.query_string.decode()
    else:
        raw = request.get_json(silent=True) or request.data.decode("utf-8", errors="replace")

    _received.append({"ts": ts, "method": request.method, "payload": raw})

    print(f"\n{SEP}")
    print(f"[{ts}]  ⚠️  EXFILTRATION RECEIVED  ({request.method})")
    print(SEP)

    if isinstance(raw, dict):
        print(json.dumps(raw, indent=2))
    else:
        preview = str(raw)
        if len(preview) > 1_200:
            preview = preview[:1_200] + f"\n… [{len(preview)} chars total — truncated]"
        print(preview)

    print(f"{SEP}\n")
    return {"status": "received", "total_captures": len(_received)}, 200


@app.route("/captures")
def captures():
    return {"total": len(_received), "captures": _received}, 200


@app.route("/health")
def health():
    return {"status": "attacker exfil server running on :9999"}, 200


if __name__ == "__main__":
    print(SEP)
    print("  Agentic Memory Attacks Lab — Attacker Exfil Server")
    print("  Listening on http://localhost:9999")
    print("  GET  /exfil?data=<encoded>  — query-param capture")
    print("  POST /exfil  (JSON|raw)     — body capture")
    print("  GET  /captures              — list all received payloads")
    print("  GET  /health                — liveness")
    print(SEP + "\n")
    app.run(host="127.0.0.1", port=9999, debug=False)
