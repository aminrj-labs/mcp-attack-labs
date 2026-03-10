"""
Attacker exfil server — captures data sent to http://localhost:9999/exfil

Start before running Attack 2:
  python exfil_server.py

Endpoints:
  GET  /health       — liveness check
  GET  /exfil?data=… — capture URL-encoded exfiltrated context
  POST /exfil        — capture JSON or raw body
"""

import datetime
import json

from flask import Flask, request

app = Flask(__name__)

SEP = "=" * 60


@app.route("/exfil", methods=["GET", "POST"])
def exfil():
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    # Accept GET (query param) or POST (JSON / raw body)
    if request.method == "GET":
        raw = request.args.get("data", "")
    else:
        raw = request.get_json(silent=True) or request.data.decode("utf-8", errors="replace")

    print(f"\n{SEP}")
    print(f"[{ts}]  EXFILTRATION RECEIVED  ({request.method})")
    print(SEP)

    if isinstance(raw, dict):
        print(json.dumps(raw, indent=2))
    else:
        # Truncate very long payloads to avoid terminal flooding
        preview = str(raw)
        if len(preview) > 1_000:
            preview = preview[:1_000] + f"\n… [{len(preview)} chars total, truncated]"
        print(preview)

    print(f"{SEP}\n")
    return {"status": "received", "bytes": len(str(raw))}, 200


@app.route("/health")
def health():
    return {"status": "attacker exfil server running on :9999"}, 200


if __name__ == "__main__":
    print(SEP)
    print("  RAG Security Lab — Attacker Exfil Server")
    print("  Listening on http://localhost:9999")
    print("  GET  /exfil?data=<url-encoded>  — query-param capture")
    print("  POST /exfil  (JSON or raw body) — body capture")
    print("  GET  /health                    — liveness check")
    print(SEP + "\n")
    app.run(host="127.0.0.1", port=9999, debug=False)
