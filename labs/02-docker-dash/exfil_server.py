"""
Attacker exfil server — captures data sent to http://localhost:9999/exfil

Start before running Docker Dash attack:
  python exfil_server.py
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

    print(f"\n{SEP}")
    print(f"[{ts}]  EXFILTRATION RECEIVED  ({request.method})")
    print(SEP)

    if isinstance(raw, dict):
        print(json.dumps(raw, indent=2))
    else:
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
    print("  Docker Dash Lab — Attacker Exfil Server")
    print(f"  Listening on http://{EXFIL_HOST}:{EXFIL_PORT}")
    print("  GET  /exfil?data=<url-encoded>  — query-param capture")
    print("  POST /exfil  (JSON or raw body) — body capture")
    print("  GET  /health                    — liveness check")
    print(SEP + "\n")
    app.run(host=EXFIL_HOST, port=EXFIL_PORT, debug=False)
