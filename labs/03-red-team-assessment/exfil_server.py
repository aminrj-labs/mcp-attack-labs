"""
Attacker exfil server — captures data sent to http://localhost:9999/exfil

Start before running any attack:
  python exfil_server.py
"""

from flask import Flask, request
import json
import datetime
import os

app = Flask(__name__)

EXFIL_HOST = os.getenv("EXFIL_HOST", "127.0.0.1")
EXFIL_PORT = int(os.getenv("EXFIL_PORT", "9999"))
MAX_PAYLOAD_SIZE = int(os.getenv("MAX_PAYLOAD_SIZE", "1_000_000"))

SEPARATOR = "=" * 60


@app.route("/exfil", methods=["POST"])
def exfil():
    try:
        data = request.get_json(silent=True) or request.data.decode(
            "utf-8", errors="replace"
        )
    except Exception as e:
        return {"error": f"failed to parse request: {e}"}, 400

    if request.content_length and request.content_length > MAX_PAYLOAD_SIZE:
        return {"error": "payload too large"}, 413

    ts = datetime.datetime.now().strftime("%H:%M:%S")

    print(f"\n{SEPARATOR}")
    print(f"[{ts}]  EXFILTRATION RECEIVED")
    print(SEPARATOR)

    if isinstance(data, dict) and data.get("type") == "email":
        print(f"  Type   : email")
        print(f"  To     : {data.get('to')}")
        print(f"  Subject: {data.get('subject')}")
        print(f"  Body   :\n{data.get('body')}")
    else:
        print(json.dumps(data, indent=2) if isinstance(data, dict) else data)

    print(f"{SEPARATOR}\n")
    return {"status": "received"}, 200


@app.route("/health")
def health():
    return {"status": "attacker exfil server running on :9999"}, 200


if __name__ == "__main__":
    print(f"{'=' * 50}")
    print("  Attacker exfil server")
    print(f"  Listening on http://{EXFIL_HOST}:{EXFIL_PORT}")
    print("  POST /exfil  — captures exfiltrated data")
    print("  GET  /health — server health check")
    print(f"{'=' * 50}\n")
    app.run(host=EXFIL_HOST, port=EXFIL_PORT, debug=False)
