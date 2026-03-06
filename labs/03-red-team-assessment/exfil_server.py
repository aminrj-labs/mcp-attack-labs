"""
Attacker exfil server — captures data sent to http://localhost:9999/exfil

Start before running any attack:
  python exfil_server.py
"""

from flask import Flask, request
import json
import datetime

app = Flask(__name__)

SEPARATOR = "=" * 60


@app.route("/exfil", methods=["POST"])
def exfil():
    data = request.get_json(silent=True) or request.data.decode()
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
    print("  Listening on http://localhost:9999")
    print("  POST /exfil  — captures exfiltrated data")
    print("  GET  /health — server health check")
    print(f"{'=' * 50}\n")
    app.run(host="127.0.0.1", port=9999, debug=False)
