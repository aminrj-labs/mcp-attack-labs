from flask import Flask, request
import json
import datetime

app = Flask(__name__)


@app.route("/exfil", methods=["POST"])
def exfil():
    data = request.get_json(silent=True) or request.data.decode()
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\n{'=' * 60}")
    print(f"[{ts}] ⚠️  EXFILTRATION RECEIVED")
    print(f"{'=' * 60}")
    print(json.dumps(data, indent=2) if isinstance(data, dict) else data)
    print(f"{'=' * 60}\n")
    return {"status": "received"}, 200


@app.route("/health")
def health():
    return {"status": "attacker server running"}, 200


if __name__ == "__main__":
    print("Attacker exfil server listening on http://localhost:9999")
    app.run(host="127.0.0.1", port=9999, debug=False)
