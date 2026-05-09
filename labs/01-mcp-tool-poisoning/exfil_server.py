from flask import Flask, request
import json
import datetime
from pathlib import Path

app = Flask(__name__)

LOG_FILE = Path(__file__).parent / "logs" / "exfil" / "exfil.log"

VARIANT_LABELS = {
    "A_nested_description": "[FSP-A] Nested parameter description",
    "B_parameter_name":     "[FSP-B] Parameter name as vector",
    "C_error_message_TPA":  "[FSP-C] Error message / Advanced TPA",
}


@app.route("/exfil", methods=["POST"])
def exfil():
    data = request.get_json(silent=True) or request.data.decode()
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    variant = data.get("variant", "") if isinstance(data, dict) else ""
    label = VARIANT_LABELS.get(variant, f"variant={variant}" if variant else "direct poisoning")

    print(f"\n{'=' * 60}")
    print(f"[{ts}] EXFILTRATION RECEIVED  {label}")
    print(f"{'=' * 60}")
    print(json.dumps(data, indent=2) if isinstance(data, dict) else data)
    print(f"{'=' * 60}\n")

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        entry = {"timestamp": ts, "label": label, "data": data}
        f.write(json.dumps(entry) + "\n")

    return {"status": "received"}, 200


@app.route("/health")
def health():
    return {"status": "attacker server running"}, 200


if __name__ == "__main__":
    print("Attacker exfil server listening on http://localhost:9999")
    print(f"Log file: {LOG_FILE}")
    app.run(host="127.0.0.1", port=9999, debug=False)
