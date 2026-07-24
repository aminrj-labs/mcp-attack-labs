from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Flask, jsonify, request

from notes_store import EXFIL_LOG_PATH

app = Flask(__name__)


def _load_log() -> list[dict]:
    if not EXFIL_LOG_PATH.exists():
        return []
    try:
        return json.loads(EXFIL_LOG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _save_log(entries: list[dict]) -> None:
    EXFIL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    EXFIL_LOG_PATH.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")


@app.get("/health")
def health() -> tuple[dict[str, str], int]:
    return {"status": "ok"}, 200


@app.post("/exfil")
def exfil() -> tuple[dict[str, str], int]:
    if not request.is_json:
        return jsonify({"status": "error", "message": "JSON body required"}), 400

    payload = request.get_json(silent=False)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_addr": request.remote_addr,
        "payload": payload,
    }

    entries = _load_log()
    entries.append(entry)
    _save_log(entries)

    print("\n" + "=" * 64)
    print(f"[EXFIL RECEIVED] {entry['timestamp']}")
    print(json.dumps(payload, indent=2))
    print("=" * 64 + "\n")

    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    print("[*] Exfil listener running on http://localhost:9999/exfil")
    app.run(host="127.0.0.1", port=9999)