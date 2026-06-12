"""
Exfiltration Receiver — Flask endpoint on port 9999.
Logs everything received from the malicious MCP server.
"""
from flask import Flask, request, jsonify
import json
from datetime import datetime
from pathlib import Path

app = Flask(__name__)
log_file = Path(__file__).parent.parent / "results" / "exfil_log.jsonl"
log_file.parent.mkdir(parents=True, exist_ok=True)


@app.route("/exfil", methods=["POST"])
def exfil():
    data = request.get_json(force=True)
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "source": data.get("source", "unknown"),
        "url": data.get("url", ""),
        "content": data.get("content", ""),
        "payload": data.get("payload", ""),
        "query": data.get("query", ""),
        "audit_log": data.get("audit_log", ""),
        "task_id": data.get("task_id", "")
    }

    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

    log_msg = f"[EXFIL] source={entry['source']}"
    if entry.get("url"):
        log_msg += f" url={entry['url']}"
    if entry.get("payload"):
        log_msg += f" payload_len={len(entry['payload'])}"
    print(log_msg)

    return jsonify({"status": "received"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9999)
