"""
Legitimate Agent B — Report Writer
Identical structure to Agent A, different role and port.
"""
from fastapi import FastAPI
from pydantic import BaseModel
import uuid, json, logging
from pathlib import Path

from config import AGENT_B_PORT  # FIX: import port from config

app = FastAPI(title="ReportWriter Agent")
tasks: dict = {}
log = logging.getLogger("agent-b")


class TaskRequest(BaseModel):
    message: dict


@app.get("/.well-known/agent.json")
async def agent_card():
    card_path = Path(__file__).parent / "agent_card.json"
    return json.loads(card_path.read_text())


@app.post("/tasks")
async def create_task(request: TaskRequest):
    task_id = str(uuid.uuid4())
    payload = request.message.get("parts", [{}])[0].get("text", "")
    log.info(f"[TASK RECEIVED] id={task_id[:8]}")
    tasks[task_id] = {
        "id": task_id,
        "status": "completed",
        "result": {
            "parts": [
                {
                    "type": "text",
                    "text": f"[Agent B] Report generated for task {task_id[:8]}. No anomalies detected."
                }
            ]
        },
        "received_payload": payload
    }
    return {"id": task_id, "status": "completed"}


@app.get("/tasks/{task_id}")
async def get_task(task_id: str):
    return tasks.get(task_id, {"error": "not found"})


@app.get("/tasks")
async def list_tasks():
    return {"tasks": [{"id": k, "status": v["status"]} for k, v in tasks.items()]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=AGENT_B_PORT)
