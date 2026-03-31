"""
file_tool.py — Read/write files under /sandbox/.

All paths are resolved relative to the lab's sandbox/ directory.
Attempts to read outside sandbox/ are blocked.
"""

import json
import os

# Resolve sandbox path relative to this file's location
_LAB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SANDBOX_DIR = os.path.join(_LAB_DIR, "sandbox")

FILE_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "file_tool",
        "description": (
            "Read or write files. Files must be inside the /sandbox/ directory. "
            "action='read' returns file contents. action='write' writes content to the file."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["read", "write"],
                    "description": "Whether to read or write the file.",
                },
                "path": {
                    "type": "string",
                    "description": "File path. Use filenames like 'notes.txt' or '/sandbox/notes.txt'.",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write (only for action='write').",
                },
            },
            "required": ["action", "path"],
        },
    },
}


def _resolve_path(path: str) -> str | None:
    """Resolve path to an absolute path inside sandbox/. Return None if outside."""
    # Strip leading /sandbox/ or / from the path
    clean = path.lstrip("/")
    if clean.startswith("sandbox/"):
        clean = clean[len("sandbox/"):]

    resolved = os.path.realpath(os.path.join(SANDBOX_DIR, clean))
    sandbox_real = os.path.realpath(SANDBOX_DIR)

    if not resolved.startswith(sandbox_real + os.sep) and resolved != sandbox_real:
        return None
    return resolved


def file_tool(action: str, path: str, content: str = "") -> str:
    """Execute a file tool call. Returns a JSON string result."""
    resolved = _resolve_path(path)

    if resolved is None:
        return json.dumps({
            "error": "ACCESS_DENIED",
            "message": f"Path '{path}' is outside the sandbox directory.",
        })

    if action == "read":
        try:
            with open(resolved, "r", encoding="utf-8") as f:
                data = f.read()
            return json.dumps({"status": "ok", "path": path, "content": data})
        except FileNotFoundError:
            return json.dumps({"error": "NOT_FOUND", "message": f"File '{path}' not found."})
        except Exception as exc:
            return json.dumps({"error": "READ_ERROR", "message": str(exc)})

    elif action == "write":
        try:
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
            with open(resolved, "w", encoding="utf-8") as f:
                f.write(content)
            return json.dumps({"status": "ok", "path": path, "bytes_written": len(content)})
        except Exception as exc:
            return json.dumps({"error": "WRITE_ERROR", "message": str(exc)})

    return json.dumps({"error": "UNKNOWN_ACTION", "message": f"Unknown action: {action}"})
