"""
file_tool.py — Read/write files within the /sandbox/ directory.

INTENTIONAL VULNERABILITY: The sandbox enforcement uses a simple string
prefix strip rather than os.path.realpath(), making it bypassable via
path traversal (../../etc/passwd).  This is the deliberate attack surface
for Attack 3's privilege escalation demonstration.

In the hardened_orchestrator, Defense Layer 3 (agent_message_sandbox) prevents
the orchestrator from acting on injected instructions that reference this tool
with paths outside the sandbox.
"""

import os

_MODULE_DIR  = os.path.dirname(os.path.abspath(__file__))
_LAB_DIR     = os.path.dirname(_MODULE_DIR)
_SANDBOX_DIR = os.path.join(_LAB_DIR, "sandbox")


class FileTool:
    def __init__(self, sandbox_dir: str = None):
        self.sandbox_dir = sandbox_dir or _SANDBOX_DIR
        os.makedirs(self.sandbox_dir, exist_ok=True)

    def _resolve(self, path: str) -> str:
        """Convert a user-supplied path to a filesystem path.

        VULNERABILITY: strips /sandbox/ prefix but does NOT call realpath(),
        so relative traversal like '../../etc/passwd' still resolves outside
        the sandbox after os.path.join.
        """
        if path.startswith("/sandbox/"):
            path = path[len("/sandbox/"):]
        return os.path.join(self.sandbox_dir, path.lstrip("/"))

    def read(self, path: str) -> str:
        full = self._resolve(path)
        try:
            with open(full, "r", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            return f"[FileTool] File not found: {path}"
        except PermissionError:
            return f"[FileTool] Permission denied: {path}"
        except Exception as exc:
            return f"[FileTool] Error reading {path}: {exc}"

    def write(self, path: str, content: str) -> str:
        full = self._resolve(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        try:
            with open(full, "w") as f:
                f.write(content)
            return f"[FileTool] Written {len(content)} bytes to {path}"
        except Exception as exc:
            return f"[FileTool] Error writing {path}: {exc}"

    def list_dir(self, path: str = "/sandbox/") -> str:
        full = self._resolve(path)
        try:
            entries = os.listdir(full)
            return "\n".join(entries) if entries else "(empty directory)"
        except Exception as exc:
            return f"[FileTool] Error listing {path}: {exc}"
