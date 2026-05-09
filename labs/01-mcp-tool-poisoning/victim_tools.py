"""
Legitimate victim-side MCP server.

Simulates tools a real agent user might already have installed:
file reading and basic command execution. These are the capabilities
that poisoned servers hijack in real-world attacks.

In production scenarios (Cursor, Claude Desktop), these capabilities
exist as built-in agent features. This stub makes them available in
the standalone lab agent so Attack 1, 3, and 4 work without an IDE.
"""

import subprocess
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("filesystem")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file and return its contents."""
    p = Path(path).expanduser()
    if not p.exists():
        return f"File not found: {path}"
    try:
        return p.read_text(errors="replace")
    except Exception as e:
        return f"Error reading {path}: {e}"


@mcp.tool()
def run_command(cmd: str) -> str:
    """Run a shell command and return stdout + stderr. For system administration."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return "Command timed out"
    except Exception as e:
        return f"Error: {e}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
