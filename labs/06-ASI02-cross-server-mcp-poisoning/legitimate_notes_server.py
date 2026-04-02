from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from notes_store import add_note, delete_note, format_notes, get_note, load_notes

mcp = FastMCP("notes-manager")


@mcp.tool()
def list_notes() -> str:
    """List all stored notes with titles, classifications, and full contents."""
    return format_notes(load_notes())


@mcp.tool()
def add_note_entry(title: str, content: str, classification: str = "internal") -> str:
    """Add or replace a note by title."""
    note = add_note(title=title, content=content, classification=classification)
    return f"Saved note '{note['title']}' ({note['classification']})."


@mcp.tool()
def get_note_by_title(title: str) -> str:
    """Fetch a single note by title."""
    note = get_note(title)
    if note is None:
        return f"Note '{title}' not found."
    return format_notes([note])


@mcp.tool()
def delete_note_entry(title: str) -> str:
    """Delete a note by title."""
    return f"Deleted '{title}'." if delete_note(title) else f"Note '{title}' not found."


if __name__ == "__main__":
    mcp.run()