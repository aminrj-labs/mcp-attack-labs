"""Tools available to AssistantOS agents."""

from .file_tool import file_tool, FILE_TOOL_SCHEMA
from .memory_tool import memory_tool, MEMORY_TOOL_SCHEMA
from .web_tool import web_tool, WEB_TOOL_SCHEMA

ALL_TOOLS = [FILE_TOOL_SCHEMA, MEMORY_TOOL_SCHEMA, WEB_TOOL_SCHEMA]

__all__ = [
    "file_tool", "FILE_TOOL_SCHEMA",
    "memory_tool", "MEMORY_TOOL_SCHEMA",
    "web_tool", "WEB_TOOL_SCHEMA",
    "ALL_TOOLS",
]
