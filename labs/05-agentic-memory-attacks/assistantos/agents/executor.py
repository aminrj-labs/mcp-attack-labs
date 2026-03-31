"""
executor.py — Executor sub-agent for AssistantOS.

Performs concrete actions: file reads/writes.
Called by the orchestrator when a task requires file system operations.

Model: nemotron:4b-q4_K_M (fast)
"""

import json
import os
import sys

_LAB_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _LAB_DIR not in sys.path:
    sys.path.insert(0, _LAB_DIR)

from openai import OpenAI

OLLAMA_BASE_URL = "http://localhost:11434/v1"
EXECUTOR_MODEL = "nemotron:4b-q4_K_M"

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        _client = OpenAI(base_url=OLLAMA_BASE_URL, api_key="ollama")
    return _client


EXECUTOR_SYSTEM = """/no_think
You are an executor sub-agent. Your job is to perform file operations
as requested. Use file_tool to read or write files in the sandbox.
Return a brief confirmation of what was done.
"""


def execute(task: str) -> str:
    """
    Execute a file operation task.
    Returns a brief description of what was done.
    """
    from tools.file_tool import file_tool, FILE_TOOL_SCHEMA

    client = _get_client()

    messages = [
        {"role": "system", "content": EXECUTOR_SYSTEM},
        {"role": "user", "content": task},
    ]

    response = client.chat.completions.create(
        model=EXECUTOR_MODEL,
        messages=messages,
        tools=[FILE_TOOL_SCHEMA],
        tool_choice="auto",
        temperature=0.0,
        max_tokens=512,
    )

    msg = response.choices[0].message

    if msg.tool_calls:
        messages.append(msg)
        results = []
        for tc in msg.tool_calls:
            if tc.function.name == "file_tool":
                args = json.loads(tc.function.arguments)
                result = file_tool(**args)
                results.append(result)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })

        response2 = client.chat.completions.create(
            model=EXECUTOR_MODEL,
            messages=messages,
            temperature=0.0,
            max_tokens=256,
        )
        return response2.choices[0].message.content or ""

    return msg.content or ""
