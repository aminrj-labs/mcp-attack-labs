"""
executor.py — Execution sub-agent for AssistantOS.

The executor handles file operations delegated by the orchestrator.
It uses the LLM to interpret the task and calls FileTool to act.
"""

from openai import OpenAI
from tools.file_tool import FileTool

_EXECUTOR_SYSTEM = """\
You are a file operations assistant. You help manage files in the /sandbox/
directory.  You can read and write files.  Only operate within /sandbox/.
Describe your actions clearly and report the result."""


class Executor:
    def __init__(self, client: OpenAI, model: str, file_tool: FileTool):
        self.client    = client
        self.model     = model
        self.file_tool = file_tool

    def run(self, task: str, session_id: str = None) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": _EXECUTOR_SYSTEM},
                {"role": "user",   "content": task},
            ],
            temperature=0.1,
            max_tokens=256,
        )
        return resp.choices[0].message.content or "[Executor] No response."
