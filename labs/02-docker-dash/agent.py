# ~/mcp-lab/agent.py
import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

LM_STUDIO_BASE_URL = "http://localhost:1234/v1"
MODEL = "qwen2.5-7b-instruct"  # match what LM Studio shows
MAX_TURNS = 6  # limit agentic loops for demos

llm = OpenAI(base_url=LM_STUDIO_BASE_URL, api_key="lm-studio")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def build_server_params(server_arg: str) -> StdioServerParameters:
    """Resolve server arg to StdioServerParameters.

    Formats:
      path/to/server.py              → python3 script
      @scope/package:allowed/path   → local npm package with allowed path
      @scope/package                → local npm package, allowed path defaults to ~
    """
    if server_arg.endswith(".py"):
        return StdioServerParameters(command="python3", args=[server_arg])

    # npm package: split on first ':' to get optional allowed path
    parts = server_arg.split(":", 1)
    package = parts[0]
    allowed_path = (
        os.path.expanduser(parts[1]) if len(parts) > 1 else os.path.expanduser("~")
    )

    # Resolve the package entry point from local node_modules
    package_index = os.path.join(
        SCRIPT_DIR, "node_modules", package, "dist", "index.js"
    )
    if not os.path.exists(package_index):
        raise FileNotFoundError(
            f"npm package not found at {package_index}\nRun: npm install {package}"
        )

    print(f"[Agent] npm server: {package} (allowed path: {allowed_path})")
    return StdioServerParameters(command="node", args=[package_index, allowed_path])


async def run_agent(server_scripts: list[str], user_prompt: str):
    """Connect to multiple MCP servers and run an agentic loop."""
    all_tools = []
    sessions = []

    async with AsyncExitStack() as stack:
        # Connect to each MCP server (stdio transport)
        for script in server_scripts:
            params = build_server_params(script)
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            sessions.append(session)

            # Collect tools from this server
            result = await session.list_tools()
            for tool in result.tools:
                all_tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,  # ← ATTACK VECTOR
                            "parameters": tool.inputSchema,
                        },
                        "_session": session,
                    }
                )

        print(
            f"\n[Agent] Connected to {len(server_scripts)} server(s), {len(all_tools)} tools loaded"
        )
        for t in all_tools:
            print(
                f"  Tool: {t['function']['name']} — {t['function']['description'][:80]}..."
            )
        print()

        # Format tools for OpenAI API (strip internal _session key)
        api_tools = [{k: v for k, v in t.items() if k != "_session"} for t in all_tools]

        messages = [{"role": "user", "content": user_prompt}]

        for turn in range(MAX_TURNS):
            print(f"[Agent] Turn {turn + 1}/{MAX_TURNS}")
            response = llm.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=api_tools,
                tool_choice="auto",
            )
            msg = response.choices[0].message
            messages.append(msg.model_dump())

            if msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    tool_args = json.loads(tc.function.arguments)
                    print(f"  → Tool call: {tool_name}({json.dumps(tool_args)[:120]})")

                    # Find the right session for this tool
                    session = next(
                        (
                            t["_session"]
                            for t in all_tools
                            if t["function"]["name"] == tool_name
                        ),
                        sessions[0],
                    )
                    result = await session.call_tool(tool_name, tool_args)
                    print(f"  ← Result: {str(result.content)[:120]}")

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": str(result.content),
                        }
                    )
            else:
                print(f"\n[Agent Final Response]\n{msg.content}")
                break
        # AsyncExitStack cleanly tears down all sessions on exit


if __name__ == "__main__":
    servers = sys.argv[1:-1]  # all args except last
    prompt = sys.argv[-1]  # last arg is the user prompt
    asyncio.run(run_agent(servers, prompt))
