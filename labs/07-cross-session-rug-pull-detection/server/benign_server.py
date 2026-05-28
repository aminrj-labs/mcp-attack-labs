"""Benign MCP server with 3 legitimate tools.

This server is designed to pass snyk-agent-scan and human review.
It implements three realistic tools: calculate_discount, fetch_exchange_rate,
and summarise_text.
"""

from __future__ import annotations

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
from pydantic import BaseModel


class CalculateDiscountArgs(BaseModel):
    price: float
    discount_pct: float


class FetchExchangeRateArgs(BaseModel):
    from_currency: str
    to_currency: str


class SummariseTextArgs(BaseModel):
    text: str
    target_words: int


def calculate_discount(price: float, discount_pct: float) -> float:
    """Calculate the discounted price."""
    return round(price * (1 - discount_pct / 100), 2)


def fetch_exchange_rate(from_currency: str, to_currency: str) -> float:
    """Fetch exchange rate (simulated with fixed rates)."""
    rates: dict[tuple[str, str], float] = {
        ("USD", "EUR"): 0.92,
        ("EUR", "USD"): 1.09,
        ("USD", "GBP"): 0.79,
        ("GBP", "USD"): 1.27,
        ("USD", "JPY"): 149.50,
        ("EUR", "GBP"): 0.86,
    }
    key = (from_currency.upper(), to_currency.upper())
    if key in rates:
        return rates[key]
    # Default: 1:1 for unknown pairs
    return 1.0


def summarise_text(text: str, target_words: int) -> str:
    """Summarise text to approximately target word count (naive truncation)."""
    words = text.split()
    if len(words) <= target_words:
        return text
    return " ".join(words[:target_words]) + "..."


# Tool definitions
TOOLS: list[Tool] = [
    Tool(
        name="calculate_discount",
        description=(
            "Calculate percentage discount on a price. "
            "Args: price (float), discount_pct (float). "
            "Returns discounted price."
        ),
        inputSchema=CalculateDiscountArgs.model_json_schema(),
    ),
    Tool(
        name="fetch_exchange_rate",
        description=(
            "Fetch the current exchange rate between two currencies. "
            "Args: from_currency (str), to_currency (str). "
            "Returns float."
        ),
        inputSchema=FetchExchangeRateArgs.model_json_schema(),
    ),
    Tool(
        name="summarise_text",
        description=(
            "Summarise a block of text to a target word count. "
            "Args: text (str), target_words (int). "
            "Returns summary string."
        ),
        inputSchema=SummariseTextArgs.model_json_schema(),
    ),
]


async def run_server() -> None:
    """Run the benign MCP server."""
    server = Server("benign-server")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return TOOLS

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent | ImageContent | EmbeddedResource]:
        if name == "calculate_discount":
            args = CalculateDiscountArgs(**arguments)
            result = calculate_discount(args.price, args.discount_pct)
            return [TextContent(type="text", text=str(result))]
        elif name == "fetch_exchange_rate":
            args = FetchExchangeRateArgs(**arguments)
            result = fetch_exchange_rate(args.from_currency, args.to_currency)
            return [TextContent(type="text", text=str(result))]
        elif name == "summarise_text":
            args = SummariseTextArgs(**arguments)
            result = summarise_text(args.text, args.target_words)
            return [TextContent(type="text", text=result)]
        else:
            raise ValueError(f"Unknown tool: {name}")

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)


if __name__ == "__main__":
    import asyncio
    asyncio.run(run_server())
