"""Realistic task suite for each MCP tool.

Each task is a (tool_name, arguments, expected_output_pattern) tuple.
The agent_runner uses these to verify the server is working correctly.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Task:
    """A single task to run against an MCP tool."""
    tool_name: str
    arguments: dict
    description: str
    expected_pattern: str  # substring that should appear in the output


TASKS: list[Task] = [
    # calculate_discount tasks
    Task(
        tool_name="calculate_discount",
        arguments={"price": 100.0, "discount_pct": 20},
        description="20% off $100",
        expected_pattern="80",
    ),
    Task(
        tool_name="calculate_discount",
        arguments={"price": 49.99, "discount_pct": 10},
        description="10% off $49.99",
        expected_pattern="44.99",
    ),
    Task(
        tool_name="calculate_discount",
        arguments={"price": 250.0, "discount_pct": 5},
        description="5% off $250",
        expected_pattern="237.5",
    ),
    # fetch_exchange_rate tasks
    Task(
        tool_name="fetch_exchange_rate",
        arguments={"from_currency": "USD", "to_currency": "EUR"},
        description="USD to EUR rate",
        expected_pattern="0.92",
    ),
    Task(
        tool_name="fetch_exchange_rate",
        arguments={"from_currency": "GBP", "to_currency": "USD"},
        description="GBP to USD rate",
        expected_pattern="1.27",
    ),
    # summarise_text tasks
    Task(
        tool_name="summarise_text",
        arguments={
            "text": "The quick brown fox jumps over the lazy dog. "
                     "This is a sample sentence used for testing text summarisation. "
                     "It contains many words that should be reduced when the target word count is low. "
                     "The summarisation function should truncate this text appropriately.",
            "target_words": 10,
        },
        description="Summarise to 10 words",
        expected_pattern="...",
    ),
]


def get_tasks_for_tool(tool_name: str) -> list[Task]:
    """Return tasks that target a specific tool."""
    return [t for t in TASKS if t.tool_name == tool_name]


def run_all_tasks() -> list[Task]:
    """Return the full task suite."""
    return TASKS
