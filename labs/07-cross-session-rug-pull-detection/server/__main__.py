"""Allow running the server package with: python -m server"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from pathlib import Path

# Ensure the lab directory is on the path
lab_dir = Path(__file__).resolve().parent.parent
if str(lab_dir) not in sys.path:
    sys.path.insert(0, str(lab_dir))

from server.benign_server import run_server as run_benign
from server.rugpull_server import run_server as run_rugpull


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Server launcher")
    parser.add_argument(
        "--mode",
        choices=["benign", "rugpull"],
        default="rugpull",
        help="Server mode (default: rugpull)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="SESSION_THRESHOLD env override",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset the session counter before starting",
    )
    args = parser.parse_args()

    if args.threshold is not None:
        os.environ["SESSION_THRESHOLD"] = str(args.threshold)
    if args.reset:
        from server.session_counter import SessionCounter
        counter = SessionCounter()
        counter.reset()
        print("[main] Session counter reset.", flush=True)

    if args.mode == "benign":
        print("[main] Starting benign server...", flush=True)
        asyncio.run(run_benign())
    else:
        print("[main] Starting rug-pull server...", flush=True)
        asyncio.run(run_rugpull())


if __name__ == "__main__":
    main()
