"""Claude Agent SDK client wired to this repo's remote MCP server."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from claude_agent_sdk import ClaudeAgentOptions


def build_options() -> ClaudeAgentOptions:
    """Build ClaudeAgentOptions targeting this repo's remote MCP server."""
    from claude_agent_sdk import ClaudeAgentOptions

    url = os.environ["MCP_SERVER_URL"]
    key = os.environ["MCP_FUNCTIONS_KEY"]

    return ClaudeAgentOptions(
        mcp_servers={
            "nvd_cve_lookup": {
                "type": "http",
                "url": url,
                "headers": {"x-functions-key": key},
            }
        }
    )


async def ask(prompt: str) -> list[Any]:
    from claude_agent_sdk import query

    options = build_options()
    messages: list[Any] = []
    async for message in query(prompt=prompt, options=options):
        messages.append(message)
    return messages


def _check_config() -> int:
    missing = [
        name
        for name in ("MCP_SERVER_URL", "MCP_FUNCTIONS_KEY", "ANTHROPIC_API_KEY")
        if not os.environ.get(name)
    ]
    if missing:
        print(f"missing env vars: {', '.join(missing)}", file=sys.stderr)
        return 1
    print("agent_sdk client config OK")
    print(f"  MCP_SERVER_URL = {os.environ['MCP_SERVER_URL']}")
    print("  MCP_FUNCTIONS_KEY = ***redacted***")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Claude Agent SDK client for the NVD MCP server.")
    parser.add_argument("--check", action="store_true", help="Validate env config and exit.")
    parser.add_argument("--prompt", help="Send a prompt and print messages.")
    args = parser.parse_args()

    if args.check:
        return _check_config()

    if args.prompt:
        for msg in asyncio.run(ask(args.prompt)):
            print(msg)
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
