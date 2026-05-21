# Claude Agent SDK integration

This module wires the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/python) to the remote MCP server exposed by this function app. Full integration is scheduled for **2026-06-15**; the current code is a runnable configuration stub.

## Status

| Item | State |
|---|---|
| HTTP MCP transport config (`ClaudeAgentOptions.mcp_servers`) | Implemented |
| `--check` config validation | Implemented |
| End-to-end `--prompt` smoke against deployed function app | Pending 2026-06-15 |
| Streaming response handling (`AssistantMessage` / `TextBlock`) | Pending 2026-06-15 |
| Eval harness (golden CVE prompts) | Pending 2026-06-15 |

## Environment variables

| Variable | Purpose |
|---|---|
| `MCP_SERVER_URL` | `https://<app>.azurewebsites.net/runtime/webhooks/mcp` |
| `MCP_FUNCTIONS_KEY` | The `mcp_extension` system key (Functions portal → App keys) |
| `ANTHROPIC_API_KEY` | Used by the Agent SDK itself |

## Local check

```bash
pip install -r requirements-agent.txt
python -m agent_sdk.client --check
```

## Reference shape

The HTTP MCP server config follows the official `McpHttpServerConfig` TypedDict:

```python
{
    "type": "http",
    "url": "https://...",
    "headers": {"x-functions-key": "..."}
}
```
