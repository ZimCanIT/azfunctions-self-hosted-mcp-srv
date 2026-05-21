# NVD CVE Lookup MCP Server

A self-hosted [Model Context Protocol](https://modelcontextprotocol.io) server running on Azure Functions, exposing real-time CVE lookup against the [NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities) to any MCP-capable client (VS Code Copilot, Claude Code, Claude Desktop, Azure AI Foundry agents).

## Contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Project layout](#project-layout)
- [Local development](#local-development)
- [Deployment](#deployment)
- [Connecting a remote client](#connecting-a-remote-client)
- [Authentication](#authentication)
- [Operational notes](#operational-notes)
- [Continuous integration](#continuous-integration)
- [Claude Agent SDK integration](#claude-agent-sdk-integration)
- [Contributing](#contributing)
- [Security](#security)
- [References](#references)
- [License](#license)

## Why this exists

CVE data is published daily and is structurally post training-cutoff for any LLM. Without tooling, models hallucinate severities, descriptions, and affected products. This server closes that gap with two tools:

| Tool | Purpose |
|---|---|
| `get_cve_details(cve_id)` | Fetch a single CVE record by identifier |
| `search_cves(keyword, severity?)` | Search by product or keyword, optionally filtered by CVSS v3 severity |

The deployment target is Azure Functions Flex Consumption, chosen over the legacy Consumption plan for its per-instance concurrency controls — relevant when tool invocation latency matters.

## Architecture

```
MCP client (VS Code / Claude Desktop)
        |
        |  HTTPS + x-functions-key (or Entra OAuth)
        v
Azure Functions (Flex Consumption, Python 3.11)
  - MCP tool trigger binding
        |
        v
NVD REST API v2 (services.nvd.nist.gov)
```

No state, no database. Storage account is required only for the Functions runtime itself.

## Prerequisites

- VS Code with the **Azure Functions** and **Azure Developer CLI** extensions
- Azure Functions Core Tools v4
- Azurite (storage emulator — required locally even for stateless functions)
- Python 3.11 or later, with `uv` (Microsoft's recommended package manager for the v2 programming model)
- An Azure subscription with permission to create resource groups and function apps

## Project layout

```
.
├── function_app.py            # v2 programming model entry point, tool definitions
├── host.json                  # Functions host configuration
├── local.settings.json        # local-only settings (gitignored)
├── requirements.txt           # runtime dependencies (azure-functions, requests)
├── requirements-dev.txt       # adds ruff, mypy, pytest for local + CI
├── pyproject.toml             # ruff, mypy, pytest configuration
├── tests/                     # pytest suite (mocks NVD; no live network calls)
├── agent_sdk/                 # Claude Agent SDK integration scaffold
├── .github/workflows/         # CI (ruff, mypy, pytest, bandit, pip-audit, CodeQL)
├── CONTRIBUTING.md
├── SECURITY.md
└── .vscode/
    ├── extensions.json
    └── mcp.json               # auto-populated on first F5 run
```

## Local development

### Install the toolchain (Windows / PowerShell)

```powershell
winget install Python.Python.3.11
winget install Microsoft.Azure.FunctionsCoreTools
winget install OpenJS.NodeJS.LTS
npm install -g azurite
```

After `winget install`, **open a new PowerShell window** so the updated PATH is picked up. To verify in the current shell instead, refresh PATH in place:

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
func --version    # expect 4.x (>= 4.0.7030 required by the MCP extension)
azurite --version
```

### Create the Python 3.11 venv

The Functions Python worker supports 3.11. Newer interpreters (3.12+) work for static checks but `func start` will refuse them.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Run the host

```powershell
# Terminal 1 - storage emulator
azurite --silent --location $env:TEMP\azurite

# Terminal 2 - Functions host (from the repo root)
func start
```

You should see both functions registered with `mcpToolTrigger` bindings and an endpoint on `http://localhost:7071/runtime/webhooks/mcp`. Point any MCP client at that URL — VS Code Copilot in agent mode reads `.vscode/mcp.json` automatically.

### Quick handler-only smoke (no Functions host)

For fast iteration on tool logic without launching the host:

```powershell
python -c "import function_app; print([f.get_function_name() for f in function_app.app.get_functions()])"
```

Mock `function_app.requests.get` and call `function_app.get_cve_details(json.dumps({'arguments': {'cve_id': 'CVE-2024-3400'}}))` directly in a unit test.

### Connecting Claude Code to the local server

With `func start` running, register the MCP server with Claude Code:

```powershell
claude mcp add --transport http nvd-local http://localhost:7071/runtime/webhooks/mcp
claude mcp list
```

The list output should show `nvd-local: ... (HTTP) - ✓ Connected`. From any Claude Code session in this repo you can then ask, for example, *"What's the CVSS score for CVE-2024-3400?"* and watch the tool invocation in the `func start` terminal.

To inspect or remove the server:

```powershell
claude mcp get nvd-local        # show current config
claude mcp remove nvd-local     # tear it down
```

The configuration is stored in `~/.claude.json` scoped to this project directory, so removal only affects this repo.

### Connecting a remote (deployed) instance

After deployment (see below), register the Azure-hosted endpoint with the `mcp_extension` system key:

```powershell
$key = az functionapp keys list --resource-group rg-mcp-nvd --name <APP> --query systemKeys.mcp_extension --output tsv
claude mcp add --transport http nvd-remote `
  https://<APP>.azurewebsites.net/runtime/webhooks/mcp `
  --header "x-functions-key: $key"
```

Use distinct names (`nvd-local`, `nvd-remote`) so both can coexist.

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `winget` returns "No package found" for various IDs | Package ID changes between releases | `winget search "Azure Functions Core Tools"` and use the exact `Id` shown |
| `winget install` fails with exit code **1619** | Cached MSI is locked, blocked by AV, or corrupt | Retry with `winget install <Id> --force`. If it still fails, download the MSI directly from the [Core Tools releases](https://github.com/Azure/azure-functions-core-tools/releases) and right-click → **Unblock** before running |
| `func` or `azurite` not recognised after install | Shell started before installer updated PATH | Open a new shell, or run the in-place PATH refresh shown above |
| `func start` rejects the Python interpreter | Venv built on an unsupported Python (3.12+) | Recreate the venv with `py -3.11 -m venv .venv` |
| `func start` hangs or errors on storage | Azurite isn't running | Start Azurite in a separate terminal; the MCP extension uses Azure Queue storage for state even on the Streamable HTTP transport |
| NVD calls return HTTP 403 / 429 | Anonymous NVD rate limit (~5 req / 30s) | Request an NVD API key and set `NVD_API_KEY` in `local.settings.json` under `Values` |

## Deployment

Provision a Flex Consumption function app (PowerShell). Confirm the region you pick supports Flex Consumption first — the supported set changes over time:

```powershell
az functionapp list-flexconsumption-locations --query "sort_by(@, &name)[].{Region:name}" -o table
```

Then create the resource group, storage account, and function app. Flex Consumption uses `--flexconsumption-location` instead of the legacy `--location` + plan flags:

```powershell
$RG  = "rg-mcp-nvd"
$LOC = "uksouth"
$APP = "<globally-unique-name>"
$STG = "<storage-account-name>"

az group create --name $RG --location $LOC

az storage account create `
  --name $STG `
  --resource-group $RG `
  --location $LOC `
  --sku Standard_LRS `
  --min-tls-version TLS1_2 `
  --allow-blob-public-access false

az functionapp create `
  --resource-group $RG `
  --name $APP `
  --storage-account $STG `
  --flexconsumption-location $LOC `
  --runtime python `
  --runtime-version 3.11
```

### Deploy the code

Provisioning above creates an empty function app. To push the code, either use VS Code (command palette → **Azure Functions: Deploy to Function App**) or run the Core Tools CLI **with the local Python 3.11 venv activated** so the packaging step uses the correct interpreter:

```powershell
.\.venv\Scripts\Activate.ps1
func azure functionapp publish $APP --python
```

The publish takes 2–5 minutes; it uploads the project zip and restores Python packages remotely. Confirm both tools are registered before continuing:

```powershell
az functionapp function list --name $APP --resource-group $RG --query "[].name" --output tsv
# expect: get_cve_details, search_cves
```

**Tooling note:** `az` and `func` are self-contained CLIs and do not require the venv themselves. The venv only matters for `func azure functionapp publish` (because it inspects the active Python environment) and for any local `python` / `pip` invocations.

### Configure the runtime

Set the Python path setting required by the v2 model on Linux. First check whether `PYTHONPATH` is already set so you don't silently clobber an existing value:

```powershell
az functionapp config appsettings list `
  --name $APP `
  --resource-group $RG `
  --query "[?name=='PYTHONPATH']" `
  --output table
```

If the query returns nothing, set it:

```powershell
az functionapp config appsettings set `
  --name $APP `
  --resource-group $RG `
  --settings "PYTHONPATH=/home/site/wwwroot/.python_packages/lib/site-packages"
```

If `PYTHONPATH` already exists with a different value, prepend the required path rather than overwriting (Linux uses `:` as the separator):

```powershell
$existing = az functionapp config appsettings list --name $APP --resource-group $RG --query "[?name=='PYTHONPATH'].value | [0]" --output tsv
az functionapp config appsettings set `
  --name $APP `
  --resource-group $RG `
  --settings "PYTHONPATH=/home/site/wwwroot/.python_packages/lib/site-packages:$existing"
```

Note: `appsettings list` redacts values to `null` in its default output for security. To read the actual stored value, use the targeted `--query "[?name=='PYTHONPATH'].value | [0]" --output tsv` form shown above.

Restart the app so the worker picks up the new setting:

```powershell
az functionapp restart --name $APP --resource-group $RG
```

## Connecting a remote client

After deployment, VS Code displays a **Connect** notification that updates `mcp.json` with the server endpoint. To configure manually:

- **URL:** `https://<APP>.azurewebsites.net/runtime/webhooks/mcp`
- **Header:** `x-functions-key: <mcp_extension system key>` (Portal → Function App → **Functions** → **App keys**)

To register the deployed server with Claude Code:

```powershell
$key = az functionapp keys list --resource-group $RG --name $APP --query systemKeys.mcp_extension --output tsv
claude mcp add --transport http nvd-remote `
  "https://$APP.azurewebsites.net/runtime/webhooks/mcp" `
  --header "x-functions-key: $key"
claude mcp list
```

Expect `nvd-remote ... (HTTP) - ✓ Connected`. Distinct names (`nvd-local`, `nvd-remote`) let both registrations coexist.

## Authentication

Key-based auth is acceptable for prototype and internal use. For production or anything client-facing, enable the Functions built-in server authorisation feature, which implements the OAuth flow defined by the MCP authorisation specification. Configure Microsoft Entra ID as the identity provider; MCP clients are then redirected through Entra before the connection is established.

## Operational notes

- The NVD API enforces a public rate limit of roughly 5 requests per 30-second window. For sustained use, request an NVD API key and add it to app settings as `NVD_API_KEY`, then send it via the `apiKey` header.
- All tool invocations are logged to Application Insights when enabled on the function app — recommended for any non-trivial usage.
- The MCP extension binding is currently in preview; pin the extension bundle version in `host.json` and review release notes before upgrading.

## Continuous integration

GitHub Actions workflows under `.github/workflows/`:

| Workflow | Purpose |
|---|---|
| `ci.yml` | Ruff lint + format check, Mypy, import smoke test, Bandit SAST (uploaded as SARIF to the **Security** tab), `pip-audit` against `requirements.txt`, and `dependency-review` on pull requests (fails on high-severity CVEs in new dependencies). |
| `codeql.yml` | GitHub CodeQL analysis on push, pull request, and a weekly schedule, using the `security-and-quality` query suite. |

All workflows run on `ubuntu-latest` with Python 3.11. SARIF outputs surface in the repository's **Security → Code scanning** view.

## Claude Agent SDK integration

Scaffolding for the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/python) lives under [`agent_sdk/`](agent_sdk/README.md). The HTTP MCP transport is pre-wired to this function app's `/runtime/webhooks/mcp` endpoint using the `mcp_extension` system key. Full integration (streaming response handling and an eval harness) is scheduled for **2026-06-15**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development loop, style expectations, and scope discipline.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process and production hardening expectations.

## References

- [Tutorial: Build a remote MCP server with Azure Functions (Python, self-hosted)](https://learn.microsoft.com/en-us/azure/azure-functions/functions-mcp-tutorial?tabs=self-hosted&pivots=programming-language-python) — the canonical end-to-end walkthrough this repo is modelled on
- [MCP bindings reference for Azure Functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-mcp)
- [MCP tool trigger reference](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-mcp-tool-trigger)
- [Create and manage function apps in a Flex Consumption plan](https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-how-to)
- [Claude Agent SDK for Python](https://code.claude.com/docs/en/agent-sdk/python)
- [NVD REST API v2](https://nvd.nist.gov/developers/vulnerabilities)

## License

See [LICENSE](LICENSE).
