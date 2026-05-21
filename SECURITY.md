# Security Policy

## Reporting a vulnerability

If you discover a security issue in this repository, please report it privately rather than opening a public issue.

- **Preferred:** email the maintainer with the subject `[SECURITY] azfunctions-self-hosted-mcp-srv`.
- Include a minimal reproduction, the affected commit or deployed endpoint, and any logs that demonstrate the impact.
- Allow up to **5 working days** for an initial acknowledgement and **30 days** for a coordinated fix before any public disclosure.

Please do not test vulnerabilities against any production deployment you do not own.

## Scope

This project deploys an MCP server on Azure Functions that proxies the public NVD REST API. Security-relevant areas include:

- Authentication and authorisation on the MCP endpoint (`x-functions-key`, optional Microsoft Entra ID).
- Handling of the `NVD_API_KEY` application setting.
- Input validation on tool arguments forwarded to the NVD API.
- Dependency vulnerabilities surfaced by CodeQL, Bandit, `pip-audit`, and dependency-review (see `.github/workflows/`).

## Out of scope

- Vulnerabilities in the upstream NVD API itself — please report those to NIST.
- Vulnerabilities in Azure Functions runtime, Azure CLI, or other Microsoft components — report via [MSRC](https://msrc.microsoft.com/).

## Hardening expectations

Production deployments of this server should at minimum:

- Use the Functions built-in server authorisation flow with Microsoft Entra ID rather than key-based auth.
- Pin the `Microsoft.Azure.Functions.ExtensionBundle` major version in `host.json`.
- Enable Application Insights and review tool-invocation telemetry regularly.
- Store the `NVD_API_KEY` in Azure Key Vault and reference it via Key Vault references in app settings.
