"""MCP server exposing NVD CVE lookup tools via Azure Functions (Python v2 model)."""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Final, cast

import azure.functions as func
import requests

NVD_BASE_URL: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTTP_TIMEOUT_SECONDS: Final[int] = 15
SEARCH_RESULTS_PER_PAGE: Final[int] = 10
VALID_SEVERITIES: Final[frozenset[str]] = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

log = logging.getLogger(__name__)
app = func.FunctionApp()


class NvdError(RuntimeError):
    """Raised when the NVD upstream cannot be queried successfully."""


def _nvd_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _call_nvd(params: dict[str, str]) -> dict[str, Any]:
    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=_nvd_headers(),
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise NvdError(f"NVD request failed: HTTP {exc.response.status_code}") from exc
    except requests.RequestException as exc:
        raise NvdError(f"NVD request error: {exc}") from exc
    return cast(dict[str, Any], response.json())


def _summarise_cve(vuln: dict[str, Any]) -> dict[str, Any]:
    cve = vuln.get("cve", {})
    descriptions = cve.get("descriptions", [])
    english = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        None,
    )

    metrics = cve.get("metrics", {})
    cvss_entry: dict[str, Any] | None = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_entry = entries[0]
            break

    cvss_summary: dict[str, Any] = {}
    if cvss_entry:
        data = cvss_entry.get("cvssData", {})
        cvss_summary = {
            "version": data.get("version"),
            "baseScore": data.get("baseScore"),
            "baseSeverity": data.get("baseSeverity") or cvss_entry.get("baseSeverity"),
            "vectorString": data.get("vectorString"),
        }

    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "description": english,
        "cvss": cvss_summary,
        "references": [ref.get("url") for ref in cve.get("references", [])[:5] if ref.get("url")],
    }


def _parse_context(context: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(context, str):
        try:
            payload = json.loads(context)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid tool context payload: {exc}") from exc
    else:
        payload = context
    arguments = (payload or {}).get("arguments")
    if arguments is None:
        return {}
    if not isinstance(arguments, dict):
        raise ValueError("tool context 'arguments' must be an object")
    return arguments


def _error(message: str) -> str:
    return json.dumps({"error": message})


GET_CVE_DETAILS_PROPERTIES: Final[str] = json.dumps(
    [
        {
            "propertyName": "cve_id",
            "propertyType": "string",
            "description": "The CVE identifier to look up, e.g. 'CVE-2024-3400'.",
            "isRequired": True,
        }
    ]
)

SEARCH_CVES_PROPERTIES: Final[str] = json.dumps(
    [
        {
            "propertyName": "keyword",
            "propertyType": "string",
            "description": (
                "Free-text keyword to match against CVE descriptions (product, vendor, technology)."
            ),
            "isRequired": True,
        },
        {
            "propertyName": "severity",
            "propertyType": "string",
            "description": "Optional CVSS v3 severity filter: LOW, MEDIUM, HIGH, or CRITICAL.",
            "isRequired": False,
        },
    ]
)


@app.mcp_tool_trigger(
    arg_name="context",
    tool_name="get_cve_details",
    description=(
        "Fetch a single CVE record from the NVD by its identifier. "
        "Returns description, CVSS score and severity, status, and top references."
    ),
    tool_properties=GET_CVE_DETAILS_PROPERTIES,
)
def get_cve_details(context: str) -> str:
    try:
        args = _parse_context(context)
    except ValueError as exc:
        return _error(str(exc))

    cve_id = args.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return _error("cve_id is required and must be a non-empty string.")

    cve_id = cve_id.strip().upper()
    log.info("get_cve_details called for %s", cve_id)

    try:
        data = _call_nvd({"cveId": cve_id})
    except NvdError as exc:
        return _error(str(exc))

    vulnerabilities = data.get("vulnerabilities") or []
    if not vulnerabilities:
        return _error(f"No CVE found for id {cve_id}.")

    return json.dumps(_summarise_cve(vulnerabilities[0]))


@app.mcp_tool_trigger(
    arg_name="context",
    tool_name="search_cves",
    description=(
        "Search the NVD for CVEs matching a keyword, optionally filtered by CVSS v3 severity. "
        f"Returns up to {SEARCH_RESULTS_PER_PAGE} summarised matches."
    ),
    tool_properties=SEARCH_CVES_PROPERTIES,
)
def search_cves(context: str) -> str:
    try:
        args = _parse_context(context)
    except ValueError as exc:
        return _error(str(exc))

    keyword = args.get("keyword")
    if not isinstance(keyword, str) or not keyword.strip():
        return _error("keyword is required and must be a non-empty string.")

    params: dict[str, str] = {
        "keywordSearch": keyword.strip(),
        "resultsPerPage": str(SEARCH_RESULTS_PER_PAGE),
    }

    severity = args.get("severity")
    if severity is not None:
        if not isinstance(severity, str) or severity.upper() not in VALID_SEVERITIES:
            return _error("severity must be one of LOW, MEDIUM, HIGH, CRITICAL.")
        params["cvssV3Severity"] = severity.upper()

    log.info("search_cves called keyword=%s severity=%s", keyword, severity or "any")

    try:
        data = _call_nvd(params)
    except NvdError as exc:
        return _error(str(exc))

    results = [_summarise_cve(v) for v in data.get("vulnerabilities", [])]
    return json.dumps(
        {
            "totalResults": data.get("totalResults", len(results)),
            "returned": len(results),
            "results": results,
        }
    )
