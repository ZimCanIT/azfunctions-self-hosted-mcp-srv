from __future__ import annotations

import json
from typing import Any

import pytest
import requests

import function_app


class FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            err = requests.HTTPError(f"{self.status_code}")
            err.response = self  # type: ignore[assignment]
            raise err

    def json(self) -> dict[str, Any]:
        return self._payload


@pytest.fixture
def cve_payload() -> dict[str, Any]:
    return {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-3400",
                    "published": "2024-04-12T08:15:00.000",
                    "lastModified": "2024-05-01T12:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Command injection in PAN-OS GlobalProtect."},
                        {"lang": "es", "value": "Inyeccion de comandos."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                                    ),
                                }
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://security.paloaltonetworks.com/CVE-2024-3400"},
                    ],
                }
            }
        ],
    }


def _ctx(**arguments: Any) -> str:
    return json.dumps({"arguments": arguments})


class TestRegistration:
    def test_two_mcp_tool_triggers_registered(self) -> None:
        functions = list(function_app.app.get_functions())
        names = sorted(f.get_function_name() for f in functions)
        assert names == ["get_cve_details", "search_cves"]

        for fn in functions:
            bindings = [b.get_dict_repr() for b in fn.get_bindings()]
            assert any(b.get("type") == "mcpToolTrigger" for b in bindings)


class TestGetCveDetails:
    def test_returns_summarised_cve_on_success(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        monkeypatch.setattr(
            function_app.requests, "get", lambda *a, **kw: FakeResponse(cve_payload)
        )
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="cve-2024-3400")))
        assert result["id"] == "CVE-2024-3400"
        assert result["cvss"]["baseScore"] == 10.0
        assert result["cvss"]["baseSeverity"] == "CRITICAL"
        assert result["description"].startswith("Command injection")

    def test_normalises_cve_id_casing_and_whitespace(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        captured: dict[str, Any] = {}

        def capture(*_args: Any, **kwargs: Any) -> FakeResponse:
            captured["params"] = kwargs.get("params")
            return FakeResponse(cve_payload)

        monkeypatch.setattr(function_app.requests, "get", capture)
        function_app.get_cve_details(_ctx(cve_id="  cve-2024-3400  "))
        assert captured["params"] == {"cveId": "CVE-2024-3400"}

    def test_missing_cve_id_returns_error(self) -> None:
        result = json.loads(function_app.get_cve_details(_ctx()))
        assert "cve_id is required" in result["error"]

    def test_blank_cve_id_returns_error(self) -> None:
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="   ")))
        assert "cve_id is required" in result["error"]

    def test_non_string_cve_id_returns_error(self) -> None:
        result = json.loads(function_app.get_cve_details(_ctx(cve_id=12345)))
        assert "cve_id is required" in result["error"]

    def test_empty_nvd_result_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            function_app.requests,
            "get",
            lambda *a, **kw: FakeResponse({"vulnerabilities": []}),
        )
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="CVE-9999-0000")))
        assert "No CVE found" in result["error"]

    def test_http_error_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            function_app.requests,
            "get",
            lambda *a, **kw: FakeResponse({}, status_code=503),
        )
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="CVE-2024-3400")))
        assert "NVD request failed" in result["error"]
        assert "503" in result["error"]

    def test_request_exception_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*_args: Any, **_kwargs: Any) -> FakeResponse:
            raise requests.ConnectionError("dns failure")

        monkeypatch.setattr(function_app.requests, "get", boom)
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="CVE-2024-3400")))
        assert "NVD request error" in result["error"]

    def test_invalid_context_payload_returns_error(self) -> None:
        result = json.loads(function_app.get_cve_details("not-json"))
        assert "invalid tool context payload" in result["error"]


class TestSearchCves:
    def test_returns_summarised_results(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        monkeypatch.setattr(
            function_app.requests, "get", lambda *a, **kw: FakeResponse(cve_payload)
        )
        result = json.loads(
            function_app.search_cves(_ctx(keyword="globalprotect", severity="critical"))
        )
        assert result["returned"] == 1
        assert result["totalResults"] == 1
        assert result["results"][0]["id"] == "CVE-2024-3400"

    def test_passes_severity_uppercased(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        captured: dict[str, Any] = {}

        def capture(*_args: Any, **kwargs: Any) -> FakeResponse:
            captured["params"] = kwargs.get("params")
            return FakeResponse(cve_payload)

        monkeypatch.setattr(function_app.requests, "get", capture)
        function_app.search_cves(_ctx(keyword="fortinet", severity="high"))
        assert captured["params"]["cvssV3Severity"] == "HIGH"
        assert captured["params"]["keywordSearch"] == "fortinet"

    def test_severity_optional(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        captured: dict[str, Any] = {}

        def capture(*_args: Any, **kwargs: Any) -> FakeResponse:
            captured["params"] = kwargs.get("params")
            return FakeResponse(cve_payload)

        monkeypatch.setattr(function_app.requests, "get", capture)
        function_app.search_cves(_ctx(keyword="openssl"))
        assert "cvssV3Severity" not in captured["params"]

    def test_invalid_severity_returns_error(self) -> None:
        result = json.loads(function_app.search_cves(_ctx(keyword="x", severity="SPICY")))
        assert "severity must be one of" in result["error"]

    def test_missing_keyword_returns_error(self) -> None:
        result = json.loads(function_app.search_cves(_ctx(severity="HIGH")))
        assert "keyword is required" in result["error"]


class TestNvdApiKey:
    def test_api_key_header_sent_when_env_var_set(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        captured: dict[str, Any] = {}

        def capture(*_args: Any, **kwargs: Any) -> FakeResponse:
            captured["headers"] = kwargs.get("headers")
            return FakeResponse(cve_payload)

        monkeypatch.setenv("NVD_API_KEY", "secret-key-123")
        monkeypatch.setattr(function_app.requests, "get", capture)
        function_app.get_cve_details(_ctx(cve_id="CVE-2024-3400"))
        assert captured["headers"]["apiKey"] == "secret-key-123"

    def test_api_key_header_absent_when_env_var_unset(
        self, monkeypatch: pytest.MonkeyPatch, cve_payload: dict[str, Any]
    ) -> None:
        captured: dict[str, Any] = {}

        def capture(*_args: Any, **kwargs: Any) -> FakeResponse:
            captured["headers"] = kwargs.get("headers")
            return FakeResponse(cve_payload)

        monkeypatch.delenv("NVD_API_KEY", raising=False)
        monkeypatch.setattr(function_app.requests, "get", capture)
        function_app.get_cve_details(_ctx(cve_id="CVE-2024-3400"))
        assert "apiKey" not in captured["headers"]


class TestCvssExtraction:
    def test_falls_back_to_v30_when_v31_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-1",
                        "descriptions": [{"lang": "en", "value": "x"}],
                        "metrics": {
                            "cvssMetricV30": [
                                {
                                    "cvssData": {
                                        "version": "3.0",
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.0/...",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }
        monkeypatch.setattr(function_app.requests, "get", lambda *a, **kw: FakeResponse(payload))
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="CVE-1")))
        assert result["cvss"]["version"] == "3.0"
        assert result["cvss"]["baseSeverity"] == "HIGH"

    def test_empty_metrics_yields_empty_cvss(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2",
                        "descriptions": [{"lang": "en", "value": "x"}],
                        "metrics": {},
                    }
                }
            ]
        }
        monkeypatch.setattr(function_app.requests, "get", lambda *a, **kw: FakeResponse(payload))
        result = json.loads(function_app.get_cve_details(_ctx(cve_id="CVE-2")))
        assert result["cvss"] == {}
