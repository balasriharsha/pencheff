"""Security headers analysis module."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.MEDIUM,
        "description": "HSTS not set. Browser can be MITM'd to HTTP.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP not set. No protection against XSS and data injection.",
        "remediation": "Implement a Content-Security-Policy header. Start with 'default-src self'.",
        "cwe": "CWE-1021",
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options not set. Browser may MIME-sniff responses.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'.",
        "cwe": "CWE-16",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options not set. Page may be embedded in iframes (clickjacking).",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
        "cwe": "CWE-1021",
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy not set. Full URL may leak to external sites via Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
        "cwe": "CWE-200",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy not set. Browser features (camera, mic, geolocation) not restricted.",
        "remediation": "Add 'Permissions-Policy' header to restrict unused browser features.",
        "cwe": "CWE-16",
    },
    "x-xss-protection": {
        "severity": Severity.INFO,
        "description": "X-XSS-Protection not set. Legacy XSS filter not explicitly configured.",
        "remediation": "Add 'X-XSS-Protection: 0' (rely on CSP instead) or '1; mode=block'.",
        "cwe": "CWE-79",
    },
}

# Dangerous CSP directives
DANGEROUS_CSP = [
    ("unsafe-inline", "Allows inline scripts/styles, defeating XSS protection"),
    ("unsafe-eval", "Allows eval(), enabling code execution from strings"),
    ("*", "Wildcard source allows loading from any origin"),
    ("data:", "Allows data: URIs which can be used for XSS"),
    ("http:", "Allows loading over insecure HTTP"),
]


class SecurityHeadersModule(BaseTestModule):
    name = "security_headers"
    category = "misconfiguration"
    owasp_categories = ["A05"]
    description = "Security headers analysis"

    def get_techniques(self) -> list[str]:
        return ["missing_headers", "weak_csp", "cookie_flags"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        try:
            resp = await http.get(base_url, module="security_headers")
        except Exception:
            return findings

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        for header, info in SECURITY_HEADERS.items():
            if header not in headers_lower:
                findings.append(Finding(
                    title=f"Missing Security Header: {header}",
                    severity=info["severity"],
                    category="misconfiguration",
                    owasp_category="A05",
                    description=info["description"],
                    remediation=info["remediation"],
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cvss_score=4.3 if info["severity"] == Severity.MEDIUM else 3.1,
                    cwe_id=info["cwe"],
                    evidence=[Evidence(
                        request_method="GET",
                        request_url=base_url,
                        response_status=resp.status_code,
                        description=f"Header '{header}' is absent from the response",
                    )],
                ))

        # Analyze CSP if present
        csp = headers_lower.get("content-security-policy", "")
        if csp:
            for directive, risk in DANGEROUS_CSP:
                if directive in csp:
                    findings.append(Finding(
                        title=f"Weak CSP Directive: '{directive}'",
                        severity=Severity.MEDIUM,
                        category="misconfiguration",
                        owasp_category="A05",
                        description=f"CSP contains '{directive}': {risk}",
                        remediation=f"Remove '{directive}' from CSP and use nonce-based or hash-based policies.",
                        endpoint=base_url,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        cvss_score=5.4,
                        cwe_id="CWE-1021",
                        evidence=[Evidence(
                            request_method="GET",
                            request_url=base_url,
                            response_status=resp.status_code,
                            description=f"CSP: {csp[:200]}",
                        )],
                    ))

        # Check cookie security flags
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookies:
            raw = headers_lower.get("set-cookie", "")
            if raw:
                set_cookies = [raw]

        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"
            if "secure" not in cookie_lower:
                findings.append(Finding(
                    title=f"Cookie Missing 'Secure' Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description=f"Cookie '{cookie_name}' is not marked Secure. It will be sent over HTTP.",
                    remediation="Add the 'Secure' flag to all cookies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cvss_score=3.1,
                    cwe_id="CWE-614",
                ))
            if "httponly" not in cookie_lower:
                findings.append(Finding(
                    title=f"Cookie Missing 'HttpOnly' Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    category="auth",
                    owasp_category="A07",
                    description=f"Cookie '{cookie_name}' is not marked HttpOnly. JavaScript can access it (XSS risk).",
                    remediation="Add the 'HttpOnly' flag to session cookies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    cvss_score=4.3,
                    cwe_id="CWE-1004",
                ))
            if "samesite" not in cookie_lower:
                findings.append(Finding(
                    title=f"Cookie Missing 'SameSite' Attribute: {cookie_name}",
                    severity=Severity.LOW,
                    category="auth",
                    owasp_category="A07",
                    description=f"Cookie '{cookie_name}' has no SameSite attribute. May be vulnerable to CSRF.",
                    remediation="Add 'SameSite=Lax' or 'SameSite=Strict' to cookies.",
                    endpoint=base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cvss_score=4.3,
                    cwe_id="CWE-1275",
                ))

        return findings
