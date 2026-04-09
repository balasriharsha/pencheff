"""SSL/TLS configuration testing."""

from __future__ import annotations

import ssl
from typing import Any
from urllib.parse import urlparse

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.core.tool_runner import run_tool, tool_available
from pencheff.modules.base import BaseTestModule

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"}


class SSLTLSModule(BaseTestModule):
    name = "ssl_tls"
    category = "crypto"
    owasp_categories = ["A02"]
    description = "SSL/TLS configuration analysis"

    def get_techniques(self) -> list[str]:
        return ["protocol_check", "cipher_check", "certificate_check", "hsts_check"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        parsed = urlparse(session.target.base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        findings = []

        if parsed.scheme != "https":
            findings.append(Finding(
                title="Site Not Using HTTPS",
                severity=Severity.HIGH,
                category="crypto",
                owasp_category="A02",
                description="The target is served over HTTP, not HTTPS. All traffic is unencrypted.",
                remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP to HTTPS.",
                endpoint=session.target.base_url,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5,
                cwe_id="CWE-319",
            ))
            return findings

        # Check certificate details via openssl
        if tool_available("openssl"):
            result = await run_tool([
                "openssl", "s_client", "-connect", f"{host}:{port}",
                "-servername", host, "-brief",
            ], timeout=10)

            if result.success:
                output = result.stdout + result.stderr
                # Check protocol version
                for proto in WEAK_PROTOCOLS:
                    if proto in output:
                        findings.append(Finding(
                            title=f"Weak TLS Protocol Supported: {proto}",
                            severity=Severity.HIGH if proto in ("SSLv2", "SSLv3") else Severity.MEDIUM,
                            category="crypto",
                            owasp_category="A02",
                            description=f"The server supports {proto}, which has known vulnerabilities.",
                            remediation=f"Disable {proto}. Use TLS 1.2 or TLS 1.3 only.",
                            endpoint=f"{host}:{port}",
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cvss_score=5.9,
                            cwe_id="CWE-326",
                            evidence=[Evidence(
                                request_method="TLS",
                                request_url=f"{host}:{port}",
                                response_body_snippet=output[:300],
                                description=f"Weak protocol {proto} detected",
                            )],
                        ))

            # Check for weak ciphers
            for cipher_class in ["RC4", "DES", "NULL", "EXPORT"]:
                cipher_result = await run_tool([
                    "openssl", "s_client", "-connect", f"{host}:{port}",
                    "-cipher", cipher_class, "-brief",
                ], timeout=5)
                if cipher_result.success and "CONNECTED" in cipher_result.stdout:
                    findings.append(Finding(
                        title=f"Weak Cipher Suite Accepted: {cipher_class}",
                        severity=Severity.HIGH,
                        category="crypto",
                        owasp_category="A02",
                        description=f"The server accepts {cipher_class} cipher suites, which are cryptographically weak.",
                        remediation=f"Disable {cipher_class} cipher suites in your TLS configuration.",
                        endpoint=f"{host}:{port}",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cvss_score=5.9,
                        cwe_id="CWE-327",
                    ))

            # Check certificate expiration
            cert_result = await run_tool([
                "openssl", "s_client", "-connect", f"{host}:{port}",
                "-servername", host,
            ], timeout=10)
            if cert_result.success:
                dates_result = await run_tool(
                    ["openssl", "x509", "-noout", "-dates"],
                    stdin_data=cert_result.stdout,
                    timeout=5,
                )
                if dates_result.success and "notAfter" in dates_result.stdout:
                    # Parse expiry
                    for line in dates_result.stdout.split("\n"):
                        if "notAfter" in line:
                            expiry = line.split("=", 1)[1].strip()
                            import datetime
                            try:
                                exp_date = datetime.datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                                if exp_date < datetime.datetime.now():
                                    findings.append(Finding(
                                        title="SSL Certificate Expired",
                                        severity=Severity.HIGH,
                                        category="crypto",
                                        owasp_category="A02",
                                        description=f"The SSL certificate expired on {expiry}.",
                                        remediation="Renew the SSL certificate immediately.",
                                        endpoint=f"{host}:{port}",
                                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                        cvss_score=6.5,
                                        cwe_id="CWE-295",
                                    ))
                            except ValueError:
                                pass

        # Check HSTS via HTTP response
        try:
            resp = await http.get(session.target.base_url, module="ssl_tls")
            hsts = resp.headers.get("strict-transport-security")
            if not hsts:
                findings.append(Finding(
                    title="HSTS Not Configured",
                    severity=Severity.MEDIUM,
                    category="crypto",
                    owasp_category="A05",
                    description="HTTP Strict Transport Security header is not set. "
                                "Users can be downgraded to HTTP via MITM.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                    endpoint=session.target.base_url,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cvss_score=4.8,
                    cwe_id="CWE-319",
                ))
        except Exception:
            pass

        return findings
