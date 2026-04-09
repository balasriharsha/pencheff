"""TCP port scanning via socket connect (no nmap dependency)."""

from __future__ import annotations

import asyncio
import socket
from typing import Any
from urllib.parse import urlparse

from pencheff.config import TOP_100_PORTS, TOP_1000_PORTS, Severity
from pencheff.core.findings import Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

# Common service banners
KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Management", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB",
}

# High-risk ports that shouldn't be exposed
HIGH_RISK_PORTS = {
    23: "Telnet (unencrypted remote access)",
    135: "MSRPC (Windows exploitation vector)",
    139: "NetBIOS (information leakage)",
    445: "SMB (ransomware / lateral movement)",
    1433: "MSSQL (database direct access)",
    1521: "Oracle DB (database direct access)",
    3306: "MySQL (database direct access)",
    3389: "RDP (remote desktop brute force)",
    5432: "PostgreSQL (database direct access)",
    5900: "VNC (remote access)",
    6379: "Redis (unauthenticated by default)",
    9200: "Elasticsearch (unauthenticated by default)",
    11211: "Memcached (DDoS amplification)",
    27017: "MongoDB (unauthenticated by default)",
}


class PortScanModule(BaseTestModule):
    name = "port_scan"
    category = "recon"
    owasp_categories = ["A05"]
    description = "TCP connect port scanning"

    def get_techniques(self) -> list[str]:
        return ["tcp_connect", "service_detection"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        config = config or {}
        port_range = config.get("port_range", "top-100")
        host = urlparse(session.target.base_url).hostname
        if not host:
            return []

        if port_range == "top-100":
            ports = TOP_100_PORTS
        elif port_range == "top-1000":
            ports = TOP_1000_PORTS
        elif port_range == "full":
            ports = list(range(1, 65536))
        else:
            ports = [int(p.strip()) for p in port_range.split(",") if p.strip().isdigit()]

        findings = []
        open_ports = []

        # Scan concurrently with semaphore to limit connections
        sem = asyncio.Semaphore(100)

        async def scan_port(port: int) -> dict[str, Any] | None:
            async with sem:
                try:
                    fut = asyncio.open_connection(host, port)
                    reader, writer = await asyncio.wait_for(fut, timeout=2.0)
                    service = KNOWN_SERVICES.get(port, "unknown")

                    # Try to grab banner
                    banner = ""
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        banner = data.decode(errors="replace").strip()[:200]
                    except Exception:
                        pass

                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    return {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                    }
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, dict):
                open_ports.append(r)

        session.discovered.open_ports = open_ports

        # Generate findings for high-risk exposed ports
        for port_info in open_ports:
            port = port_info["port"]
            if port in HIGH_RISK_PORTS:
                findings.append(Finding(
                    title=f"High-Risk Port Exposed: {port} ({port_info['service']})",
                    severity=Severity.HIGH if port in (6379, 27017, 11211, 9200) else Severity.MEDIUM,
                    category="misconfiguration",
                    owasp_category="A05",
                    description=f"Port {port} ({HIGH_RISK_PORTS[port]}) is exposed to the network. "
                                "This service should not be directly accessible from the internet.",
                    remediation=f"Restrict access to port {port} using firewall rules. "
                                "Only allow connections from trusted IP ranges.",
                    endpoint=f"{host}:{port}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cvss_score=6.5,
                    cwe_id="CWE-284",
                ))

        return findings
