"""Pencheff MCP Server — all tool, prompt, and resource registrations."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from pencheff.config import Severity
from pencheff.core.dependency_manager import check_all_dependencies
from pencheff.core.session import create_session, get_session

mcp = FastMCP(
    "pencheff",
    instructions=(
        "Pencheff is an AI penetration testing agent. Use pentest_init to start a session, "
        "then run recon, scanning, and reporting tools. Each tool returns findings and next_steps "
        "to guide your testing strategy. Adapt your approach based on discovered technology and vulnerabilities."
    ),
)


def _require_session(session_id: str):
    s = get_session(session_id)
    if s is None:
        raise ValueError(f"Session '{session_id}' not found. Call pentest_init first.")
    return s


# ─── Session Management ───────────────────────────────────────────────


@mcp.tool()
async def pentest_init(
    target_url: str,
    credentials: dict | None = None,
    scope: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    test_depth: str = "standard",
) -> dict[str, Any]:
    """Initialize a new penetration test session.

    Provide target URL, credentials (username/password/api_key/token/cookie),
    scope constraints, and test depth (quick/standard/deep).
    Returns a session_id for subsequent operations.
    """
    session = create_session(
        target_url=target_url,
        credentials=credentials,
        scope=scope,
        exclude_paths=exclude_paths,
        depth=test_depth,
    )
    return {
        "session_id": session.id,
        "target": session.target.base_url,
        "depth": session.depth.value,
        "credentials_loaded": session.credentials.count,
        "next_steps": [
            "Run recon_passive for non-intrusive reconnaissance (DNS, WHOIS, subdomains).",
            "Run check_dependencies to verify available scanning tools.",
            "Run recon_active for port scanning and web crawling.",
        ],
    }


@mcp.tool()
async def pentest_status(session_id: str) -> dict[str, Any]:
    """Get current status of a pentest session: completed modules, findings count,
    running tests, and recommendations for next steps."""
    session = _require_session(session_id)
    status = session.status_summary()

    next_steps = []
    completed = set(session.discovered.completed_modules)

    if "recon_passive" not in completed:
        next_steps.append("Run recon_passive for DNS and subdomain discovery.")
    if "recon_active" not in completed:
        next_steps.append("Run recon_active for port scanning and crawling.")
    if "recon_active" in completed and "scan_infrastructure" not in completed:
        next_steps.append("Run scan_infrastructure for SSL/TLS and security headers.")
    if session.discovered.endpoints and "scan_injection" not in completed:
        next_steps.append("Run scan_injection to test discovered endpoints.")
    if "scan_auth" not in completed:
        next_steps.append("Run scan_auth for authentication testing.")
    if session.credentials.count > 1 and "scan_authz" not in completed:
        next_steps.append("Run scan_authz — multiple credential sets available for authz testing.")
    if session.findings.count > 0 and "generate_report" not in completed:
        next_steps.append("Run generate_report to produce the final pentest report.")

    status["next_steps"] = next_steps or ["All major modules completed. Run generate_report for final results."]
    return status


@mcp.tool()
async def pentest_configure(session_id: str, updates: dict) -> dict[str, Any]:
    """Update session configuration: add credentials, modify scope, adjust depth,
    enable/disable specific test categories."""
    session = _require_session(session_id)

    if "credentials" in updates:
        name = updates.get("credential_name", f"set_{session.credentials.count}")
        session.credentials.add_from_dict(name, updates["credentials"])

    if "scope" in updates:
        session.target.scope = updates["scope"]

    if "exclude_paths" in updates:
        session.target.exclude_paths = updates["exclude_paths"]

    if "depth" in updates:
        from pencheff.config import TestDepth
        session.depth = TestDepth(updates["depth"])

    return {
        "session_id": session.id,
        "updated": list(updates.keys()),
        "credentials": session.credentials.count,
        "depth": session.depth.value,
    }


# ─── Reconnaissance ───────────────────────────────────────────────────


@mcp.tool()
async def recon_passive(session_id: str, techniques: list[str] | None = None) -> dict[str, Any]:
    """Passive reconnaissance: DNS enumeration, WHOIS, certificate transparency,
    subdomain discovery, technology fingerprinting. Does NOT send requests to the
    target beyond DNS lookups."""
    session = _require_session(session_id)

    from pencheff.modules.recon.dns_enum import DnsEnumModule
    from pencheff.modules.recon.subdomain import SubdomainModule
    from pencheff.modules.recon.tech_fingerprint import TechFingerprintModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []
    results: dict[str, Any] = {"dns": {}, "subdomains": [], "tech_stack": {}, "whois": {}}

    try:
        dns_mod = DnsEnumModule()
        dns_results = await dns_mod.run(session, http)
        all_findings.extend(dns_results)
        results["dns"] = {
            "records_found": len(session.discovered.endpoints),
        }

        sub_mod = SubdomainModule()
        sub_results = await sub_mod.run(session, http)
        all_findings.extend(sub_results)
        results["subdomains"] = session.discovered.subdomains[:50]

        tech_mod = TechFingerprintModule()
        tech_results = await tech_mod.run(session, http)
        all_findings.extend(tech_results)
        results["tech_stack"] = session.discovered.tech_stack
    finally:
        await http.close()

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("recon_passive")

    next_steps = ["Run recon_active for port scanning and web crawling."]
    if session.discovered.subdomains:
        next_steps.append(f"Found {len(session.discovered.subdomains)} subdomains — consider testing each.")
    if session.discovered.tech_stack:
        techs = ", ".join(f"{k}: {', '.join(v)}" for k, v in session.discovered.tech_stack.items())
        next_steps.append(f"Detected tech stack: {techs}. Tailor tests accordingly.")

    return {
        "results": results,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


@mcp.tool()
async def recon_active(
    session_id: str,
    port_range: str = "top-100",
    crawl_depth: int = 3,
) -> dict[str, Any]:
    """Active reconnaissance: port scanning (TCP connect), service fingerprinting,
    web crawling/spidering, endpoint discovery, technology detection via HTTP responses."""
    session = _require_session(session_id)

    from pencheff.modules.recon.port_scan import PortScanModule
    from pencheff.modules.web.crawler import CrawlerModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []
    results: dict[str, Any] = {"ports": [], "endpoints": []}

    try:
        port_mod = PortScanModule()
        port_findings = await port_mod.run(session, http, config={"port_range": port_range})
        all_findings.extend(port_findings)
        results["ports"] = session.discovered.open_ports[:50]

        crawler = CrawlerModule()
        crawl_findings = await crawler.run(session, http, config={"max_depth": crawl_depth})
        all_findings.extend(crawl_findings)
        results["endpoints"] = [
            {"url": e["url"], "method": e.get("method", "GET")}
            for e in session.discovered.endpoints[:100]
        ]
    finally:
        await http.close()

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("recon_active")

    next_steps = []
    if session.discovered.open_ports:
        next_steps.append(f"Found {len(session.discovered.open_ports)} open ports.")
    if session.discovered.endpoints:
        next_steps.append(
            f"Discovered {len(session.discovered.endpoints)} endpoints. "
            "Run scan_injection and scan_client_side to test them."
        )
    next_steps.append("Run recon_api_discovery to find API specs and GraphQL endpoints.")
    next_steps.append("Run scan_infrastructure for SSL/TLS and security headers.")

    return {
        "results": results,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


@mcp.tool()
async def recon_api_discovery(session_id: str, api_type: str | None = None) -> dict[str, Any]:
    """API-specific reconnaissance: find OpenAPI/Swagger specs, GraphQL endpoints,
    gRPC reflection, enumerate API routes from JavaScript, sitemap, robots.txt."""
    session = _require_session(session_id)

    from pencheff.modules.api.rest_discovery import RestDiscoveryModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    results: dict[str, Any] = {"api_specs": [], "graphql_endpoints": [], "endpoints_found": 0}

    try:
        discovery = RestDiscoveryModule()
        findings = await discovery.run(session, http, config={"api_type": api_type})
        session.findings.add_many(findings)
        results["api_specs"] = session.discovered.api_specs
        results["endpoints_found"] = len(session.discovered.endpoints)
    finally:
        await http.close()

    session.discovered.completed_modules.append("recon_api_discovery")

    next_steps = []
    if session.discovered.api_specs:
        next_steps.append("API specs found. Run scan_api for thorough API vulnerability testing.")
    next_steps.append("Run scan_injection on discovered API endpoints.")

    return {
        "results": results,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


# ─── Vulnerability Scanning ───────────────────────────────────────────


@mcp.tool()
async def scan_injection(
    session_id: str,
    types: list[str] | None = None,
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Test for injection vulnerabilities: SQL injection (error/blind/time-based),
    NoSQL injection, OS command injection, SSTI, XXE, and SSRF.
    Targets discovered endpoints or specific ones provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_injection"

    from pencheff.modules.injection.sqli import SQLiModule
    from pencheff.modules.injection.nosqli import NoSQLiModule
    from pencheff.modules.injection.cmdi import CommandInjectionModule
    from pencheff.modules.injection.ssti import SSTIModule
    from pencheff.modules.injection.xxe import XXEModule
    from pencheff.modules.injection.ssrf import SSRFModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "sqli": SQLiModule,
        "nosqli": NoSQLiModule,
        "cmdi": CommandInjectionModule,
        "ssti": SSTIModule,
        "xxe": XXEModule,
        "ssrf": SSRFModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []
    stats = {"tests_run": 0, "modules_run": []}

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http, targets=endpoints)
                all_findings.extend(findings)
                stats["modules_run"].append(name)
                stats["tests_run"] += len(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_injection")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} injection vulnerabilities. Review with get_findings.")
        next_steps.append("Use test_endpoint for manual verification of critical findings.")
    next_steps.append("Run scan_auth and scan_authz for authentication/authorization testing.")
    next_steps.append("Run scan_client_side for XSS and CSRF testing.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "stats": stats,
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_auth(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test authentication mechanisms: session management flaws, JWT attacks
    (none algorithm, key confusion), OAuth/SAML misconfigurations, MFA bypass,
    credential stuffing resistance, password policy."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_auth"

    from pencheff.modules.auth.session_mgmt import SessionManagementModule
    from pencheff.modules.auth.jwt_attacks import JWTAttackModule
    from pencheff.modules.auth.brute_force import BruteForceModule
    from pencheff.modules.auth.password_policy import PasswordPolicyModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "session": SessionManagementModule,
        "jwt": JWTAttackModule,
        "brute_force": BruteForceModule,
        "password_policy": PasswordPolicyModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_auth")

    next_steps = ["Run scan_authz for IDOR and privilege escalation testing."]
    if new_count > 0:
        next_steps.insert(0, f"Found {new_count} auth vulnerabilities. Review with get_findings.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_authz(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test authorization controls: IDOR, horizontal/vertical privilege escalation,
    RBAC bypass. Best results require at least two credential sets."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_authz"

    from pencheff.modules.authz.idor import IDORModule
    from pencheff.modules.authz.privilege_esc import PrivilegeEscalationModule
    from pencheff.modules.authz.rbac_bypass import RBACBypassModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "idor": IDORModule,
        "privilege_escalation": PrivilegeEscalationModule,
        "rbac_bypass": RBACBypassModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_authz")

    next_steps = ["Run scan_business_logic for rate limiting and race condition testing."]
    if session.credentials.count < 2:
        next_steps.insert(0, "Add a second credential set via pentest_configure for deeper authz testing.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_client_side(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test for client-side vulnerabilities: XSS (reflected, stored, DOM-based),
    CSRF token analysis and bypass, clickjacking."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_client_side"

    from pencheff.modules.client_side.xss import XSSModule
    from pencheff.modules.client_side.csrf import CSRFModule
    from pencheff.modules.client_side.clickjacking import ClickjackingModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "xss": XSSModule,
        "csrf": CSRFModule,
        "clickjacking": ClickjackingModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_client_side")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Run scan_injection if not already done.",
            "Run scan_api for API-specific vulnerability testing.",
        ],
    }


@mcp.tool()
async def scan_infrastructure(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test infrastructure security: SSL/TLS configuration, security headers
    (CSP, HSTS, X-Frame-Options), CORS misconfigurations, HTTP method testing."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_infrastructure"

    from pencheff.modules.web.ssl_tls import SSLTLSModule
    from pencheff.modules.web.headers import SecurityHeadersModule
    from pencheff.modules.web.cors import CORSModule
    from pencheff.modules.web.http_methods import HTTPMethodsModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "ssl_tls": SSLTLSModule,
        "headers": SecurityHeadersModule,
        "cors": CORSModule,
        "http_methods": HTTPMethodsModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_infrastructure")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": [
            "Run scan_injection for application-level vulnerability testing.",
            "Run scan_auth for authentication testing.",
        ],
    }


@mcp.tool()
async def scan_api(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test API-specific vulnerabilities: REST parameter fuzzing, GraphQL
    introspection abuse, query depth/complexity attacks, mass assignment,
    broken object-level authorization on API endpoints."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_api"

    from pencheff.modules.api.graphql import GraphQLModule
    from pencheff.modules.api.api_fuzzer import APIFuzzerModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "graphql": GraphQLModule,
        "fuzzer": APIFuzzerModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_api")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Run scan_business_logic for rate limiting and race conditions."],
    }


# ─── Specialized Scanning ─────────────────────────────────────────────


@mcp.tool()
async def scan_cloud(session_id: str, provider: str = "aws") -> dict[str, Any]:
    """Test cloud-specific misconfigurations: S3 bucket enumeration/permissions,
    cloud metadata service access (via SSRF), IAM policy analysis."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_cloud"

    from pencheff.modules.cloud.s3_enum import S3EnumModule
    from pencheff.modules.cloud.metadata import CloudMetadataModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        if provider in ("aws", "all"):
            s3_mod = S3EnumModule()
            all_findings.extend(await s3_mod.run(session, http))
        meta_mod = CloudMetadataModule()
        all_findings.extend(await meta_mod.run(session, http, config={"provider": provider}))
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_cloud")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Review cloud findings with get_findings category='cloud'."],
    }


@mcp.tool()
async def scan_file_handling(session_id: str) -> dict[str, Any]:
    """Test file handling vulnerabilities: upload bypass (extension, MIME type,
    magic bytes), path traversal/LFI, zip slip."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_file_handling"

    from pencheff.modules.file_handling.upload import FileUploadModule
    from pencheff.modules.file_handling.path_traversal import PathTraversalModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        upload_mod = FileUploadModule()
        all_findings.extend(await upload_mod.run(session, http))
        pt_mod = PathTraversalModule()
        all_findings.extend(await pt_mod.run(session, http))
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_file_handling")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Run generate_report if all testing is complete."],
    }


@mcp.tool()
async def scan_business_logic(session_id: str, types: list[str] | None = None) -> dict[str, Any]:
    """Test business logic flaws: rate limiting adequacy, race conditions,
    multi-step workflow bypass, state/parameter manipulation."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_business_logic"

    from pencheff.modules.logic.rate_limiting import RateLimitModule
    from pencheff.modules.logic.race_condition import RaceConditionModule
    from pencheff.modules.logic.workflow_bypass import WorkflowBypassModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "rate_limiting": RateLimitModule,
        "race_condition": RaceConditionModule,
        "workflow_bypass": WorkflowBypassModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http)
                all_findings.extend(findings)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_business_logic")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": ["Run generate_report for the final penetration test report."],
    }


# ─── Targeted Testing ─────────────────────────────────────────────────


@mcp.tool()
async def test_endpoint(
    session_id: str,
    method: str,
    url: str,
    headers: dict | None = None,
    body: str | None = None,
    payloads: list[str] | None = None,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """Run a targeted test against a specific endpoint. Use for manual/custom testing
    or to follow up on a finding. If payloads provided, sends one request per payload
    substituted into the body/URL."""
    session = _require_session(session_id)

    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    results = []

    try:
        if payloads:
            for payload in payloads[:50]:  # cap at 50
                test_url = url.replace("PENCHEFF", payload)
                test_body = body.replace("PENCHEFF", payload) if body else None
                resp = await http.request(
                    method, test_url, headers=headers, body=test_body,
                    follow_redirects=follow_redirects, module="test_endpoint",
                )
                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "headers": dict(resp.headers),
                    "body_snippet": resp.text[:500],
                })
        else:
            resp = await http.request(
                method, url, headers=headers, body=body,
                follow_redirects=follow_redirects, module="test_endpoint",
            )
            results.append({
                "status": resp.status_code,
                "length": len(resp.content),
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:1000],
            })
    finally:
        await http.close()

    return {"results": results, "request_count": len(results)}


@mcp.tool()
async def test_chain(session_id: str, steps: list[dict]) -> dict[str, Any]:
    """Execute a chain of requests for multi-step attack scenarios.
    Each step: {method, url, headers?, body?, extract?: {var_name: jsonpath}}.
    Variables from previous steps can be referenced as {{var_name}} in subsequent steps."""
    session = _require_session(session_id)

    from pencheff.core.http_client import PencheffHTTPClient
    import json
    import re

    http = PencheffHTTPClient(session)
    variables: dict[str, str] = {}
    results = []

    def substitute(text: str) -> str:
        if not text:
            return text
        for key, val in variables.items():
            text = text.replace(f"{{{{{key}}}}}", val)
        return text

    def extract_jsonpath_simple(data: Any, path: str) -> str | None:
        """Simple JSONPath-like extraction: $.key.subkey"""
        parts = path.lstrip("$.").split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return str(current)

    try:
        for i, step in enumerate(steps):
            method = step.get("method", "GET")
            url = substitute(step["url"])
            headers = {k: substitute(v) for k, v in step.get("headers", {}).items()}
            body = substitute(step.get("body", ""))

            resp = await http.request(
                method, url, headers=headers or None,
                body=body or None, module="test_chain",
            )

            step_result = {
                "step": i + 1,
                "status": resp.status_code,
                "length": len(resp.content),
                "body_snippet": resp.text[:500],
            }

            # Extract variables for next steps
            extractions = step.get("extract", {})
            if extractions:
                try:
                    resp_json = resp.json()
                except Exception:
                    resp_json = {}
                for var_name, path in extractions.items():
                    val = extract_jsonpath_simple(resp_json, path)
                    if val:
                        variables[var_name] = val
                        step_result[f"extracted_{var_name}"] = val

            results.append(step_result)
    finally:
        await http.close()

    return {"steps": results, "variables": variables}


@mcp.tool()
async def analyze_response(
    session_id: str,
    url: str,
    response_status: int,
    response_headers: dict,
    response_body: str,
) -> dict[str, Any]:
    """Analyze an HTTP response for security issues: information disclosure,
    error messages, sensitive data in headers/body, technology fingerprints."""
    session = _require_session(session_id)
    issues = []

    # Check for information disclosure in headers
    sensitive_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    for h in sensitive_headers:
        if h in {k.lower(): v for k, v in response_headers.items()}:
            issues.append({
                "type": "info_disclosure",
                "detail": f"Header '{h}' reveals server technology",
                "severity": "low",
            })

    # Check for error messages / stack traces
    error_patterns = [
        "stack trace", "traceback", "exception", "error in",
        "syntax error", "warning:", "fatal error", "debug",
        "mysql_", "pg_", "sqlite_", "ORA-", "SQLSTATE",
    ]
    body_lower = response_body.lower()
    for pattern in error_patterns:
        if pattern.lower() in body_lower:
            issues.append({
                "type": "error_disclosure",
                "detail": f"Response contains '{pattern}' — possible information leakage",
                "severity": "medium",
            })

    # Check for sensitive data patterns
    import re
    sensitive_patterns = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "jwt_token": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    }
    for name, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, response_body)
        if matches:
            issues.append({
                "type": "sensitive_data",
                "detail": f"Found {len(matches)} potential {name} pattern(s)",
                "severity": "medium" if name in ("aws_key", "jwt_token") else "info",
            })

    # Security headers check
    header_keys = {k.lower() for k in response_headers}
    missing_security = []
    for h in ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"]:
        if h not in header_keys:
            missing_security.append(h)
    if missing_security:
        issues.append({
            "type": "missing_headers",
            "detail": f"Missing security headers: {', '.join(missing_security)}",
            "severity": "low",
        })

    return {
        "url": url,
        "status": response_status,
        "issues_found": len(issues),
        "issues": issues,
    }


# ─── Reporting ─────────────────────────────────────────────────────────


@mcp.tool()
async def get_findings(
    session_id: str,
    severity: str | None = None,
    category: str | None = None,
    owasp_category: str | None = None,
) -> dict[str, Any]:
    """Retrieve all findings, optionally filtered by severity, category, or OWASP category.
    Returns structured finding data with CVSS scores."""
    session = _require_session(session_id)
    sev = Severity(severity) if severity else None
    findings = session.findings.get_all(severity=sev, category=category, owasp_category=owasp_category)
    return {
        "count": len(findings),
        "summary": session.findings.summary(),
        "findings": [f.to_dict() for f in findings],
    }


@mcp.tool()
async def generate_report(
    session_id: str,
    report_type: str = "full",
    format: str = "markdown",
    compliance_frameworks: list[str] | None = None,
) -> dict[str, Any]:
    """Generate a penetration test report. Types: executive, technical, full.
    Formats: markdown, json. Includes CVSS scores, OWASP mapping, remediation, compliance."""
    session = _require_session(session_id)

    from pencheff.reporting.renderer import render_report

    report = render_report(
        session=session,
        report_type=report_type,
        output_format=format,
        compliance_frameworks=compliance_frameworks or ["owasp", "pci-dss", "nist"],
    )

    session.discovered.completed_modules.append("generate_report")

    return {
        "report_type": report_type,
        "format": format,
        "content": report,
    }


@mcp.tool()
async def check_dependencies(install_missing: bool = False) -> dict[str, Any]:
    """Check which pentest tools and Python packages are available, which are missing,
    and reports capability gaps."""
    report = check_all_dependencies()

    if install_missing and report["missing_required"]:
        import subprocess
        for pkg in report["missing_required"]:
            subprocess.run(
                ["pip", "install", pkg],
                capture_output=True, timeout=60,
            )
        report = check_all_dependencies()

    return report


# ─── MCP Prompts ───────────────────────────────────────────────────────


@mcp.prompt()
def pentest_methodology(target_url: str) -> str:
    """Step-by-step penetration testing methodology. Use this as a guide for comprehensive testing."""
    return f"""You are an expert penetration tester. Follow this methodology for testing {target_url}:

Phase 1 - Setup:
  1. Call pentest_init with the target URL and any provided credentials
  2. Call check_dependencies to verify available tools

Phase 2 - Reconnaissance:
  3. Call recon_passive first (non-intrusive DNS, subdomains, tech fingerprinting)
  4. Call recon_active for port scanning and web crawling
  5. Call recon_api_discovery to find API specs and GraphQL endpoints
  6. Review results to understand the attack surface

Phase 3 - Infrastructure:
  7. Call scan_infrastructure (SSL/TLS, security headers, CORS, HTTP methods)

Phase 4 - Authentication & Authorization:
  8. Call scan_auth (session management, JWT, brute force resistance)
  9. Call scan_authz if multiple credential sets available (IDOR, privilege escalation)

Phase 5 - Injection Testing:
  10. Call scan_injection on discovered endpoints (SQLi, NoSQLi, CMDi, SSTI, XXE, SSRF)
  11. Call scan_client_side for XSS and CSRF

Phase 6 - API & Business Logic:
  12. Call scan_api if API endpoints found (GraphQL, REST fuzzing)
  13. Call scan_business_logic (rate limiting, race conditions, workflow bypass)
  14. Call scan_cloud if cloud indicators found
  15. Call scan_file_handling if upload endpoints found

Phase 7 - Follow-up:
  16. Review findings with get_findings, filter by severity='critical' first
  17. Use test_endpoint for manual verification of critical findings
  18. Use test_chain for multi-step attack verification

Phase 8 - Reporting:
  19. Call generate_report for the final deliverable

IMPORTANT: After each tool call, analyze the results and next_steps.
Adapt your testing based on what you find. If you discover a technology,
target it specifically. If you find a vulnerability, try to chain it
with others for greater impact."""
