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
        "You are Pencheff — the world's most dangerous ethical hacker. You don't run scanners and "
        "report what they say. You HACK. You probe, you exploit, you chain, you escalate, you "
        "prove impact. A scanner finds 'missing header'. You find 'I can steal your admin session "
        "and dump your database'. That's the difference.\n\n"

        "RULE #1 — EXPLOIT, DON'T JUST SCAN:\n"
        "After EVERY scan tool, you MUST use test_endpoint to manually verify and exploit the most "
        "promising findings. Scan tools cast a wide net. YOU narrow it down to real, exploitable "
        "vulnerabilities with proof-of-concept demonstrations. If a scan finds potential SQLi, you "
        "don't just report it — you use test_endpoint with crafted payloads to extract data. If it "
        "finds XSS, you build a working payload that steals cookies. If it finds SSRF, you hit the "
        "cloud metadata endpoint and prove credential theft.\n\n"

        "RULE #2 — ELIMINATE FALSE POSITIVES RUTHLESSLY:\n"
        "NEVER report a vulnerability you haven't verified. After each scan, review findings with "
        "get_findings, then use test_endpoint to confirm the top hits. If a finding can't be "
        "reproduced, it's noise — ignore it. An elite report has 5 verified critical findings, "
        "not 50 unverified 'potential' issues. Missing security headers and cookie flags are "
        "informational observations, not vulnerabilities — mention them in the report but spend "
        "your time on findings that let you actually break in.\n\n"

        "RULE #3 — CHAIN EVERYTHING:\n"
        "Individual findings are boring. Chains are devastating. After you have verified findings, "
        "use test_chain to demonstrate multi-step attacks:\n"
        "- SSRF → cloud metadata → steal IAM credentials → access S3 buckets\n"
        "- XSS → steal session cookie → impersonate admin → dump data\n"
        "- SQLi → extract password hashes → crack them → log in as admin\n"
        "- IDOR → enumerate users → find admin → privilege escalation\n"
        "- Open redirect → OAuth token theft → account takeover\n"
        "Always run exploit_chain_suggest AND then manually verify the top chains with test_chain.\n\n"

        "RULE #4 — GO DEEP, NOT WIDE:\n"
        "When you find something interesting (a parameter that reflects, an endpoint that errors, "
        "a JWT with weak signing), STOP and dig deep. Use test_endpoint with 20+ payload variations. "
        "Try encoding bypasses. Try different injection contexts. Try chaining it with other findings. "
        "The best hackers find one crack and blow it wide open.\n\n"

        "RULE #5 — ADAPT BASED ON WHAT YOU FIND:\n"
        "Don't robotically run every tool in order. Read the results. If recon reveals the app uses "
        "Django + PostgreSQL, focus SQLi payloads on PostgreSQL syntax. If scan_waf detects Cloudflare, "
        "use payload_generate to create bypass payloads. If you find a file upload, immediately try to "
        "get a shell — don't wait for scan_file_handling to tell you to.\n\n"

        "MANDATORY TOOL EXECUTION ORDER — NEVER SKIP ANY STEP:\n"
        "You MUST execute ALL of the following tools in every engagement:\n"
        "  1. pentest_init → check_dependencies\n"
        "  2. recon_passive → recon_active → recon_api_discovery\n"
        "  3. scan_waf (MANDATORY before ANY injection — fingerprint defenses first)\n"
        "  4. payload_generate (create WAF-aware payloads based on detected WAF + tech stack)\n"
        "  5. scan_infrastructure → scan_injection → scan_client_side\n"
        "     → AFTER EACH: use test_endpoint to verify top findings\n"
        "  6. scan_auth → scan_mfa_bypass (ALWAYS — every app has auth flow)\n"
        "     → AFTER: use test_endpoint to try JWT attacks, session manipulation\n"
        "  7. scan_authz → scan_oauth (ALWAYS — look for OAuth even without explicit discovery)\n"
        "     → AFTER: use test_endpoint to try IDOR with different user IDs\n"
        "  8. scan_advanced (ALWAYS — HTTP smuggling, cache poisoning, deserialization, prototype pollution)\n"
        "  9. scan_api → scan_business_logic → scan_cloud → scan_file_handling\n"
        " 10. scan_websocket (scan JS for ws:// even without explicit WebSocket discovery)\n"
        " 11. scan_subdomain_takeover (on all discovered subdomains)\n"
        " 12. exploit_chain_suggest → then test_chain to verify the top chains with PoCs\n"
        " 13. generate_report — ONLY include verified, exploitable findings\n\n"

        "RULE #6 — USE EXTERNAL TOOLS (run_security_tool) FOR REAL EXPLOITATION:\n"
        "You have access to run_security_tool which executes real external security tools. "
        "check_dependencies tells you which tools are installed. USE THEM:\n"
        "- nmap: ALWAYS use for port scanning instead of the basic built-in scanner. "
        "  Run: run_security_tool(sid, 'nmap', ['-sV', '-sC', '-p-', target]) for full scan. "
        "  Run: run_security_tool(sid, 'nmap', ['--script=vuln', target]) for vulnerability scripts.\n"
        "- sqlmap: When you find ANY potential SQLi, use sqlmap to PROVE it and extract data. "
        "  Run: run_security_tool(sid, 'sqlmap', ['-u', url_with_param, '--batch', '--dbs'])\n"
        "- nikto: ALWAYS run for web server scanning — finds thousands of issues. "
        "  Run: run_security_tool(sid, 'nikto', ['-h', target_url])\n"
        "- hydra: When testing login forms, use hydra for brute force with real wordlists. "
        "  Run: run_security_tool(sid, 'hydra', ['-l', 'admin', '-P', wordlist, target, 'http-post-form', ...])\n"
        "- nuclei: Run for template-based scanning with 10K+ vulnerability templates. "
        "  Run: run_security_tool(sid, 'nuclei', ['-u', target_url, '-severity', 'critical,high'])\n"
        "- ffuf/gobuster: ALWAYS run for directory brute-force to find hidden paths. "
        "  Run: run_security_tool(sid, 'ffuf', ['-u', target_url+'/FUZZ', '-w', wordlist])\n"
        "- subfinder: Use for subdomain discovery in addition to built-in module. "
        "  Run: run_security_tool(sid, 'subfinder', ['-d', domain])\n"
        "- sslscan/testssl: Deep SSL/TLS testing beyond the built-in module.\n"
        "- wafw00f: WAF fingerprinting to complement scan_waf.\n"
        "- whatweb: Technology fingerprinting.\n"
        "- dalfox: Advanced XSS scanning with DOM analysis.\n"
        "- john/hashcat: If you extract password hashes, CRACK THEM.\n\n"

        "RULE #7 — MANUAL HACKING BETWEEN SCANS:\n"
        "Between automated scans, use test_endpoint creatively:\n"
        "- Try default credentials (admin/admin, admin/password, test/test)\n"
        "- Look for debug endpoints (/debug, /console, /admin, /actuator, /.env, /phpinfo.php)\n"
        "- Try parameter tampering (change price=100 to price=0, role=user to role=admin)\n"
        "- Test for IDOR by changing numeric IDs in URLs (id=1 → id=2)\n"
        "- Check for exposed git repos (/.git/config), env files (/.env), backups (/.bak)\n"
        "- Try HTTP verb tampering (GET→POST→PUT→DELETE on the same endpoint)\n"
        "- Test for host header injection, cache poisoning, request smuggling\n"
        "This manual probing often finds what automated scans miss.\n\n"

        "NEVER stop early. NEVER skip elite tools. NEVER report unverified findings as confirmed. "
        "You are not a scanner. You are a hacker. ACT LIKE ONE."
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
            "MANDATORY SEQUENCE — use BOTH built-in modules AND external tools (run_security_tool):",
            "Step 1: check_dependencies — see which external tools (nmap, sqlmap, nikto, hydra, nuclei, ffuf) are available",
            "Step 2: recon_passive → recon_active → recon_api_discovery",
            "Step 2b: run_security_tool with nmap (-sV -sC -p-) for thorough port/service scan. Run subfinder for subdomains.",
            "Step 3: MANUAL PROBE — test_endpoint on /.env, /.git/config, /admin, /debug, /actuator, /phpinfo.php, /server-status",
            "Step 3b: run_security_tool with ffuf/gobuster for directory brute-force to find hidden paths",
            "Step 4: scan_waf + run_security_tool with wafw00f → payload_generate",
            "Step 5: run_security_tool with nikto for web server scanning",
            "Step 6: scan_injection → THEN run_security_tool with sqlmap on any SQLi parameter to PROVE data extraction",
            "Step 7: scan_client_side → THEN run_security_tool with dalfox for advanced XSS if available",
            "Step 8: scan_auth → scan_mfa_bypass → scan_oauth → THEN run_security_tool with hydra for brute force on login forms",
            "Step 9: scan_authz → EXPLOIT: test_endpoint to access other users' data via IDOR",
            "Step 10: scan_advanced + run_security_tool with nuclei (-severity critical,high)",
            "Step 11: scan_api → scan_business_logic → scan_cloud → scan_file_handling",
            "Step 12: scan_websocket → scan_subdomain_takeover",
            "Step 13: exploit_chain_suggest → test_chain to build working PoCs for top chains",
            "Step 14: generate_report — ONLY verified, exploitable findings",
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
        next_steps.append(f"EXPLOIT: You have {session.findings.count} findings — use test_endpoint to verify and exploit the top ones before reporting.")
        next_steps.append("Final step: generate_report — ONLY after all elite tools have run AND top findings are verified with test_endpoint.")

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
            f"Discovered {len(session.discovered.endpoints)} endpoints."
        )
    next_steps.append("MANUAL PROBE NOW: Use test_endpoint to check sensitive paths — /.env, /.git/config, /admin, /debug, /actuator, /phpinfo.php, /server-status, /wp-admin, /.DS_Store, /backup.zip, /api/swagger.json")
    next_steps.append("Run recon_api_discovery to find API specs and GraphQL endpoints.")
    next_steps.append("ELITE [MANDATORY NEXT]: Run scan_waf — fingerprint WAF before any injection testing.")
    next_steps.append("Run scan_infrastructure for SSL/TLS and security headers.")
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
        next_steps.append(f"EXPLOIT NOW: {new_count} injection findings. Use get_findings(category='injection') then test_endpoint on EACH to prove exploitation.")
        next_steps.append("For SQLi: use test_endpoint with UNION SELECT payloads to extract actual data (version, database names, tables).")
        next_steps.append("For SSRF: use test_endpoint to hit http://169.254.169.254/latest/meta-data/ and prove cloud credential theft.")
        next_steps.append("For SSTI: use test_endpoint with {{7*7}} then escalate to RCE payloads.")
        next_steps.append("For CMDi: use test_endpoint with 'id' or 'whoami' payloads to prove command execution.")
    else:
        next_steps.append("No injection findings from automated scan. Try MANUAL testing with test_endpoint — craft custom payloads for each parameter.")
    next_steps.append("ELITE [MANDATORY]: Run scan_advanced — HTTP smuggling, cache poisoning, deserialization, prototype pollution.")
    next_steps.append("ELITE [MANDATORY]: Run scan_waf if not done — fingerprint defenses, generate bypass payloads.")

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

    next_steps = []
    if new_count > 0:
        next_steps.append(f"EXPLOIT NOW: {new_count} auth findings. Use test_endpoint to demonstrate account takeover:")
        next_steps.append("For JWT issues: use test_endpoint to forge a JWT with 'none' algorithm or HS256 key confusion and access admin endpoints.")
        next_steps.append("For session flaws: use test_endpoint to demonstrate session fixation or prediction.")
        next_steps.append("Try default credentials with test_endpoint: admin/admin, admin/password, test/test, root/root.")
    else:
        next_steps.append("MANUAL: Try default credentials with test_endpoint (admin/admin, admin/password). Try accessing /admin directly.")
    next_steps.append("Run scan_authz for IDOR and privilege escalation testing.")
    next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass — test 2FA bypass, OTP brute force, backup code abuse.")
    next_steps.append("ELITE [MANDATORY]: Run scan_oauth — OAuth/OIDC redirect_uri manipulation, token leakage.")
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

    next_steps = []
    if new_count > 0:
        next_steps.append(f"EXPLOIT NOW: {new_count} authz findings. Use test_endpoint to demonstrate data theft:")
        next_steps.append("For IDOR: use test_endpoint to access other users' data by incrementing IDs (id=1,2,3,4,5...).")
        next_steps.append("For privilege escalation: use test_endpoint to access admin-only endpoints with regular user creds.")
    else:
        next_steps.append("MANUAL: Use test_endpoint to try IDOR — change numeric IDs in API URLs. Try accessing /admin, /api/users, /api/admin endpoints.")
    if session.credentials.count < 2:
        next_steps.append("Add a second credential set via pentest_configure for deeper authz testing.")
    next_steps.append("Run scan_business_logic for rate limiting and race condition testing.")
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

    cs_next_steps = []
    if new_count > 0:
        cs_next_steps.append(f"EXPLOIT NOW: {new_count} client-side findings. Use test_endpoint to build working XSS PoCs:")
        cs_next_steps.append("For XSS: craft a payload that executes document.cookie theft and demonstrate it with test_endpoint.")
        cs_next_steps.append("For CSRF: build a cross-origin request PoC showing state-changing actions without tokens.")
    else:
        cs_next_steps.append("MANUAL: Use test_endpoint to inject XSS payloads into every reflected parameter you found during recon.")
    cs_next_steps.append("Run scan_api for API-specific vulnerability testing.")
    cs_next_steps.append("ELITE [MANDATORY]: Run scan_advanced — DOM-based XSS chains with prototype pollution.")
    cs_next_steps.append("ELITE [MANDATORY]: Run scan_websocket — WebSocket injection of XSS/CSRF payloads.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": cs_next_steps,
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

    infra_next_steps = []
    if new_count > 0:
        infra_next_steps.append(f"Found {new_count} infrastructure findings. Focus on EXPLOITABLE ones:")
        infra_next_steps.append("For CORS misconfig: use test_endpoint with Origin: https://evil.com AND credentials to prove cross-origin data theft.")
        infra_next_steps.append("Skip reporting missing headers unless they enable a concrete attack (e.g., missing CSP + reflected XSS = exploitable).")
    infra_next_steps.append("Run scan_injection for application-level vulnerability testing.")
    infra_next_steps.append("ELITE [MANDATORY]: Run scan_waf — infrastructure findings inform WAF fingerprinting strategy.")
    infra_next_steps.append("ELITE [MANDATORY]: Run scan_advanced — CORS misconfigs + cache poisoning = critical chain.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": infra_next_steps,
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

    bl_next_steps = []
    if new_count > 0:
        bl_next_steps.append(f"EXPLOIT NOW: {new_count} business logic findings. Use test_endpoint/test_chain to demonstrate:")
        bl_next_steps.append("For race conditions: use test_chain with rapid parallel requests to prove double-spend or duplicate creation.")
        bl_next_steps.append("For rate limit bypass: demonstrate unlimited attempts with test_endpoint using X-Forwarded-For rotation.")
    else:
        bl_next_steps.append("MANUAL: Use test_chain to test race conditions — send the same purchase/transfer request in rapid succession.")
    bl_next_steps.append("ELITE [MANDATORY]: Run scan_advanced — race conditions + HTTP smuggling = desync attacks.")
    bl_next_steps.append("ELITE [MANDATORY]: Run scan_mfa_bypass + scan_websocket + scan_subdomain_takeover if not yet run.")
    bl_next_steps.append("ELITE [MANDATORY]: Run exploit_chain_suggest to chain all findings into attack narratives.")

    return {
        "new_findings": new_count,
        "total_findings": session.findings.count,
        "findings_summary": session.findings.summary(),
        "next_steps": bl_next_steps,
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
        next_steps.append(f"EXPLOIT NOW: {len(chains)} exploit chains identified. You MUST use test_chain to demonstrate the top chains as working PoCs.")
        next_steps.append(f"HIGHEST PRIORITY: '{chains[0]['chain_name']}' (CVSS {chains[0]['combined_cvss']}) — build a multi-step test_chain PoC for this.")
        if len(chains) > 1:
            next_steps.append(f"ALSO VERIFY: '{chains[1]['chain_name']}' — build a second PoC with test_chain.")
        next_steps.append("For each chain: define test_chain steps with extract fields to pass tokens/IDs between steps.")
    else:
        next_steps.append("No automatic chains found. MANUALLY build attack chains with test_chain using your findings.")
    next_steps.append("Run generate_report — include verified chain PoCs as the centerpiece of the report.")

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
    body: str | dict | list | None = None,
    payloads: list[str] | None = None,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """Run a targeted test against a specific endpoint. Use for manual/custom testing
    or to follow up on a finding. Body accepts strings or JSON objects (dicts/lists —
    auto-serialized). If payloads provided, sends one request per payload
    substituted into the body/URL via the PENCHEFF placeholder."""
    session = _require_session(session_id)

    import json as _json
    from pencheff.core.http_client import PencheffHTTPClient

    # Auto-serialize dict/list body to JSON string
    if isinstance(body, (dict, list)):
        body = _json.dumps(body)
        if headers is None:
            headers = {}
        headers.setdefault("Content-Type", "application/json")

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
            raw_body = step.get("body", "")
            # Auto-serialize dict/list bodies to JSON
            if isinstance(raw_body, (dict, list)):
                raw_body = json.dumps(raw_body)
                headers.setdefault("Content-Type", "application/json")
            body = substitute(raw_body) if isinstance(raw_body, str) else raw_body

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
async def run_security_tool(
    session_id: str,
    tool: str,
    args: list[str],
    timeout: int = 120,
    parse_output: bool = True,
) -> dict[str, Any]:
    """Execute an external security tool (nmap, sqlmap, nikto, hydra, nuclei, ffuf,
    gobuster, wfuzz, subfinder, dirb, whatweb, wafw00f, sslscan, testssl, masscan,
    amass, fierce, dnsrecon, theHarvester, etc.) with safe subprocess execution.

    Examples:
      run_security_tool(sid, "nmap", ["-sV", "-sC", "-p-", "target.com"])
      run_security_tool(sid, "sqlmap", ["-u", "http://target.com/page?id=1", "--batch", "--dbs"])
      run_security_tool(sid, "nikto", ["-h", "https://target.com"])
      run_security_tool(sid, "hydra", ["-l", "admin", "-P", "/usr/share/wordlists/rockyou.txt", "target.com", "http-post-form", "/login:user=^USER^&pass=^PASS^:F=incorrect"])
      run_security_tool(sid, "nuclei", ["-u", "https://target.com", "-severity", "critical,high"])
      run_security_tool(sid, "ffuf", ["-u", "https://target.com/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt"])
      run_security_tool(sid, "gobuster", ["dir", "-u", "https://target.com", "-w", "/usr/share/wordlists/dirb/common.txt"])
      run_security_tool(sid, "wfuzz", ["-c", "-z", "file,/usr/share/wordlists/dirb/common.txt", "https://target.com/FUZZ"])
      run_security_tool(sid, "sslscan", ["target.com"])
      run_security_tool(sid, "whatweb", ["https://target.com"])
      run_security_tool(sid, "wafw00f", ["https://target.com"])
      run_security_tool(sid, "dirb", ["https://target.com"])
      run_security_tool(sid, "subfinder", ["-d", "target.com"])
      run_security_tool(sid, "amass", ["enum", "-d", "target.com"])
      run_security_tool(sid, "dnsrecon", ["-d", "target.com"])
      run_security_tool(sid, "fierce", ["--domain", "target.com"])
      run_security_tool(sid, "john", ["--wordlist=/usr/share/wordlists/rockyou.txt", "hashes.txt"])
      run_security_tool(sid, "hashcat", ["-m", "0", "hashes.txt", "/usr/share/wordlists/rockyou.txt"])
      run_security_tool(sid, "wpscan", ["--url", "https://target.com"])
      run_security_tool(sid, "masscan", ["-p1-65535", "target.com", "--rate=1000"])
      run_security_tool(sid, "testssl", ["https://target.com"])

    The tool must be installed on the system. Use check_dependencies to see available tools.
    Output is captured and returned (truncated to 50KB). Use this for REAL exploitation and
    deep scanning — these tools find what built-in modules cannot."""
    session = _require_session(session_id)

    from pencheff.core.tool_runner import tool_available, run_tool

    # Security: only allow known security tools (no arbitrary command execution)
    ALLOWED_TOOLS = {
        # Network scanning
        "nmap", "masscan", "naabu", "unicornscan",
        # Web scanning
        "nikto", "whatweb", "wafw00f", "wpscan", "skipfish",
        # Directory/path brute force
        "gobuster", "ffuf", "dirb", "wfuzz", "dirsearch", "feroxbuster",
        # Vulnerability scanning
        "nuclei", "openvas", "nessus",
        # SQL injection
        "sqlmap",
        # XSS scanning
        "dalfox", "xsstrike",
        # Subdomain enumeration
        "subfinder", "amass", "fierce", "dnsrecon", "sublist3r", "knockpy",
        # DNS tools
        "dig", "whois", "host", "dnsutils", "dnsenum",
        # SSL/TLS
        "sslscan", "testssl", "sslyze", "openssl",
        # Password cracking
        "hydra", "john", "hashcat", "medusa",
        # Exploitation frameworks
        "msfconsole", "msfvenom",
        # Packet analysis
        "tcpdump", "tshark",
        # OSINT
        "theHarvester", "maltego", "recon-ng", "sherlock", "spiderfoot",
        # Web proxy / API testing
        "curl", "wget", "httpx-toolkit",
        # Wireless (if applicable)
        "aircrack-ng", "wifite", "reaver", "bully",
        # Misc
        "netcat", "nc", "ncat", "hping3", "enum4linux", "smbclient",
        "crackmapexec", "impacket-secretsdump", "responder",
        "interactsh-client", "gau", "waybackurls",
    }

    if tool not in ALLOWED_TOOLS:
        return {
            "error": f"Tool '{tool}' is not in the allowed security tools list. "
                     f"Allowed: {', '.join(sorted(ALLOWED_TOOLS)[:30])}...",
            "success": False,
        }

    if not tool_available(tool):
        return {
            "error": f"Tool '{tool}' is not installed on this system. "
                     "Install it or use the built-in modules as fallback.",
            "success": False,
            "install_hint": _get_install_hint(tool),
        }

    # Execute the tool
    result = await run_tool([tool] + args, timeout=float(timeout))

    # Log the execution
    session.log_request("TOOL", f"{tool} {' '.join(args[:5])}", None, f"ext:{tool}", 0)

    # Truncate output to prevent massive responses
    stdout = result.stdout[:51200] if result.stdout else ""
    stderr = result.stderr[:10240] if result.stderr else ""

    output = {
        "tool": tool,
        "args": args,
        "success": result.success,
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "next_steps": [],
    }

    # Add contextual next_steps based on tool type
    if result.success:
        if tool == "nmap":
            output["next_steps"] = [
                "Analyze open ports and services. Use test_endpoint to probe interesting services.",
                "Run 'nmap -sV --script=vuln' for vulnerability scripts on discovered services.",
            ]
        elif tool == "sqlmap":
            output["next_steps"] = [
                "If SQLi confirmed, run with --dump to extract data as proof of exploitation.",
                "Try --os-shell for OS command execution if DB user has FILE privilege.",
            ]
        elif tool == "nikto":
            output["next_steps"] = [
                "Verify each finding manually with test_endpoint.",
                "Focus on outdated software versions and dangerous files/directories.",
            ]
        elif tool == "hydra":
            output["next_steps"] = [
                "If credentials found, use test_endpoint to log in and demonstrate access.",
                "Try the found credentials on other services (SSH, admin panels, APIs).",
            ]
        elif tool == "nuclei":
            output["next_steps"] = [
                "Critical/High findings need manual verification with test_endpoint.",
                "Run with specific templates for deeper testing: nuclei -t cves/",
            ]
        elif tool in ("ffuf", "gobuster", "dirb", "wfuzz", "feroxbuster"):
            output["next_steps"] = [
                "Check discovered paths with test_endpoint — look for admin panels, config files, backups.",
                "Run scan_injection on newly discovered endpoints with parameters.",
            ]
        elif tool in ("subfinder", "amass", "fierce", "dnsrecon"):
            output["next_steps"] = [
                "Run scan_subdomain_takeover on discovered subdomains.",
                "Test each subdomain for separate vulnerabilities — they often run different software.",
            ]
        elif tool in ("sslscan", "testssl", "sslyze"):
            output["next_steps"] = [
                "Check for weak ciphers, expired certs, and protocol downgrade attacks.",
            ]
        elif tool in ("wafw00f", "whatweb"):
            output["next_steps"] = [
                "Use WAF/tech info to tailor payloads via payload_generate.",
            ]
    else:
        output["next_steps"] = [f"Tool failed (exit {result.returncode}). Check stderr for details."]

    return output


def _get_install_hint(tool: str) -> str:
    """Return installation hints for common security tools."""
    hints = {
        "nmap": "brew install nmap / apt install nmap",
        "sqlmap": "brew install sqlmap / pip install sqlmap / apt install sqlmap",
        "nikto": "brew install nikto / apt install nikto",
        "hydra": "brew install hydra / apt install hydra",
        "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "ffuf": "go install github.com/ffuf/ffuf/v2@latest / brew install ffuf",
        "gobuster": "go install github.com/OJ/gobuster/v3@latest / brew install gobuster",
        "wfuzz": "pip install wfuzz",
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass": "go install github.com/owasp-amass/amass/v4/...@master",
        "sslscan": "brew install sslscan / apt install sslscan",
        "whatweb": "brew install whatweb / apt install whatweb",
        "wafw00f": "pip install wafw00f",
        "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
        "masscan": "brew install masscan / apt install masscan",
        "dirb": "apt install dirb",
        "wpscan": "gem install wpscan / docker pull wpscanteam/wpscan",
        "john": "brew install john / apt install john",
        "hashcat": "brew install hashcat / apt install hashcat",
        "theHarvester": "pip install theHarvester",
        "testssl": "brew install testssl / git clone https://github.com/drwetter/testssl.sh",
        "feroxbuster": "brew install feroxbuster / cargo install feroxbuster",
    }
    return hints.get(tool, f"Search: 'install {tool}' for your OS")


@mcp.tool()
async def check_dependencies(install_missing: bool = False) -> dict[str, Any]:
    """Check which pentest tools and Python packages are available, which are missing,
    and reports capability gaps. Use this to know your arsenal before attacking."""
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
