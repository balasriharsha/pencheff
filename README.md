# Pencheff

AI-powered penetration testing agent for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Provide a target URL and credentials in natural language — Pencheff handles reconnaissance, vulnerability scanning, exploit chain analysis, and compliance-mapped reporting, all driven by Claude's reasoning.

Unlike static scanners, Pencheff uses Claude as its brain. Each testing module returns structured findings and `next_steps` recommendations, enabling Claude to adaptively decide what to test next, chain discovered vulnerabilities together, and prioritize like a human pentester.

## Features

- **30 MCP tools** covering the full pentest lifecycle — from reconnaissance to exploit chain analysis
- **50 attack modules** across 11 categories implementing real detection logic
- **326 payloads** across 17 payload files for injection, bypass, and exploitation testing
- **Adaptive testing** — Claude reasons about discovered tech stack, WAF detection, and vulnerabilities to guide testing strategy
- **OWASP Top 10 2021** coverage with CVSS v3.1 scoring
- **Compliance mapping** — PCI-DSS 4.0, NIST 800-53 for 27 vulnerability categories
- **Multi-credential support** — test authorization boundaries between user roles
- **Exploit chain analysis** — automatically identifies multi-step attack paths across findings
- **WAF-aware payloads** — detects WAF vendor and generates bypass-optimized payloads
- **116 external security tools** — execute nmap, sqlmap, nikto, hydra, nuclei, metasploit, and 110 more directly via `run_security_tool`
- **Exploitation-first methodology** — every scan finding is verified with `test_endpoint`, false positives eliminated, PoCs demonstrated
- **Secure by design** — credentials wrapped in `MaskedSecret`, never logged or leaked in findings
- **Natural language input** — just describe your target and credentials

## Installation

### As a Claude Code Plugin (Recommended)

```bash
/plugin marketplace add balasriharsha/pencheff
/plugin install pencheff
/reload-plugins
```

### From Source

```bash
git clone https://github.com/balasriharsha/pencheff.git
cd pencheff
```

Then add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "pencheff": {
      "command": "uv",
      "args": ["run", "--project", "./plugins/pencheff", "python", "-m", "pencheff"]
    }
  }
}
```

### Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (dependency management, installed automatically by Claude Code plugins)
- Claude Code

## Quick Start

Use the built-in skill for a full automated pentest:

```
/pencheff:pentest https://example.com username: admin, password: test123
```

Or use the agent directly:

```
@pencheff Run a full pentest against https://api.example.com with API key: sk-abc123
```

Or call individual tools for targeted testing:

```
Use pentest_init to start a session against https://example.com, then run scan_injection on the /api/login endpoint.
```

## MCP Tools (30)

### Session Management (3)

| Tool | Description |
|------|-------------|
| `pentest_init` | Initialize session with target URL, credentials, scope, and depth (quick/standard/deep) |
| `pentest_status` | Get progress — completed modules, finding counts, intelligent next-step recommendations |
| `pentest_configure` | Update credentials, scope, or depth mid-session |

### Reconnaissance (3)

| Tool | Description |
|------|-------------|
| `recon_passive` | DNS enumeration, WHOIS, certificate transparency, subdomain discovery, technology fingerprinting |
| `recon_active` | TCP port scanning (top-100/top-1000), web crawling, service fingerprinting, endpoint discovery |
| `recon_api_discovery` | OpenAPI/Swagger spec detection, GraphQL introspection, API route enumeration from JavaScript/sitemap/robots.txt |

### Vulnerability Scanning (7)

| Tool | Description |
|------|-------------|
| `scan_injection` | 10 injection types: SQLi (error/blind/time-based), NoSQLi, command injection, SSTI, XXE, SSRF, LDAP injection, second-order injection, open redirect, HTTP header injection |
| `scan_auth` | Session management flaws, JWT attacks (none algorithm, claim tampering), brute force resistance, password policy |
| `scan_authz` | IDOR, horizontal/vertical privilege escalation, RBAC bypass (requires multiple credential sets for best results) |
| `scan_client_side` | XSS (reflected/stored/DOM-based), CSRF token analysis, clickjacking |
| `scan_infrastructure` | SSL/TLS configuration, security headers (CSP, HSTS, X-Frame-Options, etc.), CORS misconfigurations, HTTP method enumeration |
| `scan_api` | REST parameter fuzzing, GraphQL depth/batch attacks, mass assignment / object injection testing |
| `scan_cloud` | S3 bucket enumeration/permissions, cloud metadata service access (AWS/GCP/Azure) |

### Advanced Attacks (4)

| Tool | Description |
|------|-------------|
| `scan_waf` | WAF detection and fingerprinting (Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, F5, Fortinet, Sucuri, Barracuda, Wordfence), bypass testing with encoding/obfuscation. **Run before injection scans** — results inform payload strategy |
| `scan_advanced` | HTTP request smuggling (CL.TE, TE.CL, TE.TE with 12 obfuscation variants), web cache poisoning/deception, insecure deserialization (Java/Python/PHP/.NET/YAML), prototype pollution (server-side and client-side), DNS rebinding |
| `scan_websocket` | Cross-Site WebSocket Hijacking (CSWSH), WebSocket auth bypass, message injection (SQLi/XSS/CMDi via WebSocket), insecure transport detection. Auto-discovers WebSocket endpoints from JavaScript and upgrade probes |
| `scan_subdomain_takeover` | Dangling CNAME detection for 20+ services (GitHub Pages, S3, Heroku, Azure, Shopify, Fastly, Netlify, Vercel, and more) with HTTP response signature matching |

### Authentication & Authorization Deep Dive (2)

| Tool | Description |
|------|-------------|
| `scan_oauth` | OAuth/OIDC testing: redirect_uri manipulation (13+ bypass techniques), state parameter validation, token leakage via Referer, scope escalation. Auto-discovers OAuth endpoints from `.well-known` and common paths |
| `scan_mfa_bypass` | 2FA/MFA bypass: direct endpoint access (skip 2FA), OTP brute force (rate limit check), backup code abuse, race condition on code validation |

### Specialized Scanning (2)

| Tool | Description |
|------|-------------|
| `scan_file_handling` | File upload bypass (extension, MIME type, magic bytes), path traversal with encoding bypasses |
| `scan_business_logic` | Rate limiting adequacy, race conditions (concurrent requests), workflow bypass, state manipulation |

### Intelligence Tools (2)

| Tool | Description |
|------|-------------|
| `exploit_chain_suggest` | Analyzes all findings against 14 chain rules to identify multi-step attack paths (e.g., SSRF + cloud metadata = credential theft, XSS + weak session = account takeover). Returns ranked chains with combined CVSS and exploitation narratives |
| `payload_generate` | Generates context-aware payloads optimized for the target's detected tech stack and WAF. Supports 13 attack types with framework-specific mutations (MySQL/PostgreSQL/MSSQL for SQLi, Jinja2/Twig/Freemarker for SSTI, etc.) and WAF bypass encodings |

### External Tool Execution (1)

| Tool | Description |
|------|-------------|
| `run_security_tool` | Execute any of 116 allowlisted external security tools (nmap, sqlmap, nikto, hydra, nuclei, metasploit, etc.) with safe subprocess execution. Accepts tool name and arguments, returns stdout/stderr with intelligent next-step recommendations based on tool category. See [External Security Tools](#external-security-tools-116) for the full list |

### Manual / Targeted Testing (3)

| Tool | Description |
|------|-------------|
| `test_endpoint` | Custom HTTP request with specific payloads against a single endpoint. Accepts `body` as string, dict, or list (auto-serialized to JSON). Supports payload substitution via `PENCHEFF` marker |
| `test_chain` | Multi-step attack sequence with variable extraction (JSONPath) and substitution between steps — for verifying exploit chains. Step bodies accept string, dict, or list |
| `analyze_response` | Analyze an HTTP response for information disclosure, error messages, sensitive data patterns (AWS keys, JWTs, emails), and missing security headers |

### Reporting (3)

| Tool | Description |
|------|-------------|
| `get_findings` | Retrieve findings filtered by severity, category, or OWASP category |
| `generate_report` | Full pentest report — executive summary, technical details, CVSS scores, compliance mapping (Markdown/JSON). Types: executive, technical, full |
| `check_dependencies` | Verify available Python packages and system tools, report capability gaps |

## Attack Modules (50)

### Reconnaissance (5 modules)

| Module | File | Techniques |
|--------|------|------------|
| DNS Enumeration | `recon/dns_enum.py` | A/AAAA/MX/TXT/NS/CNAME records, AXFR zone transfer, SPF/DMARC analysis |
| Subdomain Discovery | `recon/subdomain.py` | Certificate transparency logs, DNS brute force |
| Technology Fingerprint | `recon/tech_fingerprint.py` | Headers, cookies, HTML patterns, JavaScript framework detection |
| Port Scanner | `recon/port_scan.py` | TCP connect scan (top-100/top-1000), banner grabbing, service identification |
| Subdomain Takeover | `recon/subdomain_takeover.py` | Dangling CNAME detection for 20+ services, NS delegation takeover check |

### Web Infrastructure (5 modules)

| Module | File | Techniques |
|--------|------|------------|
| Web Crawler | `web/crawler.py` | Recursive spidering, endpoint discovery, parameter extraction |
| SSL/TLS | `web/ssl_tls.py` | Protocol version check, weak cipher detection, certificate analysis |
| Security Headers | `web/headers.py` | 7+ header checks (HSTS, CSP, X-Frame-Options, etc.), cookie flag analysis |
| CORS | `web/cors.py` | Wildcard origin, reflected origin, null origin, subdomain bypass, credential leak |
| HTTP Methods | `web/http_methods.py` | PUT/DELETE/TRACE/CONNECT enumeration, method override testing |

### Injection (10 modules)

| Module | File | Techniques |
|--------|------|------------|
| SQL Injection | `injection/sqli.py` | Error-based, blind boolean, time-based with database-specific payloads (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) |
| NoSQL Injection | `injection/nosqli.py` | MongoDB operator injection ($gt, $ne, $regex, $where), JavaScript injection |
| Command Injection | `injection/cmdi.py` | Pipe, semicolon, backtick, $() with output-based and time-based detection |
| SSTI | `injection/ssti.py` | Jinja2, Twig, Freemarker, ERB, Mako template detection and exploitation |
| XXE | `injection/xxe.py` | Classic external entity, blind XXE, parameter entities, billion laughs detection |
| SSRF | `injection/ssrf.py` | Cloud metadata (AWS/GCP/Azure), internal scanning, IP encoding bypasses (octal, hex, IPv6) |
| LDAP Injection | `injection/ldap.py` | Filter injection, authentication bypass, blind boolean LDAP |
| Second-Order Injection | `injection/second_order.py` | Stored SQLi/XSS/SSTI via two-phase inject-then-trigger with canary markers |
| Open Redirect | `injection/open_redirect.py` | 25+ redirect parameter names, 12 bypass techniques (protocol-relative, encoding, backslash, null byte) |
| Header Injection | `injection/header_injection.py` | CRLF injection, HTTP response splitting, host header poisoning for password reset attacks |

### Authentication (6 modules)

| Module | File | Techniques |
|--------|------|------------|
| Session Management | `auth/session_mgmt.py` | Session timeout, fixation, hijacking, concurrent session testing |
| JWT Attacks | `auth/jwt_attacks.py` | None algorithm, claim tampering, key confusion (RS256 to HS256), expiration checks |
| Brute Force | `auth/brute_force.py` | Account enumeration, lockout policy detection, rate limit testing |
| Password Policy | `auth/password_policy.py` | Complexity requirements, common password acceptance |
| OAuth/OIDC | `auth/oauth_attacks.py` | redirect_uri bypass (13+ techniques), state parameter validation, token leakage, scope escalation, PKCE bypass |
| MFA Bypass | `auth/mfa_bypass.py` | Direct endpoint access, OTP brute force, backup code abuse, race condition on validation |

### Authorization (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| IDOR | `authz/idor.py` | Numeric ID manipulation, UUID enumeration, cross-user access testing |
| Privilege Escalation | `authz/privilege_esc.py` | Vertical/horizontal escalation via parameter and path manipulation |
| RBAC Bypass | `authz/rbac_bypass.py` | Role injection, forced browsing, path normalization bypass |

### Client-Side (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| XSS | `client_side/xss.py` | Reflected, stored indicators, DOM-based, context-aware detection, encoding bypasses |
| CSRF | `client_side/csrf.py` | Token absence/weakness, SameSite bypass, custom header bypass |
| Clickjacking | `client_side/clickjacking.py` | X-Frame-Options testing, CSP frame-ancestors analysis |

### API Security (4 modules)

| Module | File | Techniques |
|--------|------|------------|
| REST Discovery | `api/rest_discovery.py` | OpenAPI/Swagger detection (15+ common paths), API documentation enumeration |
| GraphQL | `api/graphql.py` | Introspection dump, query depth limits, batch query limits, field suggestion |
| API Fuzzer | `api/api_fuzzer.py` | Parameter type fuzzing, boundary values, method enumeration |
| Mass Assignment | `api/mass_assignment.py` | Privilege property injection (role, admin, is_staff), framework-specific payloads (Rails, Django, Node.js, Laravel) |

### Business Logic (3 modules)

| Module | File | Techniques |
|--------|------|------------|
| Rate Limiting | `logic/rate_limiting.py` | Rapid request burst testing, rate limit header analysis |
| Race Conditions | `logic/race_condition.py` | Concurrent request testing for double-spend, TOCTOU |
| Workflow Bypass | `logic/workflow_bypass.py` | Multi-step process skip, state manipulation |

### Cloud (2 modules)

| Module | File | Techniques |
|--------|------|------------|
| S3 Enumeration | `cloud/s3_enum.py` | Bucket naming patterns, public listing, permission testing |
| Cloud Metadata | `cloud/metadata.py` | IMDSv1/v2 access via SSRF, credential theft |

### File Handling (2 modules)

| Module | File | Techniques |
|--------|------|------------|
| File Upload | `file_handling/upload.py` | Extension bypass (double ext, null byte), MIME type confusion, magic byte injection |
| Path Traversal | `file_handling/path_traversal.py` | LFI with encoding bypasses (double URL encoding, UTF-8, null byte) |

### Advanced (7 modules)

| Module | File | Techniques |
|--------|------|------------|
| WAF Detection | `advanced/waf_detection.py` | Fingerprinting for 10 WAF vendors via response signature matching, encoding/obfuscation bypass testing |
| HTTP Smuggling | `advanced/http_smuggling.py` | CL.TE, TE.CL desync via raw sockets, TE.TE with 12 header obfuscation variants, CRLF request splitting |
| Cache Poisoning | `advanced/cache_poisoning.py` | Unkeyed header injection (10 headers), cache deception via path suffix, fat GET parameter cloaking |
| Deserialization | `advanced/deserialization.py` | Java (magic bytes, ysoserial endpoints), Python pickle, PHP unserialize, .NET ViewState, YAML constructor injection |
| Prototype Pollution | `advanced/prototype_pollution.py` | Server-side JSON body pollution (__proto__, constructor.prototype), client-side URL parameter pollution, gadget detection |
| DNS Rebinding | `advanced/dns_rebinding.py` | Host header validation assessment, IP binding check |
| WebSocket Security | `advanced/websocket_security.py` | CSWSH (origin validation), auth bypass, message injection, insecure transport, auto-discovery from JavaScript |

## Payload Library (326 payloads across 17 files)

| File | Payloads | Description |
|------|----------|-------------|
| `sqli.txt` | 20 | Error-based, UNION, time-based, blind boolean SQLi |
| `xss.txt` | 18 | Reflected XSS, encoding bypasses, event handlers, javascript: protocol |
| `ssti.txt` | 10 | Jinja2, Twig, Mako, ERB, Freemarker template payloads |
| `path_traversal.txt` | 16 | ../../../, encoding variants, Windows paths, null byte |
| `xxe.txt` | 18 | External entity, blind OOB, parameter entity, CDATA exfil, PHP/Java-specific |
| `nosqli.txt` | 13 | MongoDB operators ($gt, $ne, $regex, $where), URL-encoded variants |
| `cmdi.txt` | 24 | Pipe, semicolon, backtick, $(), blind via sleep/ping, argument injection |
| `ssrf.txt` | 23 | Cloud metadata (AWS/GCP/Azure/DO), IP encoding (octal, hex, IPv6), protocol tricks |
| `waf_bypass.txt` | 38 | Double encoding, Unicode, case mutation, nested tags, comment injection, null byte |
| `oauth.txt` | 20 | redirect_uri bypass (subdomain, encoding, fragment, protocol-relative, backslash) |
| `deserialization.txt` | 19 | Java gadget indicators, Python pickle, PHP objects, YAML constructors, Node.js |
| `smuggling.txt` | 27 | CL.TE/TE.CL probes, 12 TE obfuscation variants, CRLF sequences, H2 smuggling |
| `prototype_pollution.txt` | 15 | __proto__ JSON injection, constructor.prototype, URL parameter variants |
| `websocket.txt` | 15 | XSS/SQLi/CMDi via WebSocket, oversized messages, admin channel subscribe |
| `ldap.txt` | 15 | Filter injection (*, )(, \00), auth bypass, attribute enumeration |
| `open_redirect.txt` | 25 | Protocol-relative, double encoding, null byte, @-bypass, backslash, data: URI |
| `header_injection.txt` | 10 | CRLF injection (%0d%0a), response splitting, Set-Cookie injection |

## Architecture

```
plugins/pencheff/
├── .claude-plugin/plugin.json     # Plugin metadata
├── .mcp.json                      # MCP server launch config
├── agents/pencheff.md             # Agent definition
├── skills/pentest/                # /pencheff:pentest skill
├── pyproject.toml                 # Python package (hatch build)
└── pencheff/
    ├── __main__.py                # Entry: python -m pencheff
    ├── server.py                  # FastMCP server — 30 tools, 1 prompt
    ├── config.py                  # Constants, OWASP/PCI-DSS/NIST mappings (27 categories)
    ├── core/
    │   ├── session.py             # PentestSession state (endpoints, subdomains, tech stack,
    │   │                          #   WebSocket/OAuth endpoints, WAF info, exploit chains)
    │   ├── credentials.py         # MaskedSecret, CredentialSet, CredentialStore
    │   ├── findings.py            # Finding model, CVSS scoring, deduplication
    │   ├── http_client.py         # httpx wrapper: HTTP/1.1, HTTP/2, WebSocket, raw sockets,
    │   │                          #   credential injection, rate limiting
    │   ├── payload_loader.py      # Centralized payload file loader
    │   ├── tool_runner.py         # Safe subprocess execution (no shell=True)
    │   └── dependency_manager.py  # Python/system tool availability checks (116 tools)
    ├── modules/
    │   ├── base.py                # BaseTestModule ABC
    │   ├── recon/                  # 5 modules: DNS, subdomains, tech fingerprint, port scan,
    │   │                          #   subdomain takeover
    │   ├── web/                   # 5 modules: crawler, SSL/TLS, headers, CORS, HTTP methods
    │   ├── injection/             # 10 modules: SQLi, NoSQLi, CMDi, SSTI, XXE, SSRF,
    │   │                          #   LDAP, second-order, open redirect, header injection
    │   ├── auth/                  # 6 modules: session mgmt, JWT, brute force, password policy,
    │   │                          #   OAuth/OIDC, MFA bypass
    │   ├── authz/                 # 3 modules: IDOR, privilege escalation, RBAC bypass
    │   ├── client_side/           # 3 modules: XSS, CSRF, clickjacking
    │   ├── api/                   # 4 modules: REST discovery, GraphQL, API fuzzer,
    │   │                          #   mass assignment
    │   ├── logic/                 # 3 modules: rate limiting, race conditions, workflow bypass
    │   ├── cloud/                 # 2 modules: S3 enum, metadata service
    │   ├── file_handling/         # 2 modules: upload bypass, path traversal
    │   └── advanced/              # 7 modules: WAF detection, HTTP smuggling, cache poisoning,
    │                              #   deserialization, prototype pollution, DNS rebinding,
    │                              #   WebSocket security
    ├── reporting/
    │   ├── cvss.py                # CVSS v3.1 base score calculator
    │   ├── compliance.py          # OWASP/PCI-DSS/NIST coverage analysis
    │   └── renderer.py            # Markdown and JSON report rendering
    └── payloads/                  # 17 payload files, 326 total payloads
```

## How It Works

### Adaptive Intelligence

Every tool returns a structured response:

```json
{
  "findings": [...],
  "findings_summary": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 4 },
  "next_steps": [
    "WAF detected: Cloudflare. Use payload_generate to create WAF-aware payloads.",
    "3 bypass techniques succeeded — use these for injection scans.",
    "Run scan_injection and scan_advanced with WAF-aware strategy."
  ]
}
```

Claude reads these `next_steps` and decides what to test next. This feedback loop means Pencheff adapts to each target instead of running the same static checks every time.

### Exploitation-First Methodology

Pencheff doesn't just scan — it **hacks**. The agent follows 7 core rules:

1. **Exploit, don't just scan** — After every scan tool, use `test_endpoint` to verify findings. If you can't prove it, it's not a finding.
2. **Eliminate false positives** — Re-test with different payloads, check for SPA behavior, confirm with manual verification.
3. **Chain everything** — Every finding is a building block. SSRF + cloud metadata = credential theft. XSS + weak sessions = account takeover. Use `exploit_chain_suggest` and `test_chain`.
4. **Go deep** — Don't stop at the first layer. If SQLi works, extract data. If SSRF works, pivot to internal services.
5. **Adapt to defenses** — WAF detected? Generate bypass payloads. Rate limited? Slow down and rotate. SPA returning 200 for all paths? Recognize it and move on.
6. **Use external tools** — `run_security_tool` gives you access to 116 tools. Use nmap for port scanning, sqlmap for SQLi exploitation, hydra for brute force, nuclei for template scanning.
7. **Manual hacking between scans** — Use `test_endpoint` to probe interesting behavior. Don't wait for a scan tool to tell you what to test.

### Testing Phases (10)

The built-in `pentest_methodology` prompt guides Claude through a comprehensive 10-phase assessment:

1. **Preparation** — Initialize session with `pentest_init`, verify tools with `check_dependencies`, run `run_security_tool` with nmap for port scanning
2. **Reconnaissance** — Map the full attack surface: DNS, subdomains, ports, tech stack, APIs. Use `subfinder`, `amass`, `whatweb` via `run_security_tool`
3. **Infrastructure** — SSL/TLS, security headers, CORS, HTTP methods. Use `sslscan`, `testssl` via `run_security_tool`
4. **Authentication** — Session management, JWT vulnerabilities, brute force resistance. Use `hydra` for credential testing
5. **WAF Detection** — Fingerprint WAF with `scan_waf` and `wafw00f` before injection testing
6. **Injection Warfare** — 10 injection types across all discovered endpoints. Use `sqlmap` for SQLi exploitation, verify every finding with `test_endpoint`
7. **Advanced Attacks** — HTTP smuggling, cache poisoning, deserialization, prototype pollution. Use `nuclei` for template-based detection
8. **API, Business Logic & Specialized** — GraphQL, mass assignment, race conditions, cloud, file handling, OAuth, MFA bypass, WebSocket, subdomain takeover
9. **Exploit Chain Analysis** — Automatic chain detection with `exploit_chain_suggest` + manual verification with `test_chain`
10. **Reporting** — CVSS-scored findings with OWASP/PCI-DSS/NIST compliance mapping

### Using External Tools

The `run_security_tool` tool lets the agent execute any of the 116 allowlisted tools directly:

```
# Port scanning with nmap
run_security_tool(session_id, "nmap", ["-sV", "-sC", "-p-", "target.com"])

# SQL injection exploitation with sqlmap
run_security_tool(session_id, "sqlmap", ["-u", "https://target.com/api?id=1", "--batch", "--dbs"])

# Directory brute force with ffuf
run_security_tool(session_id, "ffuf", ["-u", "https://target.com/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt"])

# Brute force login with hydra
run_security_tool(session_id, "hydra", ["-l", "admin", "-P", "passwords.txt", "target.com", "http-post-form", "/login:user=^USER^&pass=^PASS^:Invalid"])

# Template-based vuln scanning with nuclei
run_security_tool(session_id, "nuclei", ["-u", "https://target.com", "-severity", "critical,high"])

# WAF detection with wafw00f
run_security_tool(session_id, "wafw00f", ["https://target.com"])
```

Each tool execution returns structured output with intelligent `next_steps` based on the tool category — the agent knows what to do after nmap finds open ports, after sqlmap confirms injection, etc.

### Exploit Chain Analysis

The `exploit_chain_suggest` tool evaluates all findings against 14 chain rules:

| Chain | Components | Impact |
|-------|------------|--------|
| SSRF + Cloud Metadata | SSRF → metadata service → IAM credentials | Full cloud account compromise |
| XSS + Weak Sessions | XSS → session theft → account takeover | User compromise |
| Open Redirect + OAuth | Redirect → redirect_uri bypass → token theft | OAuth token theft |
| SQLi + Credential Reuse | SQLi → credential dump → admin login | Full application compromise |
| File Upload + Traversal | Upload bypass → path traversal → web shell | Remote code execution |
| HTTP Smuggling + Cache | Desync → cache poisoning → mass XSS | All users compromised |
| Prototype Pollution + XSS | __proto__ pollution → gadget chain → stored XSS | Persistent XSS |
| Deserialization | Serialized object → gadget chain → RCE | Remote code execution |
| MFA Bypass + Auth | Skip 2FA → full authenticated access | Authentication bypass |
| Mass Assignment + Authz | Property injection → role escalation → admin | Privilege escalation |

### WAF-Aware Payload Generation

The `payload_generate` tool creates optimized payloads by combining:

1. **Base payloads** from the 17 payload files
2. **Tech-stack mutations** — MySQL-specific SQLi for MySQL targets, Jinja2-specific SSTI for Flask, etc.
3. **WAF bypass encodings** — double URL encoding, Unicode normalization, case mutation, comment injection based on detected WAF vendor

### Credential Security

Credentials are wrapped in `MaskedSecret` objects that display as `****` in logs, repr, and str. They are never included in findings or reports. The `CredentialStore` supports multiple named credential sets (e.g., "admin", "user", "guest") for testing authorization boundaries between roles.

### Finding Model

Each finding includes:

- Title, severity (critical/high/medium/low/info), and detailed description
- CVSS v3.1 vector string and calculated base score
- OWASP Top 10 2021 category mapping (A01–A10)
- Evidence with request/response pairs (method, URL, headers, body snippets)
- Remediation guidance
- CWE ID reference
- PCI-DSS and NIST 800-53 control mapping
- Automatic deduplication by (endpoint, parameter, category, title)

### HTTP Client Capabilities

The core HTTP client (`PencheffHTTPClient`) provides:

- **HTTP/1.1 and HTTP/2** — configurable per session
- **WebSocket support** — via the `websockets` library for WebSocket security testing
- **Raw socket connections** — via `asyncio.open_connection` for HTTP smuggling (sends malformed HTTP that httpx would refuse to construct)
- **Rate limiting** — configurable max requests per second
- **Credential injection** — automatic header injection (Bearer, Basic, API key, Cookie, custom headers)
- **SSL verification toggle** — disabled by default for testing self-signed certs
- **Connection pooling** — max 20 connections, 10 keepalive
- **Request audit logging** — every request logged with method, URL, status, module, and duration

## Test Depth

| Depth | Description |
|-------|-------------|
| `quick` | Fast scan — common vulnerabilities only, fewer payloads |
| `standard` | Balanced coverage and speed (default) |
| `deep` | Thorough testing — all payloads, extended port ranges, full crawl |

## Vulnerability Categories (27)

| Category | Module Count | Key Tests |
|----------|-------------|-----------|
| **SQL Injection** | 1 | Error-based, blind boolean, time-based, UNION, database-specific payloads |
| **NoSQL Injection** | 1 | MongoDB operator injection, JavaScript $where injection |
| **Command Injection** | 1 | Pipe, semicolon, backtick, $(), blind via timing |
| **SSTI** | 1 | Jinja2, Twig, Freemarker, ERB, Mako detection and exploitation |
| **XXE** | 1 | External entity, blind OOB, parameter entity, CDATA exfiltration |
| **SSRF** | 1 | Cloud metadata, internal scanning, IP encoding bypasses |
| **LDAP Injection** | 1 | Filter injection, authentication bypass, blind boolean |
| **Second-Order Injection** | 1 | Stored SQLi/XSS/SSTI via canary-based inject-then-trigger |
| **Open Redirect** | 1 | 25+ parameter names, 12 bypass techniques |
| **Header Injection** | 1 | CRLF injection, response splitting, host header poisoning |
| **XSS** | 1 | Reflected, stored, DOM-based, context-aware detection |
| **CSRF** | 1 | Token absence/weakness, SameSite bypass |
| **Clickjacking** | 1 | X-Frame-Options, CSP frame-ancestors |
| **Authentication** | 4 | Session management, JWT attacks, brute force, password policy |
| **OAuth/OIDC** | 1 | redirect_uri bypass, state validation, token leakage, scope escalation |
| **MFA Bypass** | 1 | Direct access, OTP brute force, backup codes, race conditions |
| **Authorization** | 3 | IDOR, privilege escalation, RBAC bypass |
| **Mass Assignment** | 1 | Privilege property injection, framework-specific payloads |
| **HTTP Smuggling** | 1 | CL.TE, TE.CL, TE.TE desync, CRLF request splitting |
| **Cache Poisoning** | 1 | Unkeyed header injection, cache deception, fat GET |
| **Deserialization** | 1 | Java, Python pickle, PHP, .NET ViewState, YAML |
| **Prototype Pollution** | 1 | Server-side JSON, client-side URL params, gadget detection |
| **WAF Detection** | 1 | 10 WAF vendor fingerprints, encoding bypass testing |
| **WebSocket** | 1 | CSWSH, auth bypass, message injection, transport security |
| **Subdomain Takeover** | 1 | Dangling CNAME for 20+ services |
| **DNS Rebinding** | 1 | Host header validation, IP binding assessment |
| **Infrastructure** | 5 | SSL/TLS, headers, CORS, HTTP methods, crawling |

## Dependencies

### Required (auto-installed)

- `mcp[cli]` — MCP protocol SDK
- `httpx` — Async HTTP client (HTTP/1.1 and HTTP/2)
- `pydantic` — Data validation
- `pyjwt` — JWT token analysis
- `cryptography` — SSL/TLS and crypto operations
- `jinja2` — Report template rendering
- `pyyaml` — YAML parsing
- `dnspython` — DNS enumeration
- `beautifulsoup4` + `lxml` — HTML parsing
- `anyio` — Async runtime

### Optional (enhanced scanning)

```bash
pip install pencheff[full]
```

- `python-nmap` — Advanced port scanning with service version detection
- `boto3` — AWS S3 bucket testing
- `paramiko` — SSH testing
- `websockets` — WebSocket security testing
- `h2` — HTTP/2 support for httpx

### System Tools

Pencheff checks for and uses these tools when available. Required Python packages are auto-installed. Optional Python packages and system tools enhance scanning capabilities — modules gracefully degrade when they are missing.

## External Security Tools (116)

All 116 tools below are allowlisted for execution via the `run_security_tool` MCP tool. Pencheff runs them with safe subprocess execution (no `shell=True`, array arguments only). Use `check_dependencies` to see which are installed on your system.

### Network Scanning (10)

| Tool | Description |
|------|-------------|
| `nmap` | Port scanning, service detection, NSE scripts, OS fingerprinting — the #1 network scanner |
| `ipscan` | Angry IP Scanner — fast IP address and port scanning with host info |
| `zenmap` | Nmap GUI — visual interpretation of scan results |
| `fping` | Fast ICMP ping to multiple hosts simultaneously |
| `unicornscan` | Asynchronous TCP/UDP scanner for large networks |
| `netcat` | Port scanning, file transfer, reverse shells, banner grabbing |
| `masscan` | Ultra-fast port scanning (100K+ ports/sec) — Internet-scale scanning |
| `naabu` | Fast port scanner (ProjectDiscovery) — SYN/CONNECT scanning |
| `nessus` | Tenable vulnerability scanner — comprehensive network security assessment |
| `hping3` | Packet crafting and analysis — firewall testing, idle scanning |

### Vulnerability Scanning (7)

| Tool | Description |
|------|-------------|
| `openvas` | Open Vulnerability Assessment Scanner — comprehensive security assessments |
| `gvm-cli` | Greenbone Vulnerability Management CLI — OpenVAS command-line interface |
| `nuclei` | Template-based vulnerability scanning (10K+ templates) — ProjectDiscovery |
| `nikto` | Web server scanner — 7000+ dangerous files, outdated software, misconfigs |
| `skipfish` | Web app security recon — generates interactive sitemap with security checks |
| `vega` | Web vulnerability scanner — SQLi, XSS, sensitive data exposure |

### Password Cracking (9)

| Tool | Description |
|------|-------------|
| `john` | John the Ripper — password cracker supporting 100s of hash types |
| `hashcat` | GPU-accelerated password recovery — 300+ hash types, world's fastest cracker |
| `rcrack` | RainbowCrack — hash cracker using precomputed rainbow tables |
| `aircrack-ng` | WiFi security suite — WEP/WPA/WPA2 cracking, packet capture |
| `hydra` | Network login brute-forcer — 50+ protocols (HTTP, SSH, FTP, MySQL, etc.) |
| `medusa` | Parallel network login brute-forcer — fast credential testing |
| `l0phtcrack` | Password auditing — dictionary, brute-force, rainbow table attacks |
| `cowpatty` | WPA2-PSK brute-force cracking — weak passphrase detection |
| `ophcrack` | Windows password cracker using rainbow tables |

### Exploitation (10)

| Tool | Description |
|------|-------------|
| `msfconsole` | Metasploit Framework — exploit development, post-exploitation, pivoting |
| `msfvenom` | Metasploit payload generator — shellcode, executables, scripts |
| `msfdb` | Metasploit database management |
| `setoolkit` | Social-Engineer Toolkit — phishing, credential harvesting |
| `beef-xss` | Browser Exploitation Framework — XSS attacks targeting browser sessions |
| `sqlmap` | SQL injection — automatic exploitation, data extraction, OS shell access |
| `armitage` | Graphical Metasploit frontend — target visualization, exploit recommendations |
| `zap-cli` | OWASP ZAP CLI — automated web security scanning and testing |
| `zaproxy` | OWASP Zed Attack Proxy — web app security scanner |
| `commix` | Command injection exploiter — automated OS command injection |

### Packet Sniffing & Spoofing (9)

| Tool | Description |
|------|-------------|
| `tshark` | Wireshark CLI — deep packet inspection of 100s of protocols |
| `tcpdump` | Command-line packet analyzer — capture and filter network traffic |
| `ettercap` | Man-in-the-middle attack suite — ARP spoofing, DNS spoofing, sniffing |
| `bettercap` | Network attack Swiss Army knife — WiFi, BLE, Ethernet MitM attacks |
| `snort` | Intrusion detection/prevention system — rule-based packet analysis |
| `ngrep` | Network grep — pattern-matching packet analyzer across protocols |
| `nemesis` | Packet crafting and injection — custom protocol packets |
| `scapy` | Interactive packet manipulation — craft, send, sniff, dissect packets |
| `dsniff` | Password sniffer — network auditing and penetration testing |

### Wireless Hacking (7)

| Tool | Description |
|------|-------------|
| `wifite` | Automated wireless auditing — WEP/WPA/WPS attacks |
| `kismet` | Wireless detector, sniffer, IDS — WiFi, Bluetooth, Zigbee, RF |
| `reaver` | WPS brute-force attack — recover WPA/WPA2 passphrases |
| `bully` | WPS brute-force (C-based) — improved performance over Reaver |
| `wifiphisher` | Rogue AP framework — WiFi phishing, credential capture |
| `hostapd-wpe` | Rogue RADIUS server for WPA2-Enterprise attacks |
| `mdk4` | WiFi testing — beacon flooding, deauth, WDS confusion |

### Directory / Path Brute Force (6)

| Tool | Description |
|------|-------------|
| `ffuf` | Fast web fuzzer — directory brute force, parameter fuzzing, vhost discovery |
| `gobuster` | Directory/DNS/vhost brute-force scanner — fast, Go-based |
| `dirb` | Web content scanner — recursive directory brute force |
| `wfuzz` | Web fuzzer — headers, POST data, URLs, authentication testing |
| `feroxbuster` | Recursive content discovery — fast, smart wordlists, auto-filtering |
| `dirsearch` | Web path brute-forcer with recursive scanning and extension support |

### Web Application Hacking (5)

| Tool | Description |
|------|-------------|
| `whatweb` | Web technology fingerprinting — CMS, frameworks, servers, plugins |
| `wafw00f` | WAF fingerprinting and detection — identifies 100+ WAF products |
| `wpscan` | WordPress vulnerability scanner — plugins, themes, users, passwords |
| `dalfox` | XSS scanner with DOM analysis — parameter mining and payload optimization |
| `xsstrike` | Advanced XSS detection — fuzzing, crawling, context analysis |

### Subdomain Enumeration (7)

| Tool | Description |
|------|-------------|
| `subfinder` | Passive subdomain discovery (ProjectDiscovery) — 30+ sources |
| `amass` | OWASP attack surface mapping — active/passive subdomain enumeration |
| `fierce` | DNS reconnaissance — subdomain brute-forcing and zone discovery |
| `dnsrecon` | DNS enumeration — zone transfers, brute force, cache snooping |
| `sublist3r` | Subdomain enumeration using search engines and public sources |
| `knockpy` | Subdomain scanner with DNS resolution and takeover detection |
| `dnsenum` | DNS enumeration — subdomains, MX, NS, zone transfer attempts |

### DNS Tools (3)

| Tool | Description |
|------|-------------|
| `dig` | DNS lookups — query DNS records with full control |
| `whois` | Domain registration info — registrar, nameservers, dates |
| `host` | Simple DNS lookup utility — forward and reverse lookups |

### SSL/TLS Testing (4)

| Tool | Description |
|------|-------------|
| `sslscan` | SSL/TLS scanner — cipher suites, protocols, certificate analysis |
| `testssl` | Comprehensive SSL/TLS testing (testssl.sh) — BEAST, POODLE, Heartbleed |
| `sslyze` | Fast SSL/TLS scanner — certificate validation, protocol support |
| `openssl` | SSL/TLS cryptography toolkit — certificate management, testing |

### OSINT / Social Engineering (9)

| Tool | Description |
|------|-------------|
| `theHarvester` | OSINT — emails, subdomains, IPs from public sources |
| `maltego` | OSINT and link analysis — data correlation across 100s of sources |
| `recon-ng` | Web reconnaissance framework — modular OSINT collection |
| `sherlock` | Username enumeration across 400+ social networks |
| `spiderfoot` | Automated OSINT collection — 200+ data sources |
| `gophish` | Phishing campaign toolkit — email phishing simulation |
| `king-phisher` | Phishing simulation — credential harvesting, website cloning |
| `evilginx2` | MitM framework — session cookie theft, 2FA bypass via reverse proxy |
| `social-engineer-toolkit` | SET alias — social engineering attack framework |

### Digital Forensics (8)

| Tool | Description |
|------|-------------|
| `autopsy` | Digital forensics platform — disk image analysis |
| `foremost` | File recovery/carving for forensic analysis |
| `scalpel` | Fast file carver — improved version of Foremost |
| `fls` | The Sleuth Kit — list files and directories in disk images |
| `mmls` | The Sleuth Kit — display partition layout of volume systems |
| `icat` | The Sleuth Kit — extract file content from disk images |
| `volatility` | Memory forensics framework — RAM analysis, process dumping |
| `binwalk` | Firmware analysis — extract embedded files and code |

### Post-Exploitation / Credentials (10)

| Tool | Description |
|------|-------------|
| `mimikatz` | Windows credential extraction — pass-the-hash, pass-the-ticket |
| `crackmapexec` | Post-exploitation — SMB, LDAP, WinRM, MSSQL credential testing |
| `impacket-secretsdump` | Impacket — dump NTLM hashes, Kerberos tickets from DC |
| `impacket-psexec` | Impacket — remote command execution via SMB |
| `impacket-smbexec` | Impacket — SMB-based remote execution |
| `impacket-wmiexec` | Impacket — WMI-based remote execution |
| `responder` | LLMNR/NBT-NS/MDNS poisoner — credential capture on LAN |
| `enum4linux` | SMB/Windows enumeration — shares, users, groups, policies |
| `smbclient` | SMB client — connect to file shares, list/download files |
| `pcredz` | Credential extraction from PCAP files — 20+ protocols |

### Web Proxy / API Testing (3)

| Tool | Description |
|------|-------------|
| `curl` | HTTP requests — full protocol control, auth, proxies |
| `wget` | HTTP downloader — recursive website mirroring |
| `httpx-toolkit` | HTTP probing (ProjectDiscovery) — tech detection, status codes |

### Static Analysis / Secret Scanning (4)

| Tool | Description |
|------|-------------|
| `semgrep` | Static analysis — 5000+ rules across 30+ languages |
| `bandit` | Python security analysis — find common security issues |
| `trufflehog` | Secret scanning — git repos, S3 buckets, filesystem |
| `git-dumper` | Extract git repositories from misconfigured web servers |

### Miscellaneous (4)

| Tool | Description |
|------|-------------|
| `interactsh-client` | Out-of-band callback detection (ProjectDiscovery) |
| `gau` | URL discovery from web archives — AlienVault, Wayback, CommonCrawl |
| `waybackurls` | Fetch URLs from Wayback Machine |
| `xsser` | Cross-site scripting framework — automated XSS exploitation |

## Compliance Frameworks

Pencheff maps every finding to industry compliance controls across 27 vulnerability categories:

- **OWASP Top 10 2021** — A01 through A10 with coverage tracking
- **PCI-DSS 4.0** — Requirements 2.2, 4.1, 6.2, 6.5.x, 6.6, 7.x, 8.x
- **NIST 800-53** — AC, AU, CM, IA, SC, SI control families

Reports include a compliance summary showing tested vs. untested categories.

## Recommended Test Targets

For testing Pencheff, use intentionally vulnerable applications:

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — `docker run -p 3000:3000 bkimminich/juice-shop`
- [DVWA](https://github.com/digininja/DVWA) — `docker run -p 80:80 vulnerables/web-dvwa`
- [WebGoat](https://owasp.org/www-project-webgoat/) — `docker run -p 8080:8080 webgoat/webgoat`

**Never run penetration tests against systems you do not own or have explicit written authorization to test.**

## License

MIT

## Author

**Bala Sriharsha** — [github.com/balasriharsha](https://github.com/balasriharsha)
