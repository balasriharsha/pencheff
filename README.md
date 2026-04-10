# Pencheff

AI-powered penetration testing agent for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Provide a target URL and credentials in natural language — Pencheff handles reconnaissance, vulnerability scanning, exploit chain analysis, and compliance-mapped reporting, all driven by Claude's reasoning.

Unlike static scanners, Pencheff uses Claude as its brain. Each testing module returns structured findings and `next_steps` recommendations, enabling Claude to adaptively decide what to test next, chain discovered vulnerabilities together, and prioritize like a human pentester.

## Features

- **29 MCP tools** covering the full pentest lifecycle — from reconnaissance to exploit chain analysis
- **50 attack modules** across 11 categories implementing real detection logic
- **326 payloads** across 17 payload files for injection, bypass, and exploitation testing
- **Adaptive testing** — Claude reasons about discovered tech stack, WAF detection, and vulnerabilities to guide testing strategy
- **OWASP Top 10 2021** coverage with CVSS v3.1 scoring
- **Compliance mapping** — PCI-DSS 4.0, NIST 800-53 for 27 vulnerability categories
- **Multi-credential support** — test authorization boundaries between user roles
- **Exploit chain analysis** — automatically identifies multi-step attack paths across findings
- **WAF-aware payloads** — detects WAF vendor and generates bypass-optimized payloads
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

## MCP Tools (29)

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

### Manual / Targeted Testing (3)

| Tool | Description |
|------|-------------|
| `test_endpoint` | Custom HTTP request with specific payloads against a single endpoint. Supports payload substitution via `PENCHEFF` marker |
| `test_chain` | Multi-step attack sequence with variable extraction (JSONPath) and substitution between steps — for verifying exploit chains |
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
    ├── server.py                  # FastMCP server — 29 tools, 1 prompt
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
    │   └── dependency_manager.py  # Python/system tool availability checks
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

### Testing Methodology (10 Phases)

The built-in `pentest_methodology` prompt guides Claude through a comprehensive 10-phase assessment:

1. **Preparation** — Initialize session with `pentest_init`, verify tools with `check_dependencies`
2. **Reconnaissance** — Map the full attack surface: DNS, subdomains, ports, tech stack, APIs
3. **Infrastructure** — SSL/TLS, security headers, CORS, HTTP methods
4. **Authentication** — Session management, JWT vulnerabilities, brute force resistance
5. **WAF Detection** — Fingerprint WAF and test bypass techniques before injection testing
6. **Injection Warfare** — 10 injection types across all discovered endpoints
7. **Advanced Attacks** — HTTP smuggling, cache poisoning, deserialization, prototype pollution
8. **API, Business Logic & Specialized** — GraphQL, mass assignment, race conditions, cloud, file handling, OAuth, MFA bypass, WebSocket, subdomain takeover
9. **Exploit Chain Analysis** — Automatic chain detection + manual verification with `test_chain`
10. **Reporting** — CVSS-scored findings with OWASP/PCI-DSS/NIST compliance mapping

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

### System Tools (used if available)

Pencheff checks for and uses these tools when available. Modules gracefully degrade when they are missing.

| Tool | Purpose |
|------|---------|
| `dig` | DNS lookups |
| `whois` | Domain registration info |
| `openssl` | SSL/TLS testing |
| `curl` | HTTP requests |
| `nmap` | Enhanced port scanning |
| `semgrep` | Static analysis |
| `bandit` | Python security analysis |
| `nuclei` | Template-based vulnerability scanning |
| `sqlmap` | SQL injection testing |
| `ffuf` | Web fuzzing |
| `nikto` | Web server scanning |
| `subfinder` | Subdomain enumeration (ProjectDiscovery) |
| `interactsh-client` | Out-of-band callback detection |
| `httpx-toolkit` | HTTP probing (ProjectDiscovery) |
| `dalfox` | XSS scanner |
| `gau` | URL discovery from web archives |

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
