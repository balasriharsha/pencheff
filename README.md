# Pencheff

AI-powered penetration testing agent for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Provide a target URL and credentials in natural language — Pencheff handles reconnaissance, vulnerability scanning, attack chaining, and compliance-mapped reporting, all driven by Claude's reasoning.

Unlike static scanners, Pencheff uses Claude as its brain. Each testing module returns structured findings and `next_steps` recommendations, enabling Claude to adaptively decide what to test next, chain discovered vulnerabilities together, and prioritize like a human pentester.

## Features

- **21 MCP tools** covering the full pentest lifecycle
- **Adaptive testing** — Claude reasons about discovered tech stack and vulnerabilities to guide testing
- **OWASP Top 10 2021** coverage with CVSS v3.1 scoring
- **Compliance mapping** — PCI-DSS 4.0, NIST 800-53
- **Multi-credential support** — test authorization boundaries between user roles
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

# Register with Claude Code (add to your project's .mcp.json or settings)
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

## MCP Tools

### Session Management

| Tool | Description |
|------|-------------|
| `pentest_init` | Initialize session with target URL, credentials, scope, and depth (quick/standard/deep) |
| `pentest_status` | Get progress — completed modules, finding counts, next steps |
| `pentest_configure` | Update credentials, scope, or depth mid-session |

### Reconnaissance

| Tool | Description |
|------|-------------|
| `recon_passive` | DNS enumeration, WHOIS, certificate transparency, subdomain discovery, SPF/DMARC |
| `recon_active` | TCP port scanning, web crawling, service fingerprinting, tech stack detection |
| `recon_api_discovery` | OpenAPI/Swagger spec detection, GraphQL introspection, endpoint enumeration |

### Vulnerability Scanning

| Tool | Description |
|------|-------------|
| `scan_injection` | SQL injection (error/blind/time-based), NoSQL injection, command injection, SSTI, XXE, SSRF |
| `scan_auth` | Session management, JWT attacks (none algo, claim tampering), brute force, password policy |
| `scan_authz` | IDOR, privilege escalation, RBAC bypass (uses multiple credential sets) |
| `scan_client_side` | XSS (reflected/stored/DOM), CSRF, clickjacking |
| `scan_infrastructure` | SSL/TLS configuration, security headers, CORS misconfigurations, HTTP methods |
| `scan_api` | REST fuzzing, GraphQL depth/batch attacks, mass assignment, API spec analysis |

### Specialized

| Tool | Description |
|------|-------------|
| `scan_cloud` | S3 bucket enumeration, cloud metadata service (AWS/GCP/Azure), IAM analysis |
| `scan_file_handling` | File upload bypass (9 payloads), path traversal (7 techniques with encoding) |
| `scan_business_logic` | Rate limiting, race conditions (concurrent requests), workflow bypass |

### Manual / Targeted

| Tool | Description |
|------|-------------|
| `test_endpoint` | Custom HTTP request with specific payloads against a single endpoint |
| `test_chain` | Multi-step attack sequence — authenticate, exploit, verify |
| `analyze_response` | Analyze an HTTP response for security issues |

### Reporting

| Tool | Description |
|------|-------------|
| `get_findings` | Retrieve findings filtered by severity, category, or OWASP category |
| `generate_report` | Full report — executive summary, technical details, compliance mapping (Markdown/JSON) |
| `check_dependencies` | Verify available tools and Python packages |

## Architecture

```
plugins/pencheff/
├── .claude-plugin/plugin.json     # Plugin metadata
├── .mcp.json                      # MCP server launch config
├── agents/pencheff.md             # Agent definition
├── skills/pentest/SKILL.md        # /pencheff:pentest skill
├── pyproject.toml                 # Python package (hatch build)
└── pencheff/
    ├── __main__.py                # Entry: python -m pencheff
    ├── server.py                  # FastMCP server, 21 tool registrations
    ├── config.py                  # Constants, OWASP/PCI-DSS/NIST mappings
    ├── core/
    │   ├── session.py             # PentestSession state management
    │   ├── credentials.py         # MaskedSecret, CredentialSet, CredentialStore
    │   ├── findings.py            # Finding model, CVSS scoring, deduplication
    │   ├── http_client.py         # httpx wrapper with auth injection, rate limiting
    │   ├── tool_runner.py         # Safe subprocess execution (no shell=True)
    │   └── dependency_manager.py  # Python/system tool availability checks
    ├── modules/
    │   ├── base.py                # BaseTestModule ABC
    │   ├── recon/                  # DNS, subdomains, tech fingerprint, port scan
    │   ├── web/                   # Crawler, SSL/TLS, headers, CORS, HTTP methods
    │   ├── injection/             # SQLi, NoSQLi, CMDi, SSTI, XXE, SSRF
    │   ├── auth/                  # Session mgmt, JWT, brute force, password policy
    │   ├── authz/                 # IDOR, privilege escalation, RBAC bypass
    │   ├── client_side/           # XSS, CSRF, clickjacking
    │   ├── api/                   # REST discovery, GraphQL, API fuzzer
    │   ├── logic/                 # Rate limiting, race conditions, workflow bypass
    │   ├── cloud/                 # S3 enum, metadata service
    │   └── file_handling/         # Upload bypass, path traversal
    ├── reporting/
    │   ├── cvss.py                # CVSS v3.1 base score calculator
    │   ├── compliance.py          # OWASP/PCI-DSS/NIST coverage analysis
    │   └── renderer.py            # Markdown and JSON report rendering
    └── payloads/                  # sqli.txt, xss.txt, ssti.txt, path_traversal.txt
```

## How It Works

### Adaptive Intelligence

Every tool returns a structured response:

```json
{
  "findings": [...],
  "stats": { "requests_made": 47, "endpoints_tested": 12 },
  "next_steps": [
    "MySQL detected — run scan_injection with time-based blind SQLi techniques",
    "JWT tokens found — run scan_auth to test for none algorithm and weak signing"
  ]
}
```

Claude reads these `next_steps` and decides what to test next. This feedback loop means Pencheff adapts to each target instead of running the same static checks every time.

### Testing Methodology

1. **Reconnaissance** — Map the attack surface: DNS, subdomains, ports, tech stack, endpoints
2. **Infrastructure** — Check SSL/TLS, security headers, CORS, allowed HTTP methods
3. **Authentication** — Test session management, JWT vulnerabilities, brute force resistance
4. **Authorization** — IDOR, privilege escalation, RBAC bypass across user roles
5. **Injection** — SQLi, XSS, SSRF, SSTI, XXE, command injection with WAF bypass
6. **API Security** — REST/GraphQL fuzzing, mass assignment, introspection leaks
7. **Business Logic** — Rate limiting, race conditions, workflow bypass
8. **Cloud & Files** — S3 misconfigs, metadata service exposure, upload bypass
9. **Report** — CVSS-scored findings with OWASP/PCI-DSS/NIST compliance mapping

### Credential Security

Credentials are wrapped in `MaskedSecret` objects that display as `****` in logs, repr, and str. They are never included in findings or reports. The `CredentialStore` supports multiple named credential sets for testing authorization boundaries between roles.

### Finding Model

Each finding includes:
- Title, severity, and detailed description
- CVSS v3.1 vector string and calculated base score
- OWASP Top 10 2021 category mapping
- Evidence with request/response pairs
- Remediation guidance
- CWE/CVE references
- PCI-DSS and NIST 800-53 control mapping
- Automatic deduplication by (endpoint, parameter, category, title)

## Test Depth

| Depth | Description |
|-------|-------------|
| `quick` | Fast scan — common vulnerabilities only, fewer payloads |
| `standard` | Balanced coverage and speed (default) |
| `deep` | Thorough testing — all payloads, extended port ranges, full crawl |

## Supported Vulnerability Categories

| Category | Tests |
|----------|-------|
| **Injection** | SQL injection (error, blind, time, union), NoSQL injection, OS command injection, SSTI (Jinja2, Twig, Freemarker, ERB, Razor, Thymeleaf), XXE, SSRF |
| **Authentication** | Session fixation, session entropy, JWT none/alg attacks, brute force, password policy, username enumeration |
| **Authorization** | IDOR (numeric ID, UUID), privilege escalation (admin paths, method override), RBAC bypass (role injection, path normalization) |
| **Client-Side** | Reflected/stored/DOM XSS (11 payloads), CSRF token validation, clickjacking (X-Frame-Options, CSP) |
| **Infrastructure** | SSL/TLS protocol/cipher/cert analysis, 7 security headers, CORS (wildcard, reflected, null origin), HTTP method enumeration |
| **API** | OpenAPI/Swagger detection (15 paths), GraphQL introspection/depth/batch, REST parameter fuzzing (14 fuzz values), mass assignment |
| **Business Logic** | Rate limiting (30-request burst), race conditions (10 concurrent), workflow step skipping, price/quantity tampering |
| **Cloud** | S3 bucket enumeration, AWS/GCP/Azure metadata service, IAM misconfigurations |
| **File Handling** | Upload bypass (9 file types, double ext, null byte), path traversal (7 techniques, encoding bypass) |

## Dependencies

### Required (auto-installed)

- `mcp[cli]` — MCP protocol SDK
- `httpx` — Async HTTP client
- `pydantic` — Data validation
- `pyjwt` — JWT token analysis
- `cryptography` — SSL/TLS and crypto operations
- `jinja2` — Report template rendering
- `dnspython` — DNS enumeration
- `beautifulsoup4` + `lxml` — HTML parsing
- `anyio` — Async runtime

### Optional (enhanced scanning)

```bash
pip install pencheff[full]
```

- `python-nmap` — Advanced port scanning
- `boto3` — AWS S3 bucket testing
- `paramiko` — SSH testing

### System Tools (used if available)

`dig`, `whois`, `openssl`, `curl` — modules gracefully degrade when these are missing.

## Compliance Frameworks

Pencheff maps every finding to industry compliance controls:

- **OWASP Top 10 2021** — A01 through A10 with coverage tracking
- **PCI-DSS 4.0** — Requirements 2.2, 4.1, 6.2, 6.5.x, 7.x, 8.x
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
