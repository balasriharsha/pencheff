"""Check and optionally install missing dependencies."""

from __future__ import annotations

import importlib
from typing import Any

from pencheff.core.tool_runner import tool_available

REQUIRED_PYTHON = {
    "httpx": "httpx",
    "pydantic": "pydantic",
    "pyjwt": "jwt",
    "cryptography": "cryptography",
    "jinja2": "jinja2",
    "dnspython": "dns.resolver",
    "beautifulsoup4": "bs4",
    "lxml": "lxml",
}

OPTIONAL_PYTHON = {
    "python-nmap": "nmap",
    "boto3": "boto3",
    "paramiko": "paramiko",
    "websockets": "websockets",
    "h2": "h2",
}

SYSTEM_TOOLS = {
    # Core utilities
    "dig": "DNS lookups",
    "whois": "Domain registration info",
    "openssl": "SSL/TLS testing",
    "curl": "HTTP requests",
    # Network scanning
    "nmap": "Port scanning, service detection, NSE scripts, OS fingerprinting",
    "masscan": "Ultra-fast port scanning (100K+ ports/sec)",
    "naabu": "Fast port scanner (ProjectDiscovery)",
    "unicornscan": "Asynchronous TCP/UDP scanner",
    "netcat": "Network utility — port scanning, file transfer, reverse shells",
    "hping3": "Packet crafting and analysis — firewall testing, idle scanning",
    # Vulnerability scanning
    "nuclei": "Template-based vulnerability scanning (10K+ templates)",
    "nikto": "Web server scanner — 7000+ dangerous files, outdated software",
    # SQL injection
    "sqlmap": "SQL injection — automatic exploitation, data extraction, OS shell",
    # XSS scanning
    "dalfox": "XSS scanner with DOM analysis",
    "xsstrike": "Advanced XSS detection and exploitation",
    # Directory/path brute force
    "ffuf": "Fast web fuzzer — directory brute force, parameter fuzzing, vhost discovery",
    "gobuster": "Directory/DNS/vhost brute-force scanner",
    "dirb": "Web content scanner — recursive directory brute force",
    "wfuzz": "Web fuzzer — headers, POST data, URLs, authentication",
    "feroxbuster": "Recursive content discovery — fast, smart wordlists",
    "dirsearch": "Web path brute-forcer with recursive scanning",
    # Subdomain enumeration
    "subfinder": "Subdomain discovery (ProjectDiscovery)",
    "amass": "Attack surface mapping — subdomain enumeration (OWASP)",
    "fierce": "DNS reconnaissance and subdomain brute-forcing",
    "dnsrecon": "DNS enumeration — zone transfers, brute force, cache snooping",
    "sublist3r": "Subdomain enumeration using search engines",
    "knockpy": "Subdomain scanner with DNS resolution",
    # SSL/TLS testing
    "sslscan": "SSL/TLS scanner — cipher suites, protocols, certificate info",
    "testssl": "Comprehensive SSL/TLS testing (testssl.sh)",
    "sslyze": "Fast SSL/TLS scanner — Python-based",
    # WAF detection
    "wafw00f": "WAF fingerprinting and detection",
    "whatweb": "Web technology fingerprinting — CMS, frameworks, servers",
    # Password cracking
    "hydra": "Network login brute-forcer — 50+ protocols (HTTP, SSH, FTP, etc.)",
    "john": "Password cracker — dictionary, brute force, rainbow tables",
    "hashcat": "GPU-accelerated password recovery — 300+ hash types",
    "medusa": "Parallel network login brute-forcer",
    # Exploitation
    "msfconsole": "Metasploit Framework — exploit development and execution",
    "msfvenom": "Metasploit payload generator",
    # OSINT
    "theHarvester": "OSINT — emails, subdomains, IPs from public sources",
    "recon-ng": "Web reconnaissance framework",
    "sherlock": "Username enumeration across social networks",
    "spiderfoot": "Automated OSINT collection",
    # Packet analysis
    "tcpdump": "Network packet capture and analysis",
    "tshark": "Wireshark CLI — deep packet inspection",
    # WordPress
    "wpscan": "WordPress vulnerability scanner",
    # Web proxy / API
    "httpx-toolkit": "HTTP probing (ProjectDiscovery)",
    # SMB/Windows
    "enum4linux": "SMB/Windows enumeration",
    "smbclient": "SMB client for file share access",
    "crackmapexec": "Post-exploitation — SMB, LDAP, WinRM, MSSQL",
    # Wireless
    "aircrack-ng": "WiFi security — WEP/WPA/WPA2 cracking",
    "wifite": "Automated wireless auditing",
    "reaver": "WPS brute-force attack",
    # Static analysis
    "semgrep": "Static analysis — 5000+ rules",
    "bandit": "Python security analysis",
    # Misc
    "interactsh-client": "Out-of-band callback detection (ProjectDiscovery)",
    "gau": "URL discovery from web archives",
    "waybackurls": "Fetch URLs from Wayback Machine",
    "responder": "LLMNR/NBT-NS/MDNS poisoner",
}


def check_python_package(import_name: str) -> bool:
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def check_all_dependencies() -> dict[str, Any]:
    """Check all dependencies and return a status report."""
    python_required = {}
    for pkg, imp in REQUIRED_PYTHON.items():
        python_required[pkg] = {
            "available": check_python_package(imp),
            "required": True,
        }

    python_optional = {}
    for pkg, imp in OPTIONAL_PYTHON.items():
        python_optional[pkg] = {
            "available": check_python_package(imp),
            "required": False,
        }

    system = {}
    for tool, desc in SYSTEM_TOOLS.items():
        system[tool] = {
            "available": tool_available(tool),
            "description": desc,
        }

    missing_required = [p for p, s in python_required.items() if not s["available"]]
    missing_optional = [p for p, s in python_optional.items() if not s["available"]]
    missing_system = [t for t, s in system.items() if not s["available"]]

    # Build capability summary based on available tools
    available_system = [t for t, s in system.items() if s["available"]]
    capabilities = []
    cap_map = {
        "nmap": "Advanced port scanning with NSE scripts",
        "sqlmap": "Automated SQL injection exploitation with data extraction",
        "nikto": "Web server vulnerability scanning (7000+ checks)",
        "hydra": "Network brute-force attacks (50+ protocols)",
        "nuclei": "Template-based vulnerability scanning (10K+ templates)",
        "ffuf": "Directory/parameter fuzzing",
        "gobuster": "Directory brute-force scanning",
        "subfinder": "Passive subdomain enumeration",
        "amass": "Attack surface mapping",
        "sslscan": "SSL/TLS configuration testing",
        "wafw00f": "WAF detection and fingerprinting",
        "whatweb": "Technology fingerprinting",
        "dalfox": "Advanced XSS detection",
        "masscan": "Ultra-fast port scanning",
        "john": "Password hash cracking",
        "hashcat": "GPU-accelerated password cracking",
        "msfconsole": "Metasploit exploitation framework",
        "wpscan": "WordPress vulnerability scanning",
        "testssl": "Comprehensive SSL/TLS testing",
        "feroxbuster": "Recursive content discovery",
    }
    for tool_name in available_system:
        if tool_name in cap_map:
            capabilities.append(f"✓ {cap_map[tool_name]} (via {tool_name})")

    return {
        "python_required": python_required,
        "python_optional": python_optional,
        "system_tools": system,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "missing_system": missing_system,
        "available_system_tools": available_system,
        "capabilities": capabilities,
        "ready": len(missing_required) == 0,
        "next_steps": [
            "Use run_security_tool to execute any available external tool for deeper testing.",
            f"{len(available_system)} external tools available, {len(missing_system)} not installed.",
            "PRIORITIZE: nmap (scanning), sqlmap (SQLi), nikto (web), hydra (brute force), nuclei (vuln scanning).",
        ],
    }
