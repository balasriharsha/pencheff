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
}

SYSTEM_TOOLS = {
    "dig": "DNS lookups",
    "whois": "Domain registration info",
    "openssl": "SSL/TLS testing",
    "curl": "HTTP requests",
    "nmap": "Port scanning (enhanced)",
    "semgrep": "Static analysis",
    "bandit": "Python security analysis",
    "nuclei": "Template-based vulnerability scanning",
    "sqlmap": "SQL injection testing",
    "ffuf": "Web fuzzing",
    "nikto": "Web server scanning",
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

    return {
        "python_required": python_required,
        "python_optional": python_optional,
        "system_tools": system,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "missing_system": missing_system,
        "ready": len(missing_required) == 0,
    }
