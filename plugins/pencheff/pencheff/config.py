"""Global configuration, constants, and mappings."""

from enum import Enum

# CVSS v3.1 severity thresholds
CVSS_SEVERITY = {
    "NONE": (0.0, 0.0),
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"


class TestDepth(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


# OWASP Top 10 2021 mapping
OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# PCI-DSS requirement mapping for common vulnerability categories
PCI_DSS_MAP = {
    "injection": ["6.5.1"],
    "xss": ["6.5.7"],
    "auth": ["6.5.10", "8.1", "8.2"],
    "authz": ["6.5.8", "7.1", "7.2"],
    "crypto": ["4.1", "6.5.3"],
    "misconfiguration": ["2.2", "6.2"],
    "ssrf": ["6.5.1"],
    "file_handling": ["6.5.1", "6.5.8"],
    "deserialization": ["6.5.1"],
    "smuggling": ["6.5.10"],
    "cache_poisoning": ["6.5.10"],
    "mfa_bypass": ["8.3"],
    "oauth": ["6.5.10"],
    "subdomain_takeover": ["6.5.8"],
    "waf_bypass": ["6.6"],
    "prototype_pollution": ["6.5.1"],
    "ldap": ["6.5.1"],
    "open_redirect": ["6.5.10"],
    "header_injection": ["6.5.1"],
    "websocket": ["6.5.10"],
    "mass_assignment": ["6.5.1", "6.5.8"],
}

# NIST 800-53 mapping
NIST_MAP = {
    "injection": ["SI-10", "SI-16"],
    "xss": ["SI-10"],
    "auth": ["IA-2", "IA-5", "IA-8"],
    "authz": ["AC-3", "AC-6"],
    "crypto": ["SC-8", "SC-12", "SC-13"],
    "misconfiguration": ["CM-6", "CM-7"],
    "ssrf": ["SI-10", "SC-7"],
    "logging": ["AU-2", "AU-3", "AU-6"],
    "deserialization": ["SI-10", "SI-16"],
    "smuggling": ["SC-7", "SI-10"],
    "cache_poisoning": ["SC-7"],
    "mfa_bypass": ["IA-2", "IA-11"],
    "oauth": ["IA-2", "IA-8"],
    "subdomain_takeover": ["CM-8", "SC-20"],
    "waf_bypass": ["SC-7", "SI-4"],
    "prototype_pollution": ["SI-10"],
    "ldap": ["SI-10", "AC-3"],
    "open_redirect": ["SI-10"],
    "header_injection": ["SI-10", "SC-7"],
    "websocket": ["SC-8", "SC-23"],
    "mass_assignment": ["AC-3", "AC-6"],
}

# Default timeouts
DEFAULT_REQUEST_TIMEOUT = 30.0
DEFAULT_SCAN_TIMEOUT = 300.0
MAX_REQUESTS_PER_SECOND = 10
MAX_CRAWL_DEPTH = 5
MAX_RESPONSE_SIZE = 1024 * 1024 * 5  # 5MB

# Common ports
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 27017,
]

TOP_1000_PORTS = list(range(1, 1001)) + [
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 3306, 3389,
    5432, 5900, 5985, 5986, 6379, 8080, 8443, 8888, 9090, 9200,
    9300, 11211, 27017, 27018, 50000,
]
