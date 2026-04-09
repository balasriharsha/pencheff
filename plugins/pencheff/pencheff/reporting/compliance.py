"""Compliance framework mapping for findings."""

from __future__ import annotations

from pencheff.config import NIST_MAP, OWASP_TOP_10, PCI_DSS_MAP


def get_owasp_coverage(findings_categories: list[str]) -> dict[str, bool]:
    """Check which OWASP Top 10 categories are covered by findings."""
    category_to_owasp = {
        "injection": "A03",
        "xss": "A03",
        "auth": "A07",
        "authz": "A01",
        "crypto": "A02",
        "misconfiguration": "A05",
        "ssrf": "A10",
        "file_handling": "A01",
        "cloud": "A05",
        "logic": "A04",
    }

    covered = set()
    for cat in findings_categories:
        owasp = category_to_owasp.get(cat)
        if owasp:
            covered.add(owasp)

    return {
        f"{code}: {name}": code in covered
        for code, name in OWASP_TOP_10.items()
    }


def get_compliance_summary(findings: list) -> dict[str, dict]:
    """Generate compliance summary across frameworks."""
    pci_findings = {}
    nist_findings = {}
    owasp_findings = {}

    for f in findings:
        # OWASP
        owasp_key = f"{f.owasp_category}: {f.owasp_name}"
        if owasp_key not in owasp_findings:
            owasp_findings[owasp_key] = []
        owasp_findings[owasp_key].append(f.title)

        # PCI-DSS
        pci_reqs = PCI_DSS_MAP.get(f.category, [])
        for req in pci_reqs:
            if req not in pci_findings:
                pci_findings[req] = []
            pci_findings[req].append(f.title)

        # NIST
        nist_controls = NIST_MAP.get(f.category, [])
        for ctrl in nist_controls:
            if ctrl not in nist_findings:
                nist_findings[ctrl] = []
            nist_findings[ctrl].append(f.title)

    return {
        "OWASP Top 10": owasp_findings,
        "PCI-DSS": pci_findings,
        "NIST 800-53": nist_findings,
    }
