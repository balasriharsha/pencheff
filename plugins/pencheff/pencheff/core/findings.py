"""Finding data model, CVSS scoring, and deduplication."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pencheff.config import CVSS_SEVERITY, NIST_MAP, OWASP_TOP_10, PCI_DSS_MAP, Severity


@dataclass
class Evidence:
    """Proof of a vulnerability — request/response pair."""

    request_method: str
    request_url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body_snippet: str | None = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "request": f"{self.request_method} {self.request_url}",
            "response_status": self.response_status,
            "description": self.description,
        }
        if self.request_body:
            d["request_body"] = self.request_body[:500]
        if self.response_body_snippet:
            d["response_snippet"] = self.response_body_snippet[:500]
        return d


@dataclass
class Finding:
    """A single vulnerability finding."""

    title: str
    severity: Severity
    category: str
    owasp_category: str  # e.g. "A03"
    description: str
    remediation: str
    endpoint: str
    parameter: str | None = None
    cvss_vector: str = ""
    cvss_score: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    cwe_id: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def owasp_name(self) -> str:
        return OWASP_TOP_10.get(self.owasp_category, "Unknown")

    @property
    def compliance_mapping(self) -> dict[str, list[str]]:
        result = {}
        pci = PCI_DSS_MAP.get(self.category)
        if pci:
            result["PCI-DSS"] = pci
        nist = NIST_MAP.get(self.category)
        if nist:
            result["NIST-800-53"] = nist
        result["OWASP"] = [f"{self.owasp_category}: {self.owasp_name}"]
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "category": self.category,
            "owasp": f"{self.owasp_category}: {self.owasp_name}",
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "references": self.references,
            "cwe": self.cwe_id,
            "compliance": self.compliance_mapping,
            "discovered_at": self.discovered_at.isoformat(),
        }


def severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score >= 0.1:
        return Severity.LOW
    return Severity.INFO


class FindingsDB:
    """Collection of findings with deduplication."""

    def __init__(self):
        self._findings: list[Finding] = []
        self._dedup_keys: set[str] = set()

    def _dedup_key(self, f: Finding) -> str:
        return f"{f.endpoint}|{f.parameter}|{f.category}|{f.title}"

    def add(self, finding: Finding) -> bool:
        """Add a finding. Returns False if duplicate."""
        key = self._dedup_key(finding)
        if key in self._dedup_keys:
            return False
        self._dedup_keys.add(key)
        self._findings.append(finding)
        return True

    def add_many(self, findings: list[Finding]) -> int:
        """Add multiple findings. Returns count of new (non-duplicate) findings."""
        return sum(1 for f in findings if self.add(f))

    def get_all(
        self,
        severity: Severity | None = None,
        category: str | None = None,
        owasp_category: str | None = None,
    ) -> list[Finding]:
        results = self._findings
        if severity:
            results = [f for f in results if f.severity == severity]
        if category:
            results = [f for f in results if f.category == category]
        if owasp_category:
            results = [f for f in results if f.owasp_category == owasp_category]
        return sorted(results, key=lambda f: f.cvss_score, reverse=True)

    @property
    def count(self) -> int:
        return len(self._findings)

    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self._findings:
            counts[f.severity.value] += 1
        return counts
