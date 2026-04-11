"""Report rendering — Markdown and JSON output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pencheff.config import Severity
from pencheff.core.session import PentestSession
from pencheff.reporting.compliance import get_compliance_summary, get_owasp_coverage


def render_report(
    session: PentestSession,
    report_type: str = "full",
    output_format: str = "markdown",
    compliance_frameworks: list[str] | None = None,
) -> str:
    if output_format == "json":
        return _render_json(session, report_type, compliance_frameworks)
    return _render_markdown(session, report_type, compliance_frameworks)


def _render_json(session: PentestSession, report_type: str, frameworks: list[str] | None) -> str:
    findings = session.findings.get_all()
    data = {
        "report": {
            "type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": session.target.base_url,
            "session_id": session.id,
        },
        "summary": session.findings.summary(),
        "total_findings": session.findings.count,
        "findings": [f.to_dict() for f in findings],
    }
    if frameworks:
        data["compliance"] = get_compliance_summary(findings)
    return json.dumps(data, indent=2)


def _render_markdown(session: PentestSession, report_type: str, frameworks: list[str] | None) -> str:
    findings = session.findings.get_all()
    summary = session.findings.summary()
    frameworks = frameworks or ["owasp", "pci-dss", "nist"]

    lines = []

    # Header
    lines.append("# Penetration Test Report")
    lines.append(f"\n**Target:** {session.target.base_url}")
    lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Session:** {session.id}")
    lines.append(f"**Depth:** {session.depth.value}")
    lines.append(f"**Total Findings:** {session.findings.count}")
    lines.append("")

    # Executive Summary
    if report_type in ("executive", "full"):
        lines.append("## Executive Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = summary.get(sev.value, 0)
            marker = " :red_circle:" if sev == Severity.CRITICAL and count > 0 else ""
            lines.append(f"| {sev.value.upper()} | {count}{marker} |")
        lines.append("")

        # Risk assessment
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        if critical > 0:
            risk = "CRITICAL"
            assessment = f"The application has {critical} critical vulnerability(ies) requiring immediate remediation."
        elif high > 0:
            risk = "HIGH"
            assessment = f"The application has {high} high-severity vulnerability(ies) that should be addressed promptly."
        elif summary.get("medium", 0) > 0:
            risk = "MEDIUM"
            assessment = "The application has moderate security issues that should be addressed in the near term."
        else:
            risk = "LOW"
            assessment = "No critical or high-severity issues were found. Continue regular security assessments."

        lines.append(f"**Overall Risk Level: {risk}**")
        lines.append(f"\n{assessment}")
        lines.append("")

        # Tech stack discovered
        if session.discovered.tech_stack:
            lines.append("### Technology Stack")
            for category, techs in session.discovered.tech_stack.items():
                lines.append(f"- **{category}:** {', '.join(techs)}")
            lines.append("")

        # Attack surface
        lines.append("### Attack Surface")
        lines.append(f"- **Endpoints discovered:** {len(session.discovered.endpoints)}")
        lines.append(f"- **Subdomains found:** {len(session.discovered.subdomains)}")
        lines.append(f"- **Open ports:** {len(session.discovered.open_ports)}")
        lines.append(f"- **Total requests sent:** {len(session.request_log)}")
        lines.append("")

    # Findings Detail
    if report_type in ("technical", "full"):
        lines.append("## Findings")
        lines.append("")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            sev_findings = [f for f in findings if f.severity == sev]
            if not sev_findings:
                continue

            lines.append(f"### {sev.value.upper()} ({len(sev_findings)})")
            lines.append("")

            for f in sev_findings:
                lines.append(f"#### [{f.id}] {f.title}")
                lines.append("")
                lines.append(f"- **CVSS Score:** {f.cvss_score} ({f.cvss_vector})")
                lines.append(f"- **Category:** {f.category}")
                lines.append(f"- **OWASP:** {f.owasp_category}: {f.owasp_name}")
                lines.append(f"- **Endpoint:** `{f.endpoint}`")
                if f.parameter:
                    lines.append(f"- **Parameter:** `{f.parameter}`")
                if f.cwe_id:
                    lines.append(f"- **CWE:** {f.cwe_id}")
                lines.append(f"- **Verification:** {f.verification_status.value.replace('_', ' ').title()}")
                if f.verification_notes:
                    lines.append(f"- **Verification Notes:** {f.verification_notes}")
                lines.append("")
                lines.append(f"**Description:** {f.description}")
                lines.append("")

                if f.evidence:
                    lines.append("**Evidence:**")
                    for e in f.evidence[:3]:
                        lines.append(f"- {e.request_method} `{e.request_url}`")
                        if e.description:
                            lines.append(f"  - {e.description}")
                        if e.response_body_snippet:
                            lines.append(f"  - Response: `{e.response_body_snippet[:100]}...`")
                    lines.append("")

                lines.append(f"**Remediation:** {f.remediation}")
                lines.append("")

                if f.references:
                    lines.append("**References:**")
                    for ref in f.references:
                        lines.append(f"- {ref}")
                    lines.append("")

                # Compliance
                compliance = f.compliance_mapping
                if compliance:
                    mapping_parts = []
                    for fw, reqs in compliance.items():
                        mapping_parts.append(f"{fw}: {', '.join(reqs)}")
                    lines.append(f"**Compliance:** {' | '.join(mapping_parts)}")
                    lines.append("")

                lines.append("---")
                lines.append("")

    # Compliance Summary
    if report_type in ("executive", "full") and frameworks:
        lines.append("## Compliance Summary")
        lines.append("")

        if "owasp" in frameworks:
            categories = [f.owasp_category for f in findings]
            coverage = get_owasp_coverage(list(set(f.category for f in findings)))
            lines.append("### OWASP Top 10 Coverage")
            lines.append("")
            lines.append("| Category | Tested | Findings |")
            lines.append("|----------|--------|----------|")
            for cat, tested in coverage.items():
                cat_code = cat.split(":")[0]
                count = sum(1 for f in findings if f.owasp_category == cat_code)
                status = "Yes" if tested else "No"
                lines.append(f"| {cat} | {status} | {count} |")
            lines.append("")

        comp_summary = get_compliance_summary(findings)

        if "pci-dss" in frameworks and comp_summary.get("PCI-DSS"):
            lines.append("### PCI-DSS")
            lines.append("")
            for req, titles in comp_summary["PCI-DSS"].items():
                lines.append(f"- **Requirement {req}:** {len(titles)} finding(s)")
            lines.append("")

        if "nist" in frameworks and comp_summary.get("NIST 800-53"):
            lines.append("### NIST 800-53")
            lines.append("")
            for ctrl, titles in comp_summary["NIST 800-53"].items():
                lines.append(f"- **{ctrl}:** {len(titles)} finding(s)")
            lines.append("")

    # Remediation Roadmap
    if report_type in ("executive", "full"):
        lines.append("## Remediation Roadmap")
        lines.append("")
        lines.append("### Immediate (Critical/High)")
        for f in findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                lines.append(f"- [ ] **{f.title}** — {f.remediation}")
        lines.append("")
        lines.append("### Short-term (Medium)")
        for f in findings:
            if f.severity == Severity.MEDIUM:
                lines.append(f"- [ ] **{f.title}** — {f.remediation}")
        lines.append("")
        lines.append("### Long-term (Low/Info)")
        for f in findings:
            if f.severity in (Severity.LOW, Severity.INFO):
                lines.append(f"- [ ] **{f.title}** — {f.remediation}")
        lines.append("")

    lines.append("---")
    lines.append("*Report generated by Pencheff AI Penetration Testing Agent*")

    return "\n".join(lines)
