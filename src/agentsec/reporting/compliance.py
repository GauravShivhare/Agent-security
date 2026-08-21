"""AgentSec - Compliance report generator (SOC2, ISO 27001, PCI DSS)."""

import json
import datetime
from pathlib import Path
from typing import Any


# Control mapping: AgentSec attack categories → compliance frameworks
COMPLIANCE_MAPPING: dict[str, dict[str, list[str]]] = {
    "prompt_injection": {
        "SOC2": ["CC6.1", "CC7.1", "CC7.2"],
        "ISO27001": ["A.14.2.5", "A.16.1.4"],
        "PCI_DSS": ["6.5.1", "6.5.7"],
        "OWASP_LLM": ["LLM01", "LLM06"],
    },
    "tool_abuse": {
        "SOC2": ["CC6.3", "CC6.6", "CC7.1"],
        "ISO27001": ["A.9.4.4", "A.12.4.1"],
        "PCI_DSS": ["6.5.1", "6.5.8", "7.1.1"],
        "OWASP_LLM": ["LLM02"],
    },
    "secret_leakage": {
        "SOC2": ["CC6.1", "CC6.7", "CC7.2"],
        "ISO27001": ["A.8.2.3", "A.10.1.1", "A.13.2.1"],
        "PCI_DSS": ["3.4", "6.5.3", "8.2.1"],
        "OWASP_LLM": ["LLM02", "LLM07"],
    },
    "memory": {
        "SOC2": ["CC6.1", "CC7.1", "CC7.3"],
        "ISO27001": ["A.13.2.1", "A.16.1.4"],
        "PCI_DSS": ["6.5.1", "8.2.1"],
        "OWASP_LLM": ["LLM06"],
    },
}


COMPLIANCE_FRAMEWORKS = {
    "SOC2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Controls — Security, Availability, Processing Integrity, Confidentiality, Privacy",
    },
    "ISO27001": {
        "name": "ISO/IEC 27001:2022",
        "description": "Information Security Management System (ISMS) Controls",
    },
    "PCI_DSS": {
        "name": "PCI DSS v4.0",
        "description": "Payment Card Industry Data Security Standard",
    },
    "OWASP_LLM": {
        "name": "OWASP Top 10 for LLM Applications",
        "description": "Security risks specific to Large Language Model applications",
    },
}


class ComplianceReporter:
    """Generate compliance-ready security reports from AgentSec scan results."""

    def __init__(self, scan_report: dict[str, Any] | None = None):
        self.scan_report = scan_report

    def generate(
        self,
        scan_report: dict[str, Any] | None = None,
        frameworks: list[str] | None = None,
        organization: str = "Organization",
    ) -> dict[str, Any]:
        """Generate a compliance report covering specified frameworks."""
        report = scan_report or self.scan_report
        if not report:
            raise ValueError("No scan report provided")

        if frameworks is None:
            frameworks = list(COMPLIANCE_FRAMEWORKS.keys())

        findings = report.get("findings", report.get("attack_results", report.get("results", [])))
        failed = [
            f for f in findings
            if f.get("success", False) or f.get("was_successful", False) or f.get("status") == "failed"
        ]

        # Map findings to control violations
        control_violations: dict[str, list[dict[str, Any]]] = {}
        for f in frameworks:
            control_violations[f] = []

        for finding in failed:
            cat = finding.get("category", "")
            mapping = COMPLIANCE_MAPPING.get(cat, {})

            for framework in frameworks:
                controls = mapping.get(framework, [])
                for control in controls:
                    impact_obj = finding.get("impact", {})
                    control_violations[framework].append({
                        "control_id": control,
                        "control_name": COMPLIANCE_FRAMEWORKS[framework]["name"],
                        "finding_id": finding.get("attack_id", "?"),
                        "finding_name": finding.get("name", finding.get("attack_name", "?")),
                        "severity": finding.get("severity", "unknown"),
                        "impact_score": impact_obj.get("score", 0),
                        "description": finding.get("description", ""),
                        "evidence": finding.get("evidence", []),
                        "status": "violated",
                    })

        # Build report
        report_data: dict[str, Any] = {
            "report_type": "compliance_security_assessment",
            "organization": organization,
            "generated_at": datetime.datetime.now().isoformat(),
            "scan_metadata": {
                "target": report.get("target_name", report.get("summary", {}).get("target_name", "unknown")),
                "total_attacks": report.get("summary", {}).get("total_attacks", len(findings)),
                "passed": report.get("summary", {}).get("passed", len(findings) - len(failed)),
                "failed": len(failed),
                "security_score": report.get("summary", {}).get("security_score", 0),
            },
            "frameworks_covered": [],
            "summary": {
                "total_findings": len(failed),
                "total_control_violations": sum(len(v) for v in control_violations.values()),
                "risk_level": self._risk_level(report.get("summary", {}).get("security_score", 100)),
            },
        }

        for fw in frameworks:
            fw_info = COMPLIANCE_FRAMEWORKS.get(fw, {})
            violations = control_violations[fw]
            unique_controls = list({v["control_id"] for v in violations})

            report_data["frameworks_covered"].append({
                "framework": fw,
                "name": fw_info.get("name", fw),
                "description": fw_info.get("description", ""),
                "controls_total_tested": len(unique_controls),
                "controls_violated": unique_controls,
                "violations": violations,
                "compliance_status": "non_compliant" if violations else "compliant",
            })

        return report_data

    def generate_markdown(
        self,
        scan_report: dict[str, Any] | None = None,
        frameworks: list[str] | None = None,
        organization: str = "Organization",
        output_path: Path | None = None,
    ) -> str:
        """Generate a compliance report as markdown."""
        data = self.generate(scan_report, frameworks, organization)

        lines = [
            f"# AI Agent Security Compliance Report",
            "",
            f"**Organization:** {data['organization']}",
            f"**Generated:** {data['generated_at']}",
            f"**Report Type:** Compliance Security Assessment",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Target Agent | {data['scan_metadata']['target']} |",
            f"| Total Attacks | {data['scan_metadata']['total_attacks']} |",
            f"| Passed | {data['scan_metadata']['passed']} |",
            f"| Failed | {data['scan_metadata']['failed']} |",
            f"| Security Score | {data['scan_metadata']['security_score']}/100 |",
            f"| Risk Level | {data['summary']['risk_level']} |",
            f"| Total Control Violations | {data['summary']['total_control_violations']} |",
            "",
            "---",
            "",
        ]

        for fw in data["frameworks_covered"]:
            lines.append(f"## {fw['name']}")
            lines.append("")
            lines.append(f"> {fw['description']}")
            lines.append("")
            lines.append(f"**Compliance Status:** {'❌ Non-Compliant' if fw['violations'] else '✅ Compliant'}")
            lines.append(f"**Controls Tested:** {fw['controls_total_tested']}")
            lines.append("")

            if fw["violations"]:
                lines.append("### Violated Controls")
                lines.append("")
                lines.append("| Control | Finding | Severity | Impact |")
                lines.append("|---------|---------|----------|--------|")

                for v in fw["violations"]:
                    lines.append(
                        f"| {v['control_id']} | {v['finding_name']} | "
                        f"{v['severity'].upper()} | {v['impact_score']}/100 |"
                    )

                lines.append("")

                # Detailed findings
                lines.append("### Findings Detail")
                lines.append("")

                seen_findings = set()
                for v in fw["violations"]:
                    fid = v["finding_id"]
                    if fid in seen_findings:
                        continue
                    seen_findings.add(fid)

                    lines.append(f"#### {v['finding_name']}")
                    lines.append(f"- **Finding ID:** `{fid}`")
                    lines.append(f"- **Severity:** {v['severity'].upper()}")
                    lines.append(f"- **Impact Score:** {v['impact_score']}/100")
                    lines.append(f"- **Affected Controls:** {', '.join(fw['controls_violated'])}")
                    lines.append("")

                    if v.get("evidence"):
                        lines.append("**Evidence:**")
                        for e in v["evidence"][:5]:
                            lines.append(f"- {e}")
                        lines.append("")

                    lines.append("**Remediation:** See `agentsec autofix` output for code-level fix suggestions.")
                    lines.append("")
            else:
                lines.append("No violations found for this framework. ✅")
                lines.append("")

            lines.append("---")
            lines.append("")

        lines.append("## Methodology")
        lines.append("")
        lines.append("This report was generated by **AgentSec — AI Agent Security Testing Framework**.")
        lines.append("The assessment used structured adversarial attacks targeting the AI agent's security boundaries,")
        lines.append("including prompt injection, tool abuse, secret leakage, and memory attack vectors.")
        lines.append("")
        lines.append("Findings are based on deterministic evaluation of observable agent behavior, not LLM judgments.")
        lines.append("")

        md_text = "\n".join(lines)

        if output_path:
            output_path.write_text(md_text, encoding="utf-8")

        return md_text

    def _risk_level(self, score: float) -> str:
        if score >= 90:
            return "Low"
        if score >= 75:
            return "Medium"
        if score >= 50:
            return "High"
        return "Critical"
