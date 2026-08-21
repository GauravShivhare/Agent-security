"""AgentSec - SARIF reporter for GitHub Code Scanning integration."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agentsec.attacks.models import AttackDefinition, Severity
from agentsec.evaluate.impact import ImpactScore
from agentsec.observe.events import event_to_dict


class SARIFReporter:
    """Generates SARIF (Static Analysis Results Interchange Format) reports.

    SARIF is the standard format for GitHub Code Scanning, GitLab SAST,
    Azure DevOps, and other security tools.
    """

    # SARIF version
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

    # Severity mapping to SARIF levels
    SEVERITY_TO_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    def __init__(self, output_path: Path | str):
        self.output_path = Path(output_path)

    def generate(
        self,
        target_name: str,
        attack_results: list[dict[str, Any]],
        tool_name: str = "AgentSec",
        tool_version: str = "0.1.0",
    ) -> Path:
        """Generate SARIF report and write to file."""

        sarif = self._build_sarif(target_name, attack_results, tool_name, tool_version)

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, default=str)

        return self.output_path

    def _build_sarif(
        self,
        target_name: str,
        attack_results: list[dict[str, Any]],
        tool_name: str,
        tool_version: str,
    ) -> dict[str, Any]:
        """Build SARIF report structure."""

        runs = [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/GauravShivhare/Agent-security",
                    "rules": self._build_rules(attack_results),
                }
            },
            "results": self._build_results(target_name, attack_results),
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.utcnow().isoformat() + "Z",
            }],
        }]

        return {
            "version": self.SARIF_VERSION,
            "$schema": self.SCHEMA_URI,
            "runs": runs,
        }

    def _build_rules(self, attack_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build SARIF rules from attack definitions."""

        rules = []
        seen_ids = set()

        for result in attack_results:
            attack_id = result["attack_id"]
            if attack_id in seen_ids:
                continue
            seen_ids.add(attack_id)

            severity = result.get("impact", {}).get("severity", result["severity"])
            level = self.SEVERITY_TO_LEVEL.get(Severity(severity), "warning")

            rule = {
                "id": attack_id,
                "name": result["name"],
                "shortDescription": {
                    "text": result["description"][:100] if result.get("description") else result["name"]
                },
                "fullDescription": {
                    "text": result.get("description", "")
                },
                "defaultConfiguration": {
                    "level": level
                },
                "help": {
                    "text": self._build_rule_help(result),
                    "markdown": self._build_rule_help(result),
                },
                "properties": {
                    "category": result["category"],
                    "severity": severity,
                    "tags": ["security", "ai-agent", result["category"]],
                }
            }
            rules.append(rule)

        return rules

    def _build_rule_help(self, result: dict[str, Any]) -> str:
        """Build help text for a rule."""
        lines = [
            f"## {result['name']}",
            "",
            result.get("description", ""),
            "",
            f"**Category:** {result['category']}",
            f"**Severity:** {result.get('impact', {}).get('severity', result['severity'])}",
        ]

        impact = result.get("impact")
        if impact:
            lines.extend([
                "",
                f"**Impact Score:** {impact.get('score', 'N/A')}/100",
                "",
                "### Impact Rationale",
                impact.get("rationale", "").replace("\n", "\n"),
            ])

        return "\n".join(lines)

    def _build_results(self, target_name: str, attack_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build SARIF results from attack results."""

        results = []

        for result in attack_results:
            if not result["success"]:
                continue  # Only report successful attacks (findings)

            attack_id = result["attack_id"]
            severity = result.get("impact", {}).get("severity", result["severity"])
            level = self.SEVERITY_TO_LEVEL.get(Severity(severity), "warning")

            # Build locations - use a virtual file for the attack
            locations = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"agentsec://{target_name}/{attack_id}",
                        "description": {"text": f"Attack: {result['name']}"},
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                    }
                }
            }]

            # Build message
            evidence_text = "\n".join(f"- {e}" for e in result.get("evidence", []))
            message = {
                "text": f"{result['name']}: {result['description']}\n\nEvidence:\n{evidence_text}"
            }

            # Build partial fingerprints for deduplication
            fingerprint = self._compute_fingerprint(result)

            sarif_result = {
                "ruleId": attack_id,
                "ruleIndex": 0,  # Will be updated
                "level": level,
                "message": message,
                "locations": locations,
                "partialFingerprints": fingerprint,
                "properties": {
                    "attackId": attack_id,
                    "category": result["category"],
                    "severity": severity,
                    "impactScore": result.get("impact", {}).get("score"),
                    "evidence": result.get("evidence", []),
                }
            }

            results.append(sarif_result)

        # Update rule indices
        rule_id_to_index = {}
        for i, result in enumerate(attack_results):
            if result["success"]:
                attack_id = result["attack_id"]
                if attack_id not in rule_id_to_index:
                    rule_id_to_index[attack_id] = len(rule_id_to_index)

        for result in results:
            result["ruleIndex"] = rule_id_to_index.get(result["ruleId"], 0)

        return results

    def _compute_fingerprint(self, result: dict[str, Any]) -> dict[str, str]:
        """Compute partial fingerprints for deduplication."""
        import hashlib

        # Create a stable fingerprint based on attack type and key evidence
        content = f"{result['attack_id']}:{result['category']}:{str(result.get('evidence', []))}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:16]

        return {
            "attackId": hash_val,
        }


def generate_sarif_report(
    target_name: str,
    attack_results: list[dict[str, Any]],
    output_path: Path | str,
    tool_name: str = "AgentSec",
    tool_version: str = "0.1.0",
) -> Path:
    """Convenience function to generate SARIF report."""
    reporter = SARIFReporter(output_path)
    return reporter.generate(target_name, attack_results, tool_name, tool_version)