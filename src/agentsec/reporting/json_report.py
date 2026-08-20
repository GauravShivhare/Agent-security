"""AgentSec - JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from agentsec.attacks.models import AttackDefinition, Severity
from agentsec.evaluate.impact import ImpactScore
from agentsec.observe.events import event_to_dict


class JSONReporter:
    """Generates machine-readable JSON report."""

    def __init__(self, output_path: Path | str):
        self.output_path = Path(output_path)

    def generate(
        self,
        target_name: str,
        attack_results: list[dict[str, Any]],
        summary: dict[str, Any],
        config: dict[str, Any] | None = None,
    ) -> Path:
        """Generate JSON report and write to file."""
        report = {
            "metadata": {
                "tool": "agentsec",
                "version": "0.1.0",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "target": target_name,
                "config": config or {},
            },
            "summary": summary,
            "results": attack_results,
        }

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return self.output_path

    @staticmethod
    def build_attack_result(
        attack: AttackDefinition,
        success: bool,
        evidence: list[str],
        events: list[dict[str, Any]],
        impact_score: ImpactScore | None = None,
    ) -> dict[str, Any]:
        """Build a single attack result object."""
        result = {
            "attack_id": attack.id,
            "name": attack.name,
            "category": attack.category.value,
            "severity": attack.severity.value,
            "description": attack.description,
            "success": success,
            "evidence": evidence,
            "events": events,
        }

        if impact_score:
            result["impact"] = {
                "severity": impact_score.severity.value,
                "score": impact_score.score,
                "dimensions": impact_score.dimensions,
                "rationale": impact_score.rationale,
            }

        return result

    @staticmethod
    def build_summary(attack_results: list[dict[str, Any]]) -> dict[str, Any]:
        """Build summary statistics from attack results."""
        total = len(attack_results)
        passed = sum(1 for r in attack_results if not r["success"])
        failed = total - passed

        severity_counts = {s.value: 0 for s in Severity}
        for r in attack_results:
            if r["success"]:
                sev = r.get("impact", {}).get("severity", r["severity"])
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Security score: 100 - (weighted failures)
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        penalty = sum(severity_counts[s] * w for s, w in weights.items())
        security_score = max(0, 100 - penalty)

        return {
            "total_attacks": total,
            "passed": passed,
            "failed": failed,
            "severity_breakdown": severity_counts,
            "security_score": security_score,
        }