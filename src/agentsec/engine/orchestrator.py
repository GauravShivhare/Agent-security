"""AgentSec - Orchestrator for running multiple attacks."""

from dataclasses import dataclass
from typing import Any

from agentsec.adapters.base import AgentTarget
from agentsec.attacks.registry import AttackRegistry
from agentsec.attacks.models import AttackDefinition
from agentsec.engine.runner import AttackRunner
from agentsec.observe.tracer import EventTracer
from agentsec.reporting.json_report import JSONReporter
from agentsec.reporting.terminal import TerminalReporter


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    target_name: str
    attack_ids: list[str] | None = None
    categories: list[str] | None = None
    severities: list[str] | None = None
    fail_on: str = "high"  # critical, high, medium, low
    verbose: bool = False
    output_json: str | None = None
    output_sarif: str | None = None
    sandbox: bool = False


@dataclass
class ScanResult:
    """Result of a complete scan."""
    target_name: str
    attack_results: list[dict[str, Any]]
    summary: dict[str, Any]
    exit_code: int


class Orchestrator:
    """Orchestrates running multiple attacks against a target."""

    def __init__(
        self,
        target: AgentTarget,
        registry: AttackRegistry,
        config: ScanConfig,
        console_reporter: TerminalReporter | None = None,
    ):
        self.target = target
        self.registry = registry
        self.config = config
        self.console = console_reporter or TerminalReporter()
        self.tracer = EventTracer()
        self.runner = AttackRunner(target, self.tracer)

    def select_attacks(self) -> list[AttackDefinition]:
        """Select attacks based on config filters."""
        attacks = self.registry.all()

        if self.config.attack_ids:
            attacks = [a for a in attacks if a.id in self.config.attack_ids]

        if self.config.categories:
            attacks = [a for a in attacks if a.category.value in self.config.categories]

        if self.config.severities:
            attacks = [a for a in attacks if a.severity.value in self.config.severities]

        return attacks

    def run(self) -> ScanResult:
        """Run all selected attacks."""
        attacks = self.select_attacks()

        if not attacks:
            self.console.print_warning("No attacks matched the selection criteria")
            return ScanResult(
                target_name=self.config.target_name,
                attack_results=[],
                summary={"total_attacks": 0, "passed": 0, "failed": 0, "severity_breakdown": {}, "security_score": 100},
                exit_code=0,
            )

        self.console.print_banner()
        self.console.print_scan_start(self.config.target_name, len(attacks))

        attack_results = []

        for i, attack in enumerate(attacks, 1):
            self.console.print_info(f"[{i}/{len(attacks)}] Running {attack.id}...")

            result = self.runner.run(attack)

            # Build attack result for reporting
            attack_result = JSONReporter.build_attack_result(
                attack=attack,
                success=result["success"],
                evidence=result["evidence"],
                events=result["events"],
                impact_score=result["impact_score"],
            )
            attack_results.append(attack_result)

            # Print to console
            self.console.print_attack_result(
                attack=attack,
                success=result["success"],
                evidence=result["evidence"],
                impact_score=result["impact_score"],
                verbose=self.config.verbose,
            )

        # Build summary
        summary = JSONReporter.build_summary(attack_results)

        # Print summary
        self.console.print_summary(summary)

        # Generate JSON report
        if self.config.output_json:
            reporter = JSONReporter(self.config.output_json)
            reporter.generate(self.config.target_name, attack_results, summary)
            self.console.print_report_path(self.config.output_json)

        # TODO: SARIF report

        # Determine exit code
        exit_code = self._determine_exit_code(summary)

        return ScanResult(
            target_name=self.config.target_name,
            attack_results=attack_results,
            summary=summary,
            exit_code=exit_code,
        )

    def _determine_exit_code(self, summary: dict[str, Any]) -> int:
        """Determine exit code based on fail-on threshold."""
        if summary["failed"] == 0:
            return 0

        fail_on = self.config.fail_on.lower()
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_order.get(fail_on, 3)

        max_severity_found = 0
        for sev, count in summary["severity_breakdown"].items():
            if count > 0:
                max_severity_found = max(max_severity_found, severity_order.get(sev, 0))

        return 1 if max_severity_found >= threshold else 0