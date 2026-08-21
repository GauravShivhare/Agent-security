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
from agentsec.reporting.sarif import SARIFReporter
from agentsec.evaluate.policy import PolicyEngine


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
    policy_dir: str | None = None
    fail_on_policy: bool = False


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

        # Policy evaluation
        policy_results = []
        if self.config.policy_dir:
            try:
                engine = PolicyEngine(self.config.policy_dir)
                all_events = []
                for ar in attack_results:
                    all_events.extend(ar.get("events", []))
                
                policy_result = engine.evaluate(
                    all_events,
                    attack_id=None,  # Overall policy check
                    target_metadata=self.target.get_metadata() if hasattr(self.target, "get_metadata") else {},
                )
                policy_results.append({
                    "policy_dir": self.config.policy_dir,
                    "passed": policy_result.passed,
                    "violations": policy_result.violations,
                    "warnings": policy_result.warnings,
                })
                
                # Print policy results
                if policy_result.violations:
                    self.console.print(f"\n[bold red]Policy Violations ({len(policy_result.violations)}):[/bold red]")
                    for v in policy_result.violations:
                        self.console.print(f"  [{v['severity'].upper()}] {v['message']} (rule: {v.get('rule', 'unknown')})")
                if policy_result.warnings:
                    self.console.print(f"\n[bold yellow]Policy Warnings ({len(policy_result.warnings)}):[/bold yellow]")
                    for w in policy_result.warnings:
                        self.console.print(f"  [{w['severity'].upper()}] {w['message']} (rule: {w.get('rule', 'unknown')})")
                if policy_result.passed and not policy_result.warnings:
                    self.console.print("\n[green]✓ All policies passed[/green]")
                    
            except Exception as e:
                self.console.print_warning(f"Policy evaluation failed: {e}")

        # Build summary
        summary = JSONReporter.build_summary(attack_results)
        
        # Add policy summary
        if policy_results:
            total_violations = sum(len(p["violations"]) for p in policy_results)
            total_warnings = sum(len(p["warnings"]) for p in policy_results)
            summary["policy_violations"] = total_violations
            summary["policy_warnings"] = total_warnings
            summary["policy_passed"] = all(p["passed"] for p in policy_results)

        # Print summary
        self.console.print_summary(summary)

        # Generate JSON report
        if self.config.output_json:
            reporter = JSONReporter(self.config.output_json)
            reporter.generate(self.config.target_name, attack_results, summary)
            self.console.print_report_path(self.config.output_json)

        # Generate SARIF report
        if self.config.output_sarif:
            reporter = SARIFReporter(self.config.output_sarif)
            reporter.generate(self.config.target_name, attack_results)
            self.console.print_report_path(self.config.output_sarif)

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
        # Check attack failures
        if summary["failed"] == 0 and summary.get("policy_violations", 0) == 0:
            return 0

        # Check attack severity
        fail_on = self.config.fail_on.lower()
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_order.get(fail_on, 3)

        max_severity_found = 0
        for sev, count in summary["severity_breakdown"].items():
            if count > 0:
                max_severity_found = max(max_severity_found, severity_order.get(sev, 0))

        attack_fail = max_severity_found >= threshold

        # Check policy violations
        policy_fail = False
        if self.config.fail_on_policy and summary.get("policy_violations", 0) > 0:
            policy_fail = True

        return 1 if (attack_fail or policy_fail) else 0