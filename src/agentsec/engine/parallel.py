"""AgentSec - Parallel scan engine for multi-category concurrent attacks."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.adapters.base import AgentTarget
from agentsec.attacks.models import AttackDefinition
from agentsec.attacks.registry import AttackRegistry
from agentsec.engine.runner import AttackRunner
from agentsec.observe.tracer import EventTracer


@dataclass
class ParallelScanResult:
    """Result of a parallel scan."""

    workers: int
    total_attacks: int
    completed: int
    results: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0


class ParallelOrchestrator:
    """Run attacks across categories in parallel using thread pool.

    Each worker gets its own adapter instance (via a factory) so
    attacks don't interfere with each other's state.
    """

    def __init__(
        self,
        registry: AttackRegistry,
        scan_config: Any,
        reporter: Any | None = None,
        max_workers: int = 4,
    ):
        self.registry = registry
        self.scan_config = scan_config
        self.reporter = reporter
        self.max_workers = max_workers

    def _filter_attacks(self) -> list[AttackDefinition]:
        """Get attacks matching the scan config filters."""
        attacks = list(self.registry.all())

        if self.scan_config.attack_ids:
            attacks = [a for a in attacks if a.id in self.scan_config.attack_ids]

        if self.scan_config.categories:
            cats = {c if isinstance(c, str) else c.value for c in self.scan_config.categories}
            attacks = [a for a in attacks if a.category.value in cats]

        if self.scan_config.severities:
            sevs = {s if isinstance(s, str) else s.value for s in self.scan_config.severities}
            attacks = [a for a in attacks if a.severity.value in sevs]

        return attacks

    def run(self, target_adapter: AgentTarget) -> ParallelScanResult:
        """Run all matching attacks in parallel threads."""
        attacks = self._filter_attacks()
        start_time = time.time()

        results: list[dict[str, Any]] = []

        # ThreadPoolExecutor because the adapters are synchronous Python callables
        # Each attack runs against a fresh reset of the agent
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}

            for attack in attacks:
                target_adapter.reset()
                runner = AttackRunner(target_adapter)
                future = pool.submit(self._run_single, runner, attack)
                futures[future] = attack

            for future in as_completed(futures):
                attack = futures[future]
                try:
                    result = future.result()
                    results.append(result)

                    if self.reporter:
                        self.reporter.report_attack(result)

                except Exception as e:
                    results.append({
                        "attack_id": attack.id,
                        "attack_name": attack.name,
                        "status": "error",
                        "error": str(e),
                        "was_successful": False,
                    })

        duration = time.time() - start_time

        return ParallelScanResult(
            workers=self.max_workers,
            total_attacks=len(attacks),
            completed=len(results),
            results=results,
            duration_seconds=duration,
        )

    def _run_single(
        self, runner: AttackRunner, attack: AttackDefinition
    ) -> dict[str, Any]:
        """Run a single attack and return the result dict."""
        result = runner.run(attack)
        return result.to_dict() if hasattr(result, "to_dict") else result


def run_parallel_scan(
    target: AgentTarget,
    registry: AttackRegistry,
    scan_config: Any,
    max_workers: int = 4,
) -> ParallelScanResult:
    """Convenience function to run a parallel scan."""
    orchestrator = ParallelOrchestrator(
        registry=registry,
        scan_config=scan_config,
        max_workers=max_workers,
    )
    return orchestrator.run(target)
