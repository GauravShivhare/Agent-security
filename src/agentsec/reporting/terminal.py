"""AgentSec - Terminal report generator with Rich."""

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from rich import box

from agentsec.attacks.models import AttackDefinition, Severity
from agentsec.evaluate.impact import ImpactScore


class TerminalReporter:
    """Generates beautiful terminal output using Rich."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def print_banner(self) -> None:
        """Print AgentSec banner."""
        banner = Text()
        banner.append("AgentSec", style="bold cyan")
        banner.append(" — AI Agent Security Testing", style="dim")
        self.console.print(Panel(banner, border_style="cyan", padding=(0, 1)))

    def print_scan_start(self, target: str, attack_count: int) -> None:
        """Print scan start info."""
        self.console.print(f"\n[bold]Target:[/bold] {target}")
        self.console.print(f"[bold]Attacks:[/bold] {attack_count}\n")

    def print_attack_result(
        self,
        attack: AttackDefinition,
        success: bool,
        evidence: list[str],
        impact_score: ImpactScore | None = None,
        verbose: bool = False,
    ) -> None:
        """Print result for a single attack."""
        status_style = "red" if success else "green"
        status_text = "FAILED" if success else "PASSED"

        # Attack header
        header = Text()
        header.append(f"[{status_text}] ", style=f"bold {status_style}")
        header.append(f"{attack.id}", style="bold")
        header.append(f" — {attack.name}")

        self.console.print(header)

        # Severity badge
        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "magenta",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }
        sev_color = severity_colors.get(attack.severity, "white")
        self.console.print(f"  Category: [{sev_color}]{attack.category.value}[/{sev_color}]  "
                          f"Severity: [{sev_color}]{attack.severity.value.upper()}[/{sev_color}]")

        # Evidence
        for ev in evidence:
            self.console.print(f"  {ev}")

        # Impact details
        if impact_score and success:
            self.console.print(f"  Impact Score: [bold]{impact_score.score}/100[/bold] "
                              f"([{sev_color}]{impact_score.severity.value.upper()}[/{sev_color}])")
            if verbose:
                for line in impact_score.rationale.split("\n"):
                    if line.strip():
                        self.console.print(f"    {line}")

        self.console.print()

    def print_summary(self, summary: dict[str, Any]) -> None:
        """Print final summary table."""
        self.console.print("\n" + "=" * 60)
        self.console.print("[bold]SUMMARY[/bold]\n")

        # Stats table
        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold")

        table.add_row("Total Attacks", str(summary["total_attacks"]))
        table.add_row("Passed", f"[green]{summary['passed']}[/green]")
        table.add_row("Failed", f"[red]{summary['failed']}[/red]")

        self.console.print(table)

        # Severity breakdown
        if summary["failed"] > 0:
            self.console.print("\n[bold]Severity Breakdown:[/bold]")
            sev_table = Table(box=box.SIMPLE)
            sev_table.add_column("Severity", style="bold")
            sev_table.add_column("Count", justify="right")

            severity_order = ["critical", "high", "medium", "low", "info"]
            severity_colors = {
                "critical": "red",
                "high": "magenta",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }

            for sev in severity_order:
                count = summary["severity_breakdown"].get(sev, 0)
                if count > 0:
                    sev_table.add_row(
                        f"[{severity_colors[sev]}]{sev.upper()}[/{severity_colors[sev]}]",
                        str(count),
                    )

            self.console.print(sev_table)

        # Security score
        score = summary["security_score"]
        score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        self.console.print(f"\n[bold]Security Score: [{score_color}]{score}/100[/{score_color}][/bold]")

        # Exit code hint
        if summary["failed"] > 0:
            self.console.print("\n[dim]Exit code: 1 (failures detected)[/dim]")
        else:
            self.console.print("\n[dim]Exit code: 0 (all checks passed)[/dim]")

    def print_report_path(self, path: str) -> None:
        """Print report file path."""
        self.console.print(f"\n[dim]Report saved to: {path}[/dim]")

    def print_error(self, message: str) -> None:
        """Print error message."""
        self.console.print(f"[bold red]Error:[/bold red] {message}")

    def print_warning(self, message: str) -> None:
        """Print warning message."""
        self.console.print(f"[bold yellow]Warning:[/bold yellow] {message}")

    def print_info(self, message: str) -> None:
        """Print info message."""
        self.console.print(f"[dim]{message}[/dim]")