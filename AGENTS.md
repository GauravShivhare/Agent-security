# AgentSec — Agent Guide

AgentSec is an open-source AI agent security testing framework. This file is for AI coding agents (Claude Code, Cursor, Codex, etc.) that want to **use** AgentSec to run security scans against AI agents or **contribute** to the project.

## Using AgentSec from an agent

### Quick scan

```bash
# Install
pip install agentsec

# Run a security scan against a target agent
agentsec scan ./my_agent --fail-on high

# Generate JSON + SARIF reports
agentsec scan ./my_agent --output-json report.json --output-sarif report.sarif

# Run with policy evaluation (OPA/Rego)
agentsec policy-init --output-dir policies
agentsec scan ./my_agent --policy-dir policies --fail-on-policy

# Generate attack mutations
agentsec mutate --attack-id indirect_prompt_injection_001 --max-variants 20 --seed 42

# Start web dashboard to view results
agentsec scan ./my_agent --output-json report.json
agentsec serve --report report.json --no-browser
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Warnings only (below threshold) |

### Artifacts

After a scan, AgentSec writes to `agentsec_runs/`:

```
agentsec_runs/
├── <timestamp>/
│   ├── report.json          # Full JSON report
│   ├── report.sarif         # SARIF 2.1.0 for CI integration
│   ├── report.md            # Markdown summary
│   ├── vulnerabilities/     # Per-finding detail files
│   └── run.json             # Run metadata (duration, cost, status)
```

### Built-in attacks

13 attacks across 4 categories:

- **Prompt Injection** (4): indirect, direct, encoding, social engineering
- **Tool Abuse** (3): unauthorized API, file read, SQL injection
- **Secret Leakage** (3): tool args, env vars, PII
- **Memory** (3): poisoning, context overflow, conversation hijack

List all attacks:

```bash
agentsec list-attacks
```

### Writing custom attacks

Create YAML files in `attacks/`:

```yaml
id: my_attack_001
name: "My Custom Attack"
category: "prompt_injection"
severity: "high"
description: "What this attack tests"

payload:
  text: |
    Adversarial input here

success_conditions:
  - type: "unexpected_tool_call"
    tool: "send_email"
    argument: "to"
    pattern: "attacker\\.example"
    description: "Agent sends email to attacker domain"

expected_impact:
  category: "data_exfiltration"
  max_severity: "critical"
  dimensions:
    privilege_required: "low"
    data_sensitivity: "high"
    external_side_effect: true
    reversibility: "low"
    blast_radius: "all_customers"
    confidence: "high"
```

Validate before running:

```bash
agentsec validate attacks/my_attack_001.yaml
```

### Adapters

AgentSec supports multiple agent framework adapters:

| Adapter | Install | 
|---------|---------|
| Custom (Python) | Built-in |
| HTTP API | Built-in |
| LangChain | `pip install agentsec[langchain]` |
| LangGraph | `pip install agentsec[langgraph]` |
| AutoGen | `pip install agentsec[autogen]` |
| CrewAI | `pip install agentsec[crewai]` |
| MCP | `pip install agentsec[mcp]` |

### CI/CD integration

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
      - run: pip install agentsec
      - run: agentsec scan ./my_agent --fail-on high --output-sarif report.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```

## Contributing

- Python 3.10+, managed with `pip` + `pyproject.toml`
- Dev install: `pip install -e .[dev]`
- Tests: `pytest tests/ -v`
- Lint: `ruff check src/`
- Type check: `mypy src/agentsec/`
- Run from source: `python -m agentsec scan examples/vulnerable_agent`

### Project layout

```
src/agentsec/
├── cli.py           # CLI entry point (Click)
├── config.py        # Config management
├── adapters/        # Target agent adapters
├── attacks/         # Attack models, registry, mutation
├── engine/          # Runner, orchestrator, sandbox
├── observe/         # Event tracing
├── evaluate/        # Success, impact, policy evaluation
├── reporting/       # JSON, terminal, SARIF reporters
└── dashboard.py     # Web dashboard (agentsec serve)
```

### Adding a new attack

1. Create a YAML file in `attacks/<category>/`
2. Define `id`, `name`, `category`, `severity`, `payload`, `success_conditions`, `expected_impact`
3. Run `agentsec validate attacks/<category>/my_attack.yaml`
4. Add a test in `tests/`
5. Run `pytest tests/ -v`

### Adding a new adapter

1. Create `src/agentsec/adapters/myadapter.py`
2. Subclass `AgentTarget` and implement `send()`, `list_tools()`, `reset()`, `get_events()`
3. Export from `src/agentsec/adapters/__init__.py`
4. Add optional dep in `pyproject.toml`
5. Add test in `tests/`
