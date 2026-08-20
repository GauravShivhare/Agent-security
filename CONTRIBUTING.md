# Contributing to AgentSec

Thank you for your interest in contributing to AgentSec! This document provides guidelines for contributing.

## Ways to Contribute

1. **Add new attacks** — High-quality attack definitions are the most valuable contribution
2. **Improve adapters** — Add support for new agent frameworks
3. **Enhance evaluation** — Better success conditions, impact scoring
4. **Fix bugs** — Report and fix issues
5. **Improve documentation** — README, code comments, examples
6. **Add tests** — Increase test coverage

## Adding Attacks

Attacks are the heart of AgentSec. Follow these guidelines:

### Quality Standards

- **One attack per file** — Each YAML file defines a single attack
- **Synthetic data only** — Never use real credentials, APIs, or personal data
- **Deterministic success conditions** — Use observable tool calls, not subjective judgments
- **Clear impact rationale** — Explain *why* this attack matters
- **Realistic scenario** — Base on actual threat models (OWASP LLM Top 10, etc.)

### Attack Categories

| Category | Description |
|----------|-------------|
| `prompt_injection` | Direct/indirect prompt injection |
| `tool_abuse` | Misuse of agent tools |
| `secret_leakage` | Exposure of credentials/secrets |
| `memory` | Memory poisoning, context manipulation |
| `social_engineering` | Manipulation via social tactics |
| `data_exfiltration` | Unauthorized data extraction |

### Severity Guidelines

| Severity | Criteria |
|----------|----------|
| `critical` | Full system compromise, all data exfiltrated, irreversible |
| `high` | Significant data access, privilege escalation, external side effects |
| `medium` | Limited data exposure, internal impact, reversible |
| `low` | Information disclosure, minor policy violation |
| `info` | Behavioral change, no security impact |

### File Naming

```
{category}/{attack_name}_{number}.yaml
```

Example: `prompt-injection/indirect_prompt_injection_001.yaml`

### Template

```yaml
id: unique_attack_id
name: "Human Readable Name"
category: "prompt_injection"
severity: "high"
description: |
  Clear description of what this attack tests and why it matters.

setup:
  source: "user_input|untrusted_document|web_content|memory"
  synthetic_data: true
  prerequisites:
    - "Specific capability the agent must have"

payload:
  text: |
    The actual adversarial input

success_conditions:
  - type: "unexpected_tool_call|protected_data_in_args|policy_violation|response_contains"
    tool: "tool_name"  # optional
    argument: "arg_name"  # optional
    pattern: "regex_pattern"  # optional
    description: "Human-readable description"

expected_impact:
  category: "data_exfiltration"
  max_severity: "critical"
  description: "What happens if this succeeds"
  dimensions:
    privilege_required: "low|medium|high|none"
    data_sensitivity: "high|medium|low|none"
    external_side_effect: true|false
    reversibility: "low|medium|high|instant"
    blast_radius: "all_customers|organization|team|user|none"
    confidence: "high|medium|low"

tags:
  - "relevant"
  - "tags"

references:
  - "https://link-to-research-or-prior-art"
```

## Adding Adapters

To add a new adapter:

1. Create `src/agentsec/adapters/{name}.py`
2. Implement the `AgentTarget` interface
3. Register in `pyproject.toml` under `[project.entry-points."agentsec.adapters"]`
4. Add tests in `tests/test_{name}_adapter.py`

## Development Setup

```bash
# Clone and install
git clone https://github.com/GauravShivhare/Agent-security.git
cd Agent-security
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v

# Run linting
ruff check src/ tests/
mypy src/
```

## Code Style

- **Python 3.10+** — Type hints required
- **Ruff** — Linting and formatting
- **MyPy** — Static type checking
- **Pytest** — Testing

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-attack`)
3. Make your changes
4. Run tests and linting (`pytest tests/ && ruff check src/ && mypy src/`)
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

## Attack Review Checklist

Before submitting an attack PR, verify:

- [ ] Uses only synthetic/fake data
- [ ] Success conditions are deterministic and observable
- [ ] Impact scoring dimensions are justified
- [ ] References real threat research (OWASP, academic papers, CVEs)
- [ ] Tags are relevant and consistent
- [ ] File follows naming convention
- [ ] YAML validates against schema
- [ ] Test passes against vulnerable demo agent

## Code of Conduct

Be respectful, inclusive, and constructive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security Issues

Report security vulnerabilities privately to security@agentsec.dev (or GitHub Security Advisories).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.