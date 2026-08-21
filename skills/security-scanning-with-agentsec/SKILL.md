---
name: security-scanning-with-agentsec
description: Run AgentSec security scans against AI agents to find prompt injection, tool abuse, secret leakage, and memory attacks
---

# Security Scanning with AgentSec

## When to use

Use this skill when asked to:
- Security-test an AI agent or LLM-powered application
- Find prompt injection vulnerabilities
- Check for tool abuse or secret leakage
- Run adversarial attacks against an agent
- Generate a security report for an agent

## Quick start

```bash
# Install
pip install git+https://github.com/GauravShivhare/Agent-security.git

# Run a scan
agentsec scan ./my_agent --fail-on high

# Get JSON + SARIF output
agentsec scan ./my_agent --output-json report.json --output-sarif report.sarif

# View results in dashboard
agentsec serve --report report.json --no-browser
```

## Scan modes

| Flag | Effect |
|------|--------|
| `--fail-on high` | Exit 1 if HIGH/CRITICAL found |
| `--fail-on critical` | Exit 1 only on CRITICAL |
| `--output-json FILE` | Write JSON report |
| `--output-sarif FILE` | Write SARIF 2.1.0 report |
| `--policy-dir DIR` | Evaluate OPA/Rego policies |
| `--fail-on-policy` | Exit 1 on policy violations |
| `--sandbox` | Run in Docker isolation |
| `--verbose` | Detailed output |

## Listing attacks

```bash
# All built-in attacks
agentsec list-attacks

# Filter by category
agentsec list-attacks --category prompt_injection
```

## Reading results

After scan, artifacts are in `agentsec_runs/<timestamp>/`:
- `report.json` — full structured report
- `report.sarif` — SARIF for GitHub Code Scanning
- `report.md` — markdown summary
- `vulnerabilities/` — per-finding detail files
- `run.json` — run metadata

## Exit codes

- `0` — all passed
- `1` — findings at/above threshold
- `2` — warnings only
