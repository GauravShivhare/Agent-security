---
name: ci-agent-security-setup
description: Add AgentSec security scanning to CI/CD pipelines (GitHub Actions, GitLab CI) to block vulnerable AI agents before production
---

# CI/CD Agent Security with AgentSec

## When to use

Use this skill when:
- User wants to add automated security scanning to their CI/CD
- User wants to block PRs that introduce AI agent vulnerabilities
- User wants SARIF results in GitHub Security tab

## GitHub Actions setup

Create `.github/workflows/agentsec.yml`:

```yaml
name: AgentSec Security Scan

on:
  push:
    paths: ['src/**', 'agents/**']
  pull_request:
    paths: ['src/**', 'agents/**']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install AgentSec
        run: pip install agentsec

      - name: Run security scan
        run: agentsec scan ./my_agent --fail-on high --output-sarif report.sarif --output-json report.json

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentsec-report
          path: report.json
```

## GitLab CI setup

Create `.gitlab-ci.yml`:

```yaml
agentsec-scan:
  image: python:3.11-slim
  script:
    - pip install agentsec
    - agentsec scan ./my_agent --fail-on high --output-json report.json
  artifacts:
    reports:
      dotenv: report.json
    paths:
      - report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## Exit codes in CI

| Code | CI Behavior |
|------|-------------|
| 0 | Pass — merge allowed |
| 1 | Fail — merge blocked (findings above threshold) |
| 2 | Warning — merge allowed with warning |

## SARIF integration

AgentSec's SARIF output is compatible with:
- **GitHub Security tab** — Auto-displays findings
- **GitHub Code Scanning** — Alerts on new findings
- **Defender for DevOps** — Azure DevOps integration
- **Semgrep App** — Combined with static analysis

## Tips

- Use `--fail-on critical` for less strict gates
- Use `--fail-on high` for production branches
- Run `agentsec mutate` in nightly CI for deeper testing
- Cache pip packages: `actions/setup-python@v5` with `cache: pip`
