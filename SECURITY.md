# Security Policy

## Reporting a vulnerability

AgentSec is a security-testing project, so responsible vulnerability reports are welcome. Please do not publish exploit details, credentials, private data, or a working proof of concept in a public issue.

For a private report, use GitHub’s **Report a vulnerability** option in the repository’s Security tab when it is available. If that option is unavailable, open a minimal issue asking for a private contact channel and do not include sensitive technical details. You can also contact the maintainer through the public profile links on [Gaurav Shivhare’s GitHub profile](https://github.com/GauravShivhare).

## What to include

Provide the affected version or commit, the smallest safe reproduction, the expected and observed behavior, the security impact, and any suggested mitigation. Redact API keys, tokens, personal information, customer data, and other secrets before sending a report.

## Scope

Reports are especially useful for vulnerabilities in AgentSec’s attack execution, adapter boundaries, report handling, policy evaluation, dependency usage, and any path that could cause unintended tool calls or sensitive-data exposure. Documentation errors and ordinary feature requests should use regular GitHub issues instead.

## Response expectations

The maintainer will acknowledge a valid report when possible, investigate it, and coordinate a fix or mitigation before public disclosure. Please allow reasonable time for triage and remediation, and avoid testing against systems you do not own or have explicit permission to assess.
