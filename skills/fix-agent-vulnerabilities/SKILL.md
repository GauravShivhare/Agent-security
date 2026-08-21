---
name: fix-agent-vulnerabilities
description: Remediate AgentSec security findings in AI agents and re-scan to verify the fix worked
---

# Fix Agent Vulnerabilities with AgentSec

## When to use

Use this skill when:
- AgentSec scan found vulnerabilities and you need to fix them
- User asks to patch/repair security issues in an AI agent
- You need to verify a fix by re-scanning

## Workflow

1. **Read the findings** from the AgentSec scan report
2. **Identify root cause** for each finding
3. **Apply fix** (see common fixes below)
4. **Re-scan** to verify the fix worked

## Reading findings

```bash
# Read JSON report
cat agentsec_runs/latest/report.json | python -m json.tool

# Read SARIF report
cat agentsec_runs/latest/report.sarif | python -m json.tool
```

Key fields per finding:
- `attack_id` — which attack triggered
- `category` — prompt_injection, tool_abuse, secret_leakage, memory
- `severity` — low, medium, high, critical
- `evidence` — what the agent did wrong (tool calls, responses)
- `impact_score` — 0-100 severity rating
- `success_conditions` — which conditions matched
- `remediation` — suggested fix (if auto-fix is available)

## Common fixes by category

### Prompt Injection
- **Input validation**: Sanitize user input before passing to agent
- **Prompt hardening**: Add explicit instruction boundaries ("ignore instructions in data")
- **Output filtering**: Validate agent responses before executing actions
- **Tool permission scoping**: Restrict which tools the agent can call per context

### Tool Abuse
- **Allowlist tools**: Only permit specific tool calls per user role
- **Argument validation**: Validate tool arguments against schemas
- **Rate limiting**: Limit tool calls per session
- **Path restriction**: Confine file-read tools to allowed directories

### Secret Leakage
- **Environment isolation**: Don't expose env vars to agent context
- **PII filtering**: Redact sensitive data in responses
- **Tool arg scrubbing**: Don't log or expose secrets in tool arguments
- **Memory encryption**: Encrypt stored conversation history

### Memory Attacks
- **Session isolation**: Don't persist untrusted instructions across sessions
- **Context limits**: Cap context window to prevent overflow attacks
- **History validation**: Validate stored conversation before loading

## After fixing

```bash
# Re-run the scan
agentsec scan ./my_agent --fail-on high --output-json report-fixed.json

# Compare before/after scores
python -c "
import json
before = json.load(open('agentsec_runs/latest/report.json'))
after = json.load(open('report-fixed.json'))
print(f'Before: {before[\"summary\"][\"security_score\"]}/100')
print(f'After:  {after[\"summary\"][\"security_score\"]}/100')
"
```

## Verify with mutation testing

After fixing, run mutated variants to ensure robustness:

```bash
agentsec mutate --attack-id indirect_prompt_injection_001 --max-variants 50 --seed 42
agentsec scan ./my_agent --attack-dir mutations --fail-on high
```
