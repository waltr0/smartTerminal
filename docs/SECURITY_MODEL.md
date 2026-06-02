# Security Model

CyberShell Copilot treats command suggestions as potentially dangerous until
validated.

## Security Principles

1. The local user remains in control.
2. The assistant never executes commands.
3. Guardrails run after every generation path.
4. The guardrail engine is deterministic and independent of any future LLM.
5. Blocked suggestions produce no shell insertion.
6. Audit logging is local and minimized.
7. Retrieved knowledge-base content is treated as data, not authority.

## Risk Levels

`safe`

No guardrail matches. The command can be displayed as a suggestion.

`caution`

Low-risk or context-sensitive behavior matched. The command can be displayed in
normal CLI output, but shell integration suppresses it when `--safe-only` is
used.

`dangerous`

High-risk behavior matched. The command requires explicit human review.

`blocked`

The command must not be rendered as ghost text or inserted by shell integration.

## Policy Modes

CyberShell supports policy profiles:

- `soc`: balanced defensive operations.
- `strict`: production-sensitive mode with lower thresholds.
- `admin`: routine system administration with normal guardrails.
- `learner`: training mode with more conservative warnings.
- `lab`: authorized lab/CTF mode that lowers network reconnaissance weight while
  still blocking destructive behavior.

Policy modes can change thresholds and category weights, but they do not disable
deterministic validation.

## Current Rule Categories

- `destructive_filesystem`
- `disk_destruction`
- `remote_code_execution`
- `network_exfiltration`
- `resource_exhaustion`
- `privilege_escalation`
- `persistence`
- `secrets_access`
- `firewall_tampering`
- `container_escape_risk`
- `network_reconnaissance`
- `operational_safety`
- `syntax`

## ATT&CK-Style Mapping

Rules include tactic/technique metadata such as:

- Impact / T1485
- Credential Access / T1552
- Discovery / T1046
- Persistence / T1053
- Defense Evasion / T1562
- Privilege Escalation / T1548

These mappings are not a replacement for a full threat-intelligence platform;
they are used to explain why a command deserves caution.

## Research Evaluation

CyberShell-Bench is a labeled benchmark used to test command-risk decisions. It
contains safe, warning, blocked, context-sensitive, and policy-sensitive cases.

```bash
cybershell bench-eval --dataset benchmarks/cybershell_bench.jsonl --fail-on-miss
```

## LLM/RAG Hardening Requirements

When FAISS or a local LLM backend is added:

- Validate output outside the model.
- Do not let prompt text disable guardrails.
- Keep KB records versioned and signed.
- Treat KB content as untrusted retrieval context.
- Enforce max output length and one-command output.
- Reject commands with malformed quoting.
- Never auto-execute generated commands.
