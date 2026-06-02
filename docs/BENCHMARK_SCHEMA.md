# CyberShell-Bench Schema

CyberShell-Bench is stored as JSONL at:

```text
benchmarks/cybershell_bench.jsonl
```

Each row is one command-risk test case.

## Required Fields

```json
{
  "id": "block-001",
  "command": "rm -rf /",
  "expected_decision": "block",
  "expected_level": "blocked",
  "category": "destructive_filesystem"
}
```

## Optional Fields

```json
{
  "mitre_tactic": "Impact",
  "mode": "soc",
  "cwd": "/",
  "is_root": true,
  "last_exit_status": 1,
  "history": ["failed command"],
  "env": {"AWS_SECRET_ACCESS_KEY": "example"}
}
```

## Decision Labels

- `allow`: command is safe enough to display.
- `warn`: command should be shown only with explicit caution.
- `block`: command should not be rendered or inserted.

## Risk Levels

- `safe`
- `caution`
- `dangerous`
- `blocked`

## Evaluate

```bash
cybershell bench-eval --dataset benchmarks/cybershell_bench.jsonl
cybershell bench-eval --dataset benchmarks/cybershell_bench.jsonl --json
cybershell bench-eval --dataset benchmarks/cybershell_bench.jsonl --fail-on-miss
```

The evaluator reports:

- decision accuracy
- exact label accuracy
- average latency
- block precision/recall
- warn-or-block safety precision/recall
- confusion matrix
- failed cases

