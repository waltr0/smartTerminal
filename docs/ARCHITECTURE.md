# Architecture

CyberShell Copilot is organized as a safety-first command suggestion pipeline.

```text
Shell context
  -> Prefix cache
  -> Knowledge base retrieval
  -> Candidate suggestion
  -> Policy-aware guardrail risk scoring
  -> Terminal output / suppression
  -> Optional audit event
```

## Modules

`ShellContext`

Captures the partial command, current directory, recent history, selected
environment values, last exit status, shell name, user, and root/non-root state.

`CommandKnowledgeBase`

Loads packaged command records from `command_kb.json`. The current backend uses
token scoring and prefix matching so the project works without external
dependencies. It intentionally exposes a small retrieval contract that can later
be implemented by FAISS HNSW.

`PrefixCache`

Stores accepted suggestions by partial prefix using an LRU policy. The cache can
be session-only or persisted to a user-selected JSON file.

`GuardrailEngine`

The deterministic final authority. Every typed command or generated suggestion
is scored against `guardrail_rules.json`, active policy thresholds, category
weight multipliers, and contextual checks. The LLM, when added, must never
bypass this module.

`PolicyRegistry`

Loads packaged policy modes from `policies.json`. Modes include `soc`, `strict`,
`admin`, `learner`, and `lab`.

`Benchmark`

Loads CyberShell-Bench JSONL cases and evaluates decision accuracy, exact label
accuracy, block precision/recall, warn-or-block safety recall, confusion, and
latency.

`SuggestionEngine`

Coordinates the flow: block unsafe partial commands early, check cache, retrieve
candidate records, score candidates, suppress blocked output, and write audit
events when enabled.

`AuditLog`

Writes privacy-minimized JSONL events containing the partial command, decision,
risk score, matched rules, source, and record ID. It avoids storing full
environment data.

## Extension Points

`CommandKnowledgeBase.retrieve()`

Replace with a FAISS-backed vector index. Keep the return shape:
`list[RetrievalHit]`.

`FaissHnswKnowledgeBase`

Optional research backend in `backends.py`. It is lazy-imported so the default
application remains dependency-light.

`CommandKnowledgeBase.suggest_from_hit()`

Replace or augment with a local LLM generation backend. Candidate output must
still be passed through `GuardrailEngine.assess()`.

`GuardrailEngine`

Rules can be expanded without source-code changes by adding entries to the JSON
rule pack. More advanced policy profiles can wrap this engine.

## Data Model Summary

Context:

```json
{
  "partial_command": "journal",
  "cwd": "/var/log",
  "history": ["systemctl status ssh"],
  "env": {"VIRTUAL_ENV": "/tmp/venv"},
  "last_exit_status": 0,
  "shell": "bash",
  "user": "analyst",
  "is_root": false
}
```

Suggestion:

```json
{
  "suggested_command": "journalctl -u ssh --since \"1 hour ago\"",
  "completion": "ctl -u ssh --since \"1 hour ago\"",
  "source": "knowledge-base",
  "confidence": 0.99,
  "retrieved_id": "ir.ssh_recent_logs"
}
```

Risk assessment:

```json
{
  "score": 70,
  "level": "blocked",
  "decision": "block",
  "findings": [
    {
      "rule_id": "fs.rm_recursive_force",
      "category": "destructive_filesystem",
      "mitre_tactic": "Impact",
      "mitre_technique": "T1485"
    }
  ]
}
```
