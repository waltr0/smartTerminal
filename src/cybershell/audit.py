from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cybershell.models import ShellContext, SuggestionResult


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def write_result(self, result: SuggestionResult) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "suggestion_evaluated",
            "partial_command": result.context.partial_command,
            "cwd": result.context.cwd,
            "shell": result.context.shell,
            "decision": result.risk.decision.value,
            "status": result.status.value,
            "risk_level": result.risk.level.value,
            "risk_score": result.risk.score,
            "matched_rules": [finding.rule_id for finding in result.risk.findings],
            "suggestion_source": result.suggestion.source if result.suggestion else None,
            "suggestion_record": result.suggestion.retrieved_id if result.suggestion else None,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    def summarize(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"events": 0, "by_decision": {}, "by_rule": {}}
        by_decision: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        events = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                events += 1
                item = json.loads(line)
                decision = item.get("decision", "unknown")
                by_decision[decision] = by_decision.get(decision, 0) + 1
                for rule_id in item.get("matched_rules", []):
                    by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
        return {"events": events, "by_decision": by_decision, "by_rule": by_rule}


def default_audit_path() -> Path:
    return Path.home() / ".cybershell" / "audit.jsonl"


def redacted_context(context: ShellContext) -> dict[str, Any]:
    env = {}
    for key, value in context.env.items():
        upper = key.upper()
        if any(marker in upper for marker in ("TOKEN", "SECRET", "KEY", "PASS")):
            env[key] = "<redacted>"
        else:
            env[key] = value
    payload = context.to_dict()
    payload["env"] = env
    return payload
