from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cybershell.models import ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine

UNSAFE = {"warn", "block"}


@dataclass(slots=True)
class BenchmarkCase:
    id: str
    command: str
    category: str
    kind: str = "guardrail"  # "guardrail" or "suggestion"
    expected_decision: str | None = None
    expected_level: str | None = None
    expected_status: str | None = None
    known_limitation: bool = False
    mitre_tactic: str | None = None
    mode: str = "soc"
    cwd: str = "."
    is_root: bool = False
    last_exit_status: int | None = None
    history: list[str] | None = None
    env: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkCase:
        return cls(
            id=str(data["id"]),
            command=str(data["command"]),
            category=str(data.get("category", "uncategorized")),
            kind=str(data.get("kind", "guardrail")),
            expected_decision=data.get("expected_decision"),
            expected_level=data.get("expected_level"),
            expected_status=data.get("expected_status"),
            known_limitation=bool(data.get("known_limitation", False)),
            mitre_tactic=data.get("mitre_tactic"),
            mode=str(data.get("mode", "soc")),
            cwd=str(data.get("cwd", ".")),
            is_root=bool(data.get("is_root", False)),
            last_exit_status=data.get("last_exit_status"),
            history=list(data.get("history", [])),
            env=dict(data.get("env", {})),
        )

    def context(self) -> ShellContext:
        return ShellContext(
            partial_command=self.command,
            cwd=self.cwd,
            history=self.history or [],
            env=self.env or {},
            last_exit_status=self.last_exit_status,
            is_root=self.is_root,
        )


def load_benchmark(path: Path) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                cases.append(BenchmarkCase.from_dict(json.loads(stripped)))
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid benchmark row {line_number}: {exc}") from exc
    return cases


def evaluate_benchmark(path: Path, default_mode: str = "soc") -> dict[str, Any]:
    cases = load_benchmark(path)
    guardrails = GuardrailEngine.packaged()
    policies = PolicyRegistry.packaged()
    # Imported lazily so the guardrail path has no suggestion-engine dependency.
    from cybershell.engine import SuggestionEngine

    engine = SuggestionEngine(guardrails=guardrails)

    rows: list[dict[str, Any]] = []
    total_latency_ms = 0.0

    for case in cases:
        mode = case.mode or default_mode
        start = time.perf_counter()
        if case.kind == "suggestion":
            result = engine.suggest(case.context(), mode=mode)
            actual = result.status.value
            expected = case.expected_status
            actual_level = result.risk.level.value
        else:
            policy = policies.get(mode)
            assessment = guardrails.assess(case.command, case.context(), policy)
            actual = assessment.decision.value
            expected = case.expected_decision
            actual_level = assessment.level.value
        latency_ms = (time.perf_counter() - start) * 1000
        total_latency_ms += latency_ms

        passed = expected == actual
        rows.append(
            {
                "id": case.id,
                "kind": case.kind,
                "category": case.category,
                "mode": mode,
                "command": case.command,
                "expected": expected,
                "actual": actual,
                "expected_level": case.expected_level,
                "actual_level": actual_level,
                "known_limitation": case.known_limitation,
                "pass": passed,
                "latency_ms": round(latency_ms, 4),
            }
        )

    guardrail_rows = [r for r in rows if r["kind"] == "guardrail"]
    suggestion_rows = [r for r in rows if r["kind"] == "suggestion"]

    unexpected_failures = [r for r in rows if not r["pass"] and not r["known_limitation"]]
    known_failures = [r for r in rows if not r["pass"] and r["known_limitation"]]
    resolved_limitations = [r for r in rows if r["pass"] and r["known_limitation"]]

    return {
        "dataset": str(path),
        "cases": len(rows),
        "guardrail_cases": len(guardrail_rows),
        "suggestion_cases": len(suggestion_rows),
        "overall_accuracy": _ratio(sum(1 for r in rows if r["pass"]), len(rows)),
        "core_accuracy": _ratio(
            sum(1 for r in rows if r["pass"] and not r["known_limitation"]),
            sum(1 for r in rows if not r["known_limitation"]),
        ),
        "guardrail_decision_accuracy": _ratio(
            sum(1 for r in guardrail_rows if r["pass"]), len(guardrail_rows)
        ),
        "suggestion_status_accuracy": _ratio(
            sum(1 for r in suggestion_rows if r["pass"]), len(suggestion_rows)
        ),
        "false_positive_rate": _false_positive_rate(guardrail_rows),
        "detection_recall": _detection_recall(guardrail_rows),
        "block_metrics": _binary_metrics(guardrail_rows, "block"),
        "warn_or_block_safety_metrics": _warn_or_block_metrics(guardrail_rows),
        "by_category": _by_category(rows),
        "confusion": _confusion(guardrail_rows),
        "avg_latency_ms": round(total_latency_ms / len(rows), 4) if rows else 0.0,
        "known_limitations": known_failures,
        "resolved_limitations": resolved_limitations,
        "failures": unexpected_failures,
        "rows": rows,
    }


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _false_positive_rate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    safe = [r for r in rows if r["expected"] == "allow"]
    false_alarms = [r for r in safe if r["actual"] in UNSAFE]
    return {
        "safe_cases": len(safe),
        "false_alarms": len(false_alarms),
        "rate": _ratio(len(false_alarms), len(safe)),
    }


def _detection_recall(rows: list[dict[str, Any]]) -> dict[str, Any]:
    dangerous = [r for r in rows if r["expected"] == "block"]
    missed = [r for r in dangerous if r["actual"] != "block"]
    return {
        "block_cases": len(dangerous),
        "missed": len(missed),
        "recall": _ratio(len(dangerous) - len(missed), len(dangerous)),
    }


def _binary_metrics(rows: list[dict[str, Any]], positive: str) -> dict[str, float]:
    tp = sum(1 for r in rows if r["expected"] == positive and r["actual"] == positive)
    fp = sum(1 for r in rows if r["expected"] != positive and r["actual"] == positive)
    fn = sum(1 for r in rows if r["expected"] == positive and r["actual"] != positive)
    return {
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def _warn_or_block_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    tp = sum(1 for r in rows if r["expected"] in UNSAFE and r["actual"] in UNSAFE)
    fp = sum(1 for r in rows if r["expected"] not in UNSAFE and r["actual"] in UNSAFE)
    fn = sum(1 for r in rows if r["expected"] in UNSAFE and r["actual"] not in UNSAFE)
    return {
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def _by_category(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        bucket = out.setdefault(row["category"], {"cases": 0, "passed": 0})
        bucket["cases"] += 1
        bucket["passed"] += int(row["pass"])
    for bucket in out.values():
        bucket["accuracy"] = _ratio(bucket["passed"], bucket["cases"])
    return dict(sorted(out.items()))


def _confusion(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    confusion: dict[str, dict[str, int]] = {}
    for row in rows:
        expected = row["expected"] or "unknown"
        confusion.setdefault(expected, {})
        confusion[expected][row["actual"]] = confusion[expected].get(row["actual"], 0) + 1
    return confusion
