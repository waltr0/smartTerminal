from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cybershell.models import ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine


@dataclass(slots=True)
class BenchmarkCase:
    id: str
    command: str
    expected_decision: str
    expected_level: str
    category: str
    mitre_tactic: str | None = None
    mode: str = "soc"
    cwd: str = "."
    is_root: bool = False
    last_exit_status: int | None = None
    history: list[str] | None = None
    env: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BenchmarkCase":
        return cls(
            id=str(data["id"]),
            command=str(data["command"]),
            expected_decision=str(data["expected_decision"]),
            expected_level=str(data["expected_level"]),
            category=str(data.get("category", "uncategorized")),
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
    rows: list[dict[str, Any]] = []
    confusion: dict[str, dict[str, int]] = {}
    total_latency_ms = 0.0

    for case in cases:
        mode = case.mode or default_mode
        policy = policies.get(mode)
        start = time.perf_counter()
        assessment = guardrails.assess(case.command, case.context(), policy)
        latency_ms = (time.perf_counter() - start) * 1000
        total_latency_ms += latency_ms

        expected = case.expected_decision
        actual = assessment.decision.value
        confusion.setdefault(expected, {})
        confusion[expected][actual] = confusion[expected].get(actual, 0) + 1
        rows.append(
            {
                "id": case.id,
                "mode": mode,
                "command": case.command,
                "expected_decision": expected,
                "actual_decision": actual,
                "expected_level": case.expected_level,
                "actual_level": assessment.level.value,
                "score": assessment.score,
                "latency_ms": round(latency_ms, 4),
                "pass": expected == actual and case.expected_level == assessment.level.value,
                "matched_rules": [finding.rule_id for finding in assessment.findings],
            }
        )

    total = len(rows)
    exact = sum(1 for row in rows if row["pass"])
    decision_exact = sum(
        1 for row in rows if row["expected_decision"] == row["actual_decision"]
    )
    block_metrics = _binary_metrics(rows, positive_decision="block")
    warn_or_block_metrics = _warn_or_block_metrics(rows)
    return {
        "dataset": str(path),
        "cases": total,
        "exact_label_accuracy": round(exact / total, 4) if total else 0.0,
        "decision_accuracy": round(decision_exact / total, 4) if total else 0.0,
        "avg_latency_ms": round(total_latency_ms / total, 4) if total else 0.0,
        "block_metrics": block_metrics,
        "warn_or_block_safety_metrics": warn_or_block_metrics,
        "confusion": confusion,
        "failures": [row for row in rows if not row["pass"]],
        "rows": rows,
    }


def _binary_metrics(rows: list[dict[str, Any]], positive_decision: str) -> dict[str, float]:
    tp = sum(
        1
        for row in rows
        if row["expected_decision"] == positive_decision
        and row["actual_decision"] == positive_decision
    )
    fp = sum(
        1
        for row in rows
        if row["expected_decision"] != positive_decision
        and row["actual_decision"] == positive_decision
    )
    fn = sum(
        1
        for row in rows
        if row["expected_decision"] == positive_decision
        and row["actual_decision"] != positive_decision
    )
    return {
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def _warn_or_block_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    unsafe = {"warn", "block"}
    tp = sum(
        1
        for row in rows
        if row["expected_decision"] in unsafe and row["actual_decision"] in unsafe
    )
    fp = sum(
        1
        for row in rows
        if row["expected_decision"] not in unsafe and row["actual_decision"] in unsafe
    )
    fn = sum(
        1
        for row in rows
        if row["expected_decision"] in unsafe and row["actual_decision"] not in unsafe
    )
    return {
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }

