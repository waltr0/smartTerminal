#!/usr/bin/env python3
"""Baseline behavior snapshot tool for CyberShell Copilot.

This is the safety net that underpins every hardening stage. It runs the
deterministic guardrail engine over the curated corpus in
``baseline/baseline_corpus.jsonl`` and records the exact decision, level,
score, and matched rules for each command.

Usage
-----
    python tools/baseline_snapshot.py --generate   # write baseline/behavior_snapshot.json
    python tools/baseline_snapshot.py --check       # diff current behavior vs the snapshot

``--check`` exit codes:
    0  no drift, OR only ``known_issue`` entries changed (expected progress)
    1  a ``lock_block``/``lock_allow`` invariant drifted (a real regression), or
       the snapshot file is missing / out of date for invariant entries

Run with ``PYTHONPATH=src`` so the ``cybershell`` package is importable.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "baseline" / "baseline_corpus.jsonl"
SNAPSHOT_PATH = REPO_ROOT / "baseline" / "behavior_snapshot.json"

# Make src/ importable whether or not PYTHONPATH was set.
SRC = REPO_ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cybershell.models import ShellContext  # noqa: E402
from cybershell.policy import PolicyRegistry  # noqa: E402
from cybershell.risk import GuardrailEngine  # noqa: E402


def load_corpus() -> list[dict]:
    entries: list[dict] = []
    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Bad corpus row {line_number}: {exc}") from exc
    return entries


def assess_entry(engine: GuardrailEngine, policies: PolicyRegistry, entry: dict) -> dict:
    policy = policies.get(entry.get("mode", "soc"))
    context = ShellContext(
        partial_command=entry["command"],
        cwd=entry.get("cwd", "."),
        is_root=bool(entry.get("is_root", False)),
    )
    assessment = engine.assess(entry["command"], context, policy)
    return {
        "id": entry["id"],
        "command": entry["command"],
        "mode": entry.get("mode", "soc"),
        "expectation": entry["expectation"],
        "decision": assessment.decision.value,
        "level": assessment.level.value,
        "score": assessment.score,
        "matched_rules": sorted(f.rule_id for f in assessment.findings),
    }


def compute_current() -> list[dict]:
    engine = GuardrailEngine.packaged()
    policies = PolicyRegistry.packaged()
    corpus = load_corpus()
    return [assess_entry(engine, policies, entry) for entry in corpus]


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
    except Exception:  # pragma: no cover - git optional
        return "unknown"


def generate() -> int:
    rows = compute_current()
    payload = {
        "schema": "cybershell-behavior-snapshot/1",
        "git_commit": _git_commit(),
        "corpus": str(CORPUS_PATH.relative_to(REPO_ROOT)),
        "count": len(rows),
        "rows": {row["id"]: row for row in rows},
    }
    SNAPSHOT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote snapshot for {len(rows)} commands -> {SNAPSHOT_PATH.relative_to(REPO_ROOT)}")
    return 0


_REQUIRED_DECISION = {"lock_block": "block", "lock_allow": "allow", "lock_warn": "warn"}


def check() -> int:
    if not SNAPSHOT_PATH.exists():
        print("No snapshot found. Run: python tools/baseline_snapshot.py --generate", file=sys.stderr)
        return 1
    saved = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))["rows"]
    current = {row["id"]: row for row in compute_current()}

    invariant_regressions: list[str] = []
    tracked_changes: list[str] = []

    for entry_id, now in current.items():
        before = saved.get(entry_id)
        required = _REQUIRED_DECISION.get(now["expectation"])

        # A locked invariant regresses only when its decision leaves the locked
        # state. Score / level / matched-rule drift while the decision holds is
        # expected during refactoring and is reported as informational only.
        if required is not None and now["decision"] != required:
            invariant_regressions.append(
                f"  ! {entry_id} [{now['expectation']}]: decision is "
                f"{now['decision']}, must be {required}  ({now['command']})"
            )

        if before is None:
            tracked_changes.append(f"  + NEW {entry_id}: {now['decision']}/{now['level']} score={now['score']}")
            continue
        if (now["decision"], now["level"], now["score"], now["matched_rules"]) != (
            before["decision"],
            before["level"],
            before["score"],
            before["matched_rules"],
        ):
            tracked_changes.append(
                f"  ~ {entry_id} [{now['expectation']}]: "
                f"{before['decision']}/{before['level']}/score={before['score']} "
                f"-> {now['decision']}/{now['level']}/score={now['score']}  ({now['command']})"
            )

    if tracked_changes:
        print("Tracked changes (decision-preserving drift or known_issue progress):")
        print("\n".join(tracked_changes))
    if invariant_regressions:
        print("\nINVARIANT REGRESSIONS — a locked decision changed:")
        print("\n".join(invariant_regressions))
        return 1
    if not tracked_changes:
        print("No drift: every corpus command behaves exactly as snapshotted.")
    else:
        print("\nNo invariant regressions. Re-run --generate to re-baseline once changes are reviewed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberShell baseline behavior snapshot tool.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--generate", action="store_true", help="Write the behavior snapshot.")
    group.add_argument("--check", action="store_true", help="Diff current behavior vs the snapshot.")
    args = parser.parse_args(argv)
    return generate() if args.generate else check()


if __name__ == "__main__":
    raise SystemExit(main())
