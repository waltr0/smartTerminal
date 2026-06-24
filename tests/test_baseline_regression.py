"""Baseline regression tests — the invariants every hardening stage must preserve.

These lock the two properties that must never break while CyberShell is hardened:
  * commands tagged ``lock_block`` in baseline/baseline_corpus.jsonl always block, and
  * commands tagged ``lock_allow`` always allow.

``known_issue`` entries are intentionally NOT asserted for correctness here (their
current behavior is wrong by design and will change in a later stage); instead this
file asserts that each known_issue still reproduces its *documented* current behavior,
so the bug stays visible until the stage that fixes it promotes the entry to a lock.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from cybershell.models import ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine

REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "baseline" / "baseline_corpus.jsonl"


def _load_corpus() -> list[dict]:
    rows: list[dict] = []
    with CORPUS_PATH.open("r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            rows.append(json.loads(line))
    return rows


class BaselineRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = GuardrailEngine.packaged()
        cls.policies = PolicyRegistry.packaged()
        cls.corpus = _load_corpus()
        cls.assertTrue(cls.corpus, "baseline corpus is empty")

    def _decision(self, entry: dict) -> str:
        policy = self.policies.get(entry.get("mode", "soc"))
        context = ShellContext(
            partial_command=entry["command"],
            cwd=entry.get("cwd", "."),
            is_root=bool(entry.get("is_root", False)),
        )
        return self.engine.assess(entry["command"], context, policy).decision.value

    def test_corpus_has_all_three_categories(self) -> None:
        kinds = {row["expectation"] for row in self.corpus}
        self.assertEqual(kinds, {"lock_block", "lock_allow", "known_issue"})

    def test_lock_block_invariants_hold(self) -> None:
        for entry in self.corpus:
            if entry["expectation"] != "lock_block":
                continue
            with self.subTest(id=entry["id"], command=entry["command"]):
                self.assertEqual(
                    self._decision(entry), "block",
                    f"{entry['id']} must always block: {entry['command']}",
                )

    def test_lock_allow_invariants_hold(self) -> None:
        for entry in self.corpus:
            if entry["expectation"] != "lock_allow":
                continue
            with self.subTest(id=entry["id"], command=entry["command"]):
                self.assertEqual(
                    self._decision(entry), "allow",
                    f"{entry['id']} must always allow: {entry['command']}",
                )

    def test_known_issues_still_reproduce_documented_behavior(self) -> None:
        # When a stage fixes one of these, promote it to lock_block/lock_allow and
        # update the corpus; this test will then guard the corrected behavior.
        for entry in self.corpus:
            if entry["expectation"] != "known_issue":
                continue
            with self.subTest(id=entry["id"], command=entry["command"]):
                self.assertIn("target_decision", entry, f"{entry['id']} must declare a target_decision")
                self.assertIn("target_stage", entry, f"{entry['id']} must declare a target_stage")
                self.assertEqual(
                    self._decision(entry), entry["current_decision"],
                    f"{entry['id']} no longer matches its documented current behavior; "
                    f"if this was fixed, promote it to a lock_* entry.",
                )


if __name__ == "__main__":
    unittest.main()
