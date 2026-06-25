"""Stage 3 regression tests: expanded coverage and an honest benchmark.

Locks the new attacker-pattern rules, the tightened archive rule (so project
backups are not false-positived), and the credibility guarantees of the rebuilt
benchmark: zero false positives, perfect accuracy on what we claim to handle,
and documented limitations surfaced rather than hidden.
"""
from __future__ import annotations

import unittest
from importlib.resources import as_file, files
from pathlib import Path

from cybershell.benchmark import evaluate_benchmark
from cybershell.models import Decision, ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine


class ExpandedRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()
        self.policy = PolicyRegistry.packaged().get("soc")

    def decide(self, command: str, cwd: str = ".") -> Decision:
        ctx = ShellContext(partial_command=command, cwd=cwd)
        return self.engine.assess(command, ctx, self.policy).decision

    def test_new_attacker_patterns_are_flagged(self) -> None:
        for command in (
            "history -c",
            "cat ~/.aws/credentials",
            "curl http://169.254.169.254/latest/meta-data/",
            "gcore -o /tmp/dump 1234",
            "journalctl --vacuum-time=1s",
            "echo '* * * * * /tmp/x' | crontab -",
        ):
            with self.subTest(command=command):
                self.assertIn(self.decide(command), {Decision.WARN, Decision.BLOCK})

    def test_recursive_world_writable_on_system_path_blocks(self) -> None:
        self.assertEqual(self.decide("chmod -R 777 /etc"), Decision.BLOCK)

    def test_sudo_wrapped_destructive_command_is_still_tiered(self) -> None:
        # sudo must not be a blind spot for target-aware scoring.
        self.assertEqual(self.decide("sudo rm -rf ~"), Decision.BLOCK)
        self.assertEqual(self.decide("sudo rm -rf /home/alice"), Decision.BLOCK)

    def test_archive_rule_does_not_flag_project_backups(self) -> None:
        self.assertEqual(
            self.decide("tar czf backup.tar.gz /home/u/project"), Decision.ALLOW
        )
        self.assertEqual(self.decide("tar czf project.tgz ./src"), Decision.ALLOW)

    def test_archive_rule_flags_sensitive_targets(self) -> None:
        self.assertEqual(self.decide("tar czf /tmp/etc.tgz /etc"), Decision.WARN)
        self.assertEqual(self.decide("tar czf keys.tgz ~/.ssh"), Decision.WARN)

    def test_crontab_list_is_not_flagged(self) -> None:
        # Listing cron (a defensive audit command) must stay allowed.
        self.assertEqual(self.decide("crontab -l"), Decision.ALLOW)


class BenchmarkCredibilityTests(unittest.TestCase):
    def _report(self):
        resource = files("cybershell").joinpath("data", "cybershell_bench.jsonl")
        with as_file(resource) as path:
            return evaluate_benchmark(path)

    def test_dataset_is_substantive(self) -> None:
        report = self._report()
        self.assertGreaterEqual(report["cases"], 100)
        self.assertGreater(report["suggestion_cases"], 0)

    def test_zero_false_positives_on_safe_commands(self) -> None:
        report = self._report()
        self.assertGreaterEqual(report["false_positive_rate"]["safe_cases"], 50)
        self.assertEqual(report["false_positive_rate"]["rate"], 0.0)

    def test_perfect_core_accuracy_and_no_unexpected_failures(self) -> None:
        report = self._report()
        self.assertEqual(report["core_accuracy"], 1.0)
        self.assertEqual(report["failures"], [])

    def test_limitations_are_documented_not_hidden(self) -> None:
        report = self._report()
        self.assertGreater(len(report["known_limitations"]), 0)
        # Honest overall accuracy counts the documented misses against us.
        self.assertLess(report["overall_accuracy"], 1.0)

    def test_packaged_and_repo_datasets_match(self) -> None:
        packaged = files("cybershell").joinpath("data", "cybershell_bench.jsonl")
        with as_file(packaged) as path:
            packaged_text = Path(path).read_text(encoding="utf-8")
        repo_path = Path(__file__).resolve().parents[1] / "benchmarks" / "cybershell_bench.jsonl"
        self.assertEqual(packaged_text, repo_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
