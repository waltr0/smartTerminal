import unittest

from cybershell.engine import SuggestionEngine
from cybershell.models import Decision, ShellContext


class SuggestionEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = SuggestionEngine.packaged()

    def test_suggests_safe_command(self) -> None:
        result = self.engine.suggest(ShellContext(partial_command="ss", cwd="/tmp"))
        self.assertIsNotNone(result.suggestion)
        self.assertIn("ss", result.suggestion.suggested_command)
        self.assertNotEqual(result.risk.decision, Decision.BLOCK)

    def test_suppresses_blocked_partial(self) -> None:
        result = self.engine.suggest(ShellContext(partial_command="rm -rf /", cwd="/"))
        self.assertIsNone(result.suggestion)
        self.assertEqual(result.risk.decision, Decision.BLOCK)

    def test_returns_blue_team_suggestion_from_context(self) -> None:
        ctx = ShellContext(
            partial_command="failed",
            cwd="/var/log",
            history=["ssh root@server", "journalctl -u ssh"],
        )
        result = self.engine.suggest(ctx)
        self.assertIsNotNone(result.suggestion)
        self.assertTrue(
            "failed" in result.suggestion.suggested_command.lower()
            or "ssh" in result.suggestion.suggested_command.lower()
        )


if __name__ == "__main__":
    unittest.main()

