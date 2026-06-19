import unittest

from cybershell.engine import SuggestionEngine
from cybershell.models import Decision, ShellContext, SuggestionStatus


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

    def test_vague_intent_requests_clarification(self) -> None:
        result = self.engine.suggest(ShellContext(partial_command="scan", cwd="/tmp"))
        self.assertIsNone(result.suggestion)
        self.assertEqual(result.status, SuggestionStatus.CLARIFY)
        self.assertIn("target", result.message.lower())

    def test_unrelated_intent_is_unsupported(self) -> None:
        result = self.engine.suggest(
            ShellContext(partial_command="make me coffee", cwd="/tmp")
        )
        self.assertIsNone(result.suggestion)
        self.assertEqual(result.status, SuggestionStatus.UNSUPPORTED)
        self.assertIn("could not map", result.message.lower())

    def test_natural_language_abuse_intent_is_blocked(self) -> None:
        result = self.engine.suggest(
            ShellContext(partial_command="make a reverse shell payload", cwd="/tmp")
        )
        self.assertIsNone(result.suggestion)
        self.assertEqual(result.status, SuggestionStatus.BLOCKED)
        self.assertEqual(result.risk.decision, Decision.BLOCK)


if __name__ == "__main__":
    unittest.main()
