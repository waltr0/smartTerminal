"""Knowledge-base quality gate.

Every packaged command must be well-formed and -- most importantly -- must not be
something the guardrail engine would itself block. A suggestion the tool would
refuse to display is a knowledge-base bug, so this test makes that impossible to
ship. It also enforces the schema so future batches stay consistent.
"""
from __future__ import annotations

import re
import unittest

from cybershell.kb import CommandKnowledgeBase
from cybershell.models import Decision, ShellContext
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine

REQUIRED_TEXT_FIELDS = ("id", "command", "description", "domain", "mitre_tactic")
ALLOWED_RISK_LEVELS = {"safe", "caution", "dangerous"}
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


class KnowledgeBaseQualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.records = CommandKnowledgeBase.packaged().records
        cls.engine = GuardrailEngine.packaged()
        cls.policy = PolicyRegistry.packaged().get("soc")

    def _command(self, record) -> str:
        return getattr(record, "command", None) or record["command"]

    def _field(self, record, name: str):
        return getattr(record, name, None) if not isinstance(record, dict) else record.get(name)

    def test_dataset_is_substantive(self) -> None:
        self.assertGreaterEqual(len(self.records), 100)

    def test_required_fields_present_and_nonempty(self) -> None:
        for record in self.records:
            for field in REQUIRED_TEXT_FIELDS:
                value = self._field(record, field)
                with self.subTest(record=self._field(record, "id"), field=field):
                    self.assertTrue(value and str(value).strip())

    def test_tags_present(self) -> None:
        for record in self.records:
            tags = self._field(record, "tags")
            with self.subTest(record=self._field(record, "id")):
                self.assertTrue(tags, "every command needs at least one tag")

    def test_risk_level_valid(self) -> None:
        for record in self.records:
            with self.subTest(record=self._field(record, "id")):
                self.assertIn(self._field(record, "risk_level"), ALLOWED_RISK_LEVELS)

    def test_mitre_technique_format(self) -> None:
        for record in self.records:
            technique = self._field(record, "mitre_technique") or ""
            with self.subTest(record=self._field(record, "id")):
                self.assertRegex(technique, MITRE_PATTERN)

    def test_ids_and_commands_unique(self) -> None:
        ids = [self._field(r, "id") for r in self.records]
        commands = [self._command(r) for r in self.records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate command ids")
        self.assertEqual(len(commands), len(set(commands)), "duplicate commands")

    def test_no_suggested_command_is_blocked(self) -> None:
        # The core safety invariant: the tool must never carry a suggestion that
        # its own guardrails would block.
        offenders = []
        for record in self.records:
            command = self._command(record)
            decision = self.engine.assess(
                command, ShellContext(partial_command=command, cwd="."), self.policy
            ).decision
            if decision == Decision.BLOCK:
                offenders.append((self._field(record, "id"), command))
        self.assertEqual(offenders, [], f"blocked suggestions in KB: {offenders}")


if __name__ == "__main__":
    unittest.main()
