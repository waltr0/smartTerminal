"""Tests for the i18n scaffold (mechanism + safe fallback)."""
from __future__ import annotations

import unittest

from cybershell.i18n import DEFAULT_LOCALE, _load_catalog, active_locale, translate


class I18nTests(unittest.TestCase):
    def test_known_key_returns_english(self) -> None:
        self.assertEqual(
            translate("status.answered", locale="en"),
            "Safe candidate generated from packaged knowledge.",
        )

    def test_unknown_key_falls_back_to_key(self) -> None:
        self.assertEqual(translate("does.not.exist", locale="en"), "does.not.exist")

    def test_interpolation(self) -> None:
        self.assertEqual(
            translate("cli.blocked_prefix", locale="en", reason="reverse shell"),
            "Blocked: reverse shell",
        )

    def test_missing_interpolation_arg_is_safe(self) -> None:
        # A template expecting {reason} but called without it must not raise.
        self.assertEqual(translate("cli.blocked_prefix", locale="en"), "Blocked: {reason}")

    def test_unknown_locale_falls_back_gracefully(self) -> None:
        self.assertEqual(translate("status.answered", locale="zz"), "status.answered")

    def test_default_locale_and_catalog_load(self) -> None:
        self.assertEqual(DEFAULT_LOCALE, "en")
        self.assertIsInstance(active_locale(), str)
        self.assertIn("status.answered", _load_catalog("en"))


if __name__ == "__main__":
    unittest.main()
