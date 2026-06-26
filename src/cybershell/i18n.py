"""Lightweight message-catalog scaffold for future internationalization.

This provides the *mechanism* for translating user-facing strings and a safe
English fallback, so localization can be adopted incrementally. The bulk of the
codebase's strings (rule messages, CLI output) are **not yet routed through this
helper** -- see docs/I18N.md for the migration plan. Until they are, CyberShell is
effectively English-only; this module exists so that work has a defined, tested
entry point rather than starting from scratch.

Usage:

    from cybershell.i18n import translate as _
    print(_("cli.safe_summary"))
    print(_("cli.blocked_prefix", reason="reverse shell"))

The active locale is read from the ``CYBERSHELL_LOCALE`` environment variable and
defaults to English. Unknown keys fall back to the key itself, so a missing
translation never crashes or blanks the output.
"""
from __future__ import annotations

import json
import os
from functools import cache
from importlib.resources import files

DEFAULT_LOCALE = "en"


@cache
def _load_catalog(locale: str) -> dict[str, str]:
    try:
        resource = files("cybershell").joinpath("locale").joinpath(f"{locale}.json")
        with resource.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def active_locale() -> str:
    return os.environ.get("CYBERSHELL_LOCALE") or DEFAULT_LOCALE


def translate(key: str, /, locale: str | None = None, **kwargs: object) -> str:
    """Return the localized string for ``key``, falling back to ``key`` itself."""
    catalog = _load_catalog(locale or active_locale())
    template = catalog.get(key, key)
    if kwargs:
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return template
    return template


# Conventional gettext-style alias.
_ = translate
