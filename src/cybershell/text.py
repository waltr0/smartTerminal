from __future__ import annotations

import re
import shlex


TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def command_head(command: str) -> str:
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        parts = command.strip().split()
    return parts[0] if parts else ""


def normalize_space(text: str) -> str:
    return " ".join(text.strip().split())

