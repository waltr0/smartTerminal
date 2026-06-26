from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any

from cybershell.models import Suggestion
from cybershell.text import normalize_space


class PrefixCache:
    """Small LRU cache for accepted command completions."""

    def __init__(self, max_entries: int = 1000, path: Path | None = None) -> None:
        self.max_entries = max_entries
        self.path = path
        self._items: OrderedDict[str, dict[str, Any]] = OrderedDict()
        if path and path.exists():
            self.load(path)

    def lookup(self, partial: str) -> Suggestion | None:
        key = normalize_space(partial)
        if not key or key not in self._items:
            return None
        item = self._items.pop(key)
        self._items[key] = item
        suggested = str(item["suggested_command"])
        completion = suggested[len(partial) :] if suggested.startswith(partial) else ""
        return Suggestion(
            suggested_command=suggested,
            completion=completion,
            source="prefix-cache",
            confidence=float(item.get("confidence", 0.95)),
            explanation="Previously accepted command pattern from the local cache.",
            retrieved_id=str(item.get("record_id") or "") or None,
        )

    def update(self, partial: str, suggestion: Suggestion) -> None:
        key = normalize_space(partial)
        if not key:
            return
        current = self._items.pop(key, {})
        acceptance_count = int(current.get("acceptance_count", 0)) + 1
        confidence = min(0.99, float(current.get("confidence", 0.82)) + 0.03)
        self._items[key] = {
            "suggested_command": suggestion.suggested_command,
            "confidence": confidence,
            "acceptance_count": acceptance_count,
            "record_id": suggestion.retrieved_id,
        }
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)

    def load(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A corrupt or unreadable cache must never crash the tool; start fresh.
            self._items.clear()
            return
        if not isinstance(raw, dict):
            self._items.clear()
            return
        self._items.clear()
        for key, value in raw.get("items", {}).items():
            if isinstance(value, dict) and "suggested_command" in value:
                self._items[key] = value

    def save(self, path: Path | None = None) -> None:
        target = path or self.path
        if target is None:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"items": dict(self._items)}
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")

