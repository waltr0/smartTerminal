from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cybershell.data_loader import load_json_resource


@dataclass(frozen=True, slots=True)
class Policy:
    name: str
    description: str
    caution_threshold: int
    dangerous_threshold: int
    block_threshold: int
    safe_only_suggestions: bool = False
    lab_allows_recon: bool = False
    category_multipliers: dict[str, float] = field(default_factory=dict)
    category_floor_decisions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            caution_threshold=int(data.get("caution_threshold", 10)),
            dangerous_threshold=int(data.get("dangerous_threshold", 35)),
            block_threshold=int(data.get("block_threshold", 60)),
            safe_only_suggestions=bool(data.get("safe_only_suggestions", False)),
            lab_allows_recon=bool(data.get("lab_allows_recon", False)),
            category_multipliers={
                str(key): float(value)
                for key, value in dict(data.get("category_multipliers", {})).items()
            },
            category_floor_decisions={
                str(key): str(value)
                for key, value in dict(data.get("category_floor_decisions", {})).items()
            },
        )


class PolicyRegistry:
    def __init__(self, policies: dict[str, Policy]) -> None:
        self.policies = policies

    @classmethod
    def packaged(cls) -> PolicyRegistry:
        raw = load_json_resource("policies.json")
        policies = {
            item["name"]: Policy.from_dict(item) for item in raw.get("policies", [])
        }
        return cls(policies)

    def get(self, name: str | None) -> Policy:
        key = name or "soc"
        if key not in self.policies:
            valid = ", ".join(sorted(self.policies))
            raise ValueError(f"Unknown policy mode {key!r}. Valid modes: {valid}")
        return self.policies[key]

    def names(self) -> list[str]:
        return sorted(self.policies)

