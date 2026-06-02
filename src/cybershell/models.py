from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(slots=True)
class ShellContext:
    partial_command: str
    cwd: str
    history: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    last_exit_status: int | None = None
    shell: str = "bash"
    user: str | None = None
    is_root: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CommandRecord:
    id: str
    command: str
    description: str
    domain: str
    tags: list[str]
    risk_level: str = "safe"
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    examples: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CommandRecord":
        return cls(
            id=str(data["id"]),
            command=str(data["command"]),
            description=str(data["description"]),
            domain=str(data.get("domain", "general")),
            tags=list(data.get("tags", [])),
            risk_level=str(data.get("risk_level", "safe")),
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            examples=list(data.get("examples", [])),
        )


@dataclass(slots=True)
class RiskFinding:
    rule_id: str
    category: str
    weight: int
    severity: str
    message: str
    evidence: str
    mitre_tactic: str | None = None
    mitre_technique: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RiskAssessment:
    command: str
    score: int
    level: RiskLevel
    decision: Decision
    findings: list[RiskFinding] = field(default_factory=list)
    safe_alternatives: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["level"] = self.level.value
        data["decision"] = self.decision.value
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass(slots=True)
class Suggestion:
    suggested_command: str
    completion: str
    source: str
    confidence: float
    explanation: str
    retrieved_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SuggestionResult:
    context: ShellContext
    suggestion: Suggestion | None
    risk: RiskAssessment
    mode: str = "soc"

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context.to_dict(),
            "suggestion": self.suggestion.to_dict() if self.suggestion else None,
            "risk": self.risk.to_dict(),
            "mode": self.mode,
        }

