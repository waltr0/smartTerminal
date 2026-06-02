from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath

from cybershell.alternatives import safe_alternatives
from cybershell.data_loader import load_json_resource
from cybershell.models import Decision, RiskAssessment, RiskFinding, RiskLevel, ShellContext
from cybershell.policy import Policy, PolicyRegistry


@dataclass(slots=True)
class GuardrailRule:
    id: str
    pattern: re.Pattern[str]
    category: str
    weight: int
    severity: str
    message: str
    mitre_tactic: str | None = None
    mitre_technique: str | None = None


DEFAULT_POLICY = PolicyRegistry.packaged().get("soc")


class GuardrailEngine:
    """Deterministic final authority for command safety decisions."""

    def __init__(self, rules: list[GuardrailRule]) -> None:
        self.rules = rules

    @classmethod
    def packaged(cls) -> "GuardrailEngine":
        raw = load_json_resource("guardrail_rules.json")
        rules = []
        for item in raw["rules"]:
            flags = re.IGNORECASE
            rules.append(
                GuardrailRule(
                    id=item["id"],
                    pattern=re.compile(item["pattern"], flags),
                    category=item["category"],
                    weight=int(item["weight"]),
                    severity=item.get("severity", "warn"),
                    message=item["message"],
                    mitre_tactic=item.get("mitre_tactic"),
                    mitre_technique=item.get("mitre_technique"),
                )
            )
        return cls(rules)

    def assess(
        self,
        command: str,
        context: ShellContext | None = None,
        policy: Policy | None = None,
    ) -> RiskAssessment:
        active_policy = policy or DEFAULT_POLICY
        normalized = command.strip()
        findings: list[RiskFinding] = []
        score = 0

        if not normalized:
            return RiskAssessment(
                command=command,
                score=0,
                level=RiskLevel.SAFE,
                decision=Decision.ALLOW,
                findings=[],
                safe_alternatives=[],
                summary="No command was provided.",
            )

        for rule in self.rules:
            match = rule.pattern.search(normalized)
            if not match:
                continue
            evidence = match.group(0)
            adjusted_weight = self._policy_weight(rule.weight, rule.category, active_policy)
            score += adjusted_weight
            findings.append(
                RiskFinding(
                    rule_id=rule.id,
                    category=rule.category,
                    weight=adjusted_weight,
                    severity=rule.severity,
                    message=rule.message,
                    evidence=evidence,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                )
            )

        syntax_finding = self._syntax_check(normalized)
        if syntax_finding:
            syntax_finding = self._with_policy_weight(syntax_finding, active_policy)
            score += syntax_finding.weight
            findings.append(syntax_finding)

        if context is not None:
            contextual_findings = self._contextual_checks(normalized, context)
            for finding in contextual_findings:
                finding = self._with_policy_weight(finding, active_policy)
                score += finding.weight
                findings.append(finding)

        if self._must_block(findings, active_policy) or score >= active_policy.block_threshold:
            level = RiskLevel.BLOCKED
            decision = Decision.BLOCK
        elif score >= active_policy.dangerous_threshold:
            level = RiskLevel.DANGEROUS
            decision = Decision.WARN
        elif score >= active_policy.caution_threshold:
            level = RiskLevel.CAUTION
            decision = Decision.WARN
        else:
            level = RiskLevel.SAFE
            decision = Decision.ALLOW

        alternatives = safe_alternatives(normalized, findings) if decision != Decision.ALLOW and findings else []
        summary = self._summary(level, findings)
        return RiskAssessment(
            command=normalized,
            score=score,
            level=level,
            decision=decision,
            findings=findings,
            safe_alternatives=alternatives,
            summary=summary,
        )

    def _syntax_check(self, command: str) -> RiskFinding | None:
        try:
            shlex.split(command, posix=True)
            return None
        except ValueError as exc:
            return RiskFinding(
                rule_id="syntax.unbalanced_shell",
                category="syntax",
                weight=18,
                severity="warn",
                message="The command has malformed shell quoting or escaping.",
                evidence=str(exc),
                mitre_tactic=None,
                mitre_technique=None,
            )

    def _contextual_checks(
        self, command: str, context: ShellContext
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        cwd = (context.cwd or "").rstrip("/")
        argv = self._split_command(command)
        head = argv[0] if argv else ""
        mutating_heads = {"rm", "mv", "cp", "chmod", "chown", "dd", "mkfs", "wipefs", "shred"}

        if context.is_root and head in mutating_heads:
            findings.append(
                RiskFinding(
                    rule_id="context.root_mutation",
                    category="privilege_escalation",
                    weight=16,
                    severity="warn",
                    message="Mutating command is being prepared from a root shell context.",
                    evidence=context.user or "root",
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1548",
                )
            )

        sensitive_targets = self._sensitive_targets(argv, cwd)
        if sensitive_targets and head in mutating_heads:
            findings.append(
                RiskFinding(
                    rule_id="context.sensitive_target",
                    category="destructive_filesystem",
                    weight=20,
                    severity="warn",
                    message="The command targets a system-sensitive path.",
                    evidence=", ".join(sensitive_targets[:3]),
                    mitre_tactic="Impact",
                    mitre_technique="T1485",
                )
            )

        if context.last_exit_status not in (None, 0) and head in {"rm", "mv", "chmod", "chown"}:
            findings.append(
                RiskFinding(
                    rule_id="context.failed_previous_command",
                    category="operational_safety",
                    weight=8,
                    severity="warn",
                    message="The previous command failed; destructive follow-up commands should be double-checked.",
                    evidence=str(context.last_exit_status),
                )
            )

        if self._has_secret_env_indicator(context) and head in {"env", "printenv", "set", "export"}:
            findings.append(
                RiskFinding(
                    rule_id="context.secret_env_dump",
                    category="secrets_access",
                    weight=22,
                    severity="warn",
                    message="The environment appears to contain secret-like variables; dumping it may expose credentials.",
                    evidence="secret-like environment key",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1552",
                )
            )

        if self._is_kubernetes_context(context) and "secret" in command.lower():
            findings.append(
                RiskFinding(
                    rule_id="context.kubernetes_secret_context",
                    category="secrets_access",
                    weight=12,
                    severity="warn",
                    message="Kubernetes context is active while the command references secrets.",
                    evidence="KUBECONFIG/context",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1552",
                )
            )

        if self._redirects_to_sensitive_path(argv, cwd):
            findings.append(
                RiskFinding(
                    rule_id="context.sensitive_redirection",
                    category="persistence",
                    weight=28,
                    severity="warn",
                    message="Command redirects output into a sensitive or persistence-related path.",
                    evidence=command,
                    mitre_tactic="Persistence",
                    mitre_technique="T1053",
                )
            )
        return findings

    def _summary(self, level: RiskLevel, findings: list[RiskFinding]) -> str:
        if not findings:
            return "No guardrail patterns matched; command appears safe for display."
        if level == RiskLevel.SAFE:
            return "Low-scoring guardrail findings matched, but policy thresholds allow the command."
        top = sorted(findings, key=lambda item: item.weight, reverse=True)[:2]
        reasons = "; ".join(finding.message for finding in top)
        if level == RiskLevel.BLOCKED:
            return f"Blocked because high-risk guardrails matched: {reasons}"
        if level == RiskLevel.DANGEROUS:
            return f"Dangerous command; require explicit review: {reasons}"
        return f"Caution recommended: {reasons}"

    def _policy_weight(self, weight: int, category: str, policy: Policy) -> int:
        multiplier = policy.category_multipliers.get(category, 1.0)
        return max(1, int(round(weight * multiplier)))

    def _with_policy_weight(self, finding: RiskFinding, policy: Policy) -> RiskFinding:
        finding.weight = self._policy_weight(finding.weight, finding.category, policy)
        return finding

    def _must_block(self, findings: list[RiskFinding], policy: Policy) -> bool:
        for finding in findings:
            if finding.severity == "block":
                return True
            if policy.category_floor_decisions.get(finding.category) == "block":
                return True
        return False

    def _split_command(self, command: str) -> list[str]:
        try:
            return shlex.split(command, posix=True)
        except ValueError:
            return command.split()

    def _sensitive_targets(self, argv: list[str], cwd: str) -> list[str]:
        sensitive = (
            "/",
            "/etc",
            "/boot",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/var/log",
            "/root",
            "/home",
            "/.ssh",
        )
        targets: list[str] = []
        for token in argv[1:]:
            if token.startswith("-") or "=" in token:
                continue
            path = self._resolve_target(token, cwd)
            if any(path == item or path.startswith(item.rstrip("/") + "/") for item in sensitive):
                targets.append(path)
        if not targets and (cwd in {"", "/"} or cwd.startswith(("/etc", "/boot", "/usr", "/var/log", "/root"))):
            targets.append(cwd or "/")
        return targets

    def _resolve_target(self, token: str, cwd: str) -> str:
        if token.startswith("~"):
            token = token.replace("~", "/home/user", 1)
        if token.startswith("/"):
            return str(PurePosixPath(token))
        base = cwd or "."
        if "\\" in base:
            return token
        return str(PurePosixPath(base) / token)

    def _has_secret_env_indicator(self, context: ShellContext) -> bool:
        markers = ("TOKEN", "SECRET", "KEY", "PASS", "CREDENTIAL")
        return any(any(marker in key.upper() for marker in markers) for key in context.env)

    def _is_kubernetes_context(self, context: ShellContext) -> bool:
        env_keys = {key.upper() for key in context.env}
        return "KUBECONFIG" in env_keys or any("kubectl" in item for item in context.history[-5:])

    def _redirects_to_sensitive_path(self, argv: list[str], cwd: str) -> bool:
        for index, token in enumerate(argv):
            if token in {">", ">>"} and index + 1 < len(argv):
                path = self._resolve_target(argv[index + 1], cwd)
                if path.startswith(("/etc/cron", "/etc/systemd", "/root/.ssh", "/home/user/.ssh")):
                    return True
            if token.startswith((">", ">>")) and len(token) > 1:
                path = self._resolve_target(token.lstrip(">"), cwd)
                if path.startswith(("/etc/cron", "/etc/systemd", "/root/.ssh", "/home/user/.ssh")):
                    return True
        return False
