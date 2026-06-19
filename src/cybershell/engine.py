from __future__ import annotations

from pathlib import Path

from cybershell.audit import AuditLog
from cybershell.cache import PrefixCache
from cybershell.kb import CommandKnowledgeBase
from cybershell.models import (
    Decision,
    ShellContext,
    Suggestion,
    SuggestionResult,
    SuggestionStatus,
)
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine
from cybershell.text import normalize_space, tokenize


class SuggestionEngine:
    def __init__(
        self,
        kb: CommandKnowledgeBase | None = None,
        guardrails: GuardrailEngine | None = None,
        cache: PrefixCache | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.kb = kb or CommandKnowledgeBase.packaged()
        self.guardrails = guardrails or GuardrailEngine.packaged()
        self.cache = cache or PrefixCache()
        self.audit_log = audit_log
        self.policies = PolicyRegistry.packaged()

    @classmethod
    def packaged(
        cls, cache_path: Path | None = None, audit_path: Path | None = None
    ) -> "SuggestionEngine":
        cache = PrefixCache(path=cache_path) if cache_path else PrefixCache()
        audit = AuditLog(audit_path) if audit_path else None
        return cls(cache=cache, audit_log=audit)

    def suggest(self, context: ShellContext, mode: str = "soc") -> SuggestionResult:
        policy = self.policies.get(mode)
        current_risk = self.guardrails.assess(context.partial_command, context, policy)
        normalized_partial = normalize_space(context.partial_command)
        if not normalized_partial:
            result = SuggestionResult(
                context=context,
                suggestion=None,
                risk=current_risk,
                mode=mode,
                status=SuggestionStatus.CLARIFY,
                message=(
                    "Type a command prefix or a defensive cybersecurity intent, "
                    "for example: ss, ssh logs, docker containers, or firewall status."
                ),
            )
            self._audit(result)
            return result

        if current_risk.decision == Decision.BLOCK:
            result = SuggestionResult(
                context=context,
                suggestion=None,
                risk=current_risk,
                mode=mode,
                status=SuggestionStatus.BLOCKED,
                message="This request was blocked by the active CyberShell safety policy.",
            )
            self._audit(result)
            return result

        cached = self.cache.lookup(context.partial_command)
        if cached:
            result = self._result_for_candidate(context, cached, mode)
            self._audit(result)
            return result

        if self._needs_scope_before_retrieval(normalized_partial):
            result = SuggestionResult(
                context=context,
                suggestion=None,
                risk=current_risk,
                mode=mode,
                status=SuggestionStatus.CLARIFY,
                message=(
                    "This request is too broad to answer safely. Include the "
                    "target and scope, such as 'scan localhost services', "
                    "'scan 10.0.0.5 top ports', or 'scan this repository for secrets'."
                ),
            )
            self._audit(result)
            return result

        suggestion = self._retrieve_safe_suggestion(context, mode)
        if suggestion is None:
            status, message = self._fallback_status(normalized_partial)
            result = SuggestionResult(
                context=context,
                suggestion=None,
                risk=current_risk,
                mode=mode,
                status=status,
                message=message,
            )
            self._audit(result)
            return result

        result = self._result_for_candidate(context, suggestion, mode)
        self._audit(result)
        return result

    def assess(self, command: str, context: ShellContext | None = None, mode: str = "soc"):
        return self.guardrails.assess(command, context, self.policies.get(mode))

    def accept(self, partial: str, suggestion: Suggestion) -> None:
        self.cache.update(partial, suggestion)
        self.cache.save()

    def _retrieve_safe_suggestion(self, context: ShellContext, mode: str) -> Suggestion | None:
        policy = self.policies.get(mode)
        hits = self.kb.retrieve(context, top_k=5)
        for hit in hits:
            suggestion = self.kb.suggest_from_hit(context.partial_command, hit)
            risk = self.guardrails.assess(suggestion.suggested_command, context, policy)
            if risk.decision != Decision.BLOCK:
                return suggestion
        return None

    def _result_for_candidate(
        self, context: ShellContext, suggestion: Suggestion, mode: str
    ) -> SuggestionResult:
        policy = self.policies.get(mode)
        risk = self.guardrails.assess(suggestion.suggested_command, context, policy)
        if risk.decision == Decision.BLOCK:
            return SuggestionResult(
                context=context,
                suggestion=None,
                risk=risk,
                mode=mode,
                status=SuggestionStatus.BLOCKED,
                message="The candidate command was suppressed because it violates policy.",
            )
        return SuggestionResult(
            context=context,
            suggestion=suggestion,
            risk=risk,
            mode=mode,
            status=SuggestionStatus.ANSWERED,
            message="Safe candidate generated from packaged knowledge.",
        )

    def _audit(self, result: SuggestionResult) -> None:
        if self.audit_log:
            self.audit_log.write_result(result)

    def _fallback_status(self, partial: str) -> tuple[SuggestionStatus, str]:
        tokens = set(tokenize(partial))
        broad_terms = {
            "audit",
            "check",
            "container",
            "containers",
            "docker",
            "firewall",
            "k8s",
            "kubernetes",
            "logs",
            "network",
            "permissions",
            "ports",
            "process",
            "processes",
            "scan",
            "services",
            "show",
            "users",
        }
        if len(tokens) <= 2 and tokens & broad_terms:
            return (
                SuggestionStatus.CLARIFY,
                (
                    "I need one more detail before suggesting a command. Include the "
                    "target, scope, or defensive goal, such as 'ssh logs', "
                    "'docker containers', or 'scan localhost services'."
                ),
            )
        return (
            SuggestionStatus.UNSUPPORTED,
            (
                "I could not map this request to a packaged safe command. Rephrase "
                "with the system, target, and defensive goal, or run kb-search to "
                "inspect available command domains."
            ),
        )

    def _needs_scope_before_retrieval(self, partial: str) -> bool:
        tokens = tokenize(partial)
        if len(tokens) != 1:
            return False
        return tokens[0] in {
            "audit",
            "check",
            "inspect",
            "list",
            "review",
            "scan",
            "show",
        }
