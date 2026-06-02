from __future__ import annotations

from pathlib import Path

from cybershell.audit import AuditLog
from cybershell.cache import PrefixCache
from cybershell.kb import CommandKnowledgeBase
from cybershell.models import Decision, ShellContext, Suggestion, SuggestionResult
from cybershell.policy import PolicyRegistry
from cybershell.risk import GuardrailEngine


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
        if current_risk.decision == Decision.BLOCK:
            result = SuggestionResult(
                context=context, suggestion=None, risk=current_risk, mode=mode
            )
            self._audit(result)
            return result

        cached = self.cache.lookup(context.partial_command)
        if cached:
            result = self._result_for_candidate(context, cached, mode)
            self._audit(result)
            return result

        suggestion = self._retrieve_safe_suggestion(context, mode)
        if suggestion is None:
            result = SuggestionResult(
                context=context, suggestion=None, risk=current_risk, mode=mode
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
            return SuggestionResult(context=context, suggestion=None, risk=risk, mode=mode)
        return SuggestionResult(
            context=context, suggestion=suggestion, risk=risk, mode=mode
        )

    def _audit(self, result: SuggestionResult) -> None:
        if self.audit_log:
            self.audit_log.write_result(result)
