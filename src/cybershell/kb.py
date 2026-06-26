from __future__ import annotations

from dataclasses import dataclass

from cybershell.data_loader import load_json_resource
from cybershell.models import CommandRecord, ShellContext, Suggestion
from cybershell.text import normalize_space, tokenize

MIN_RETRIEVAL_SCORE = 1.0


@dataclass(slots=True)
class RetrievalHit:
    record: CommandRecord
    score: float


class CommandKnowledgeBase:
    """Dependency-free command retrieval backend.

    The production architecture can replace this class with FAISS without
    changing the engine contract. This implementation keeps the project
    installable and testable on a fresh machine.
    """

    def __init__(self, records: list[CommandRecord]) -> None:
        self.records = records
        self._token_index: dict[str, set[str]] = {}
        self._by_id = {record.id: record for record in records}
        self._record_tokens = {
            record.id: set(
                tokenize(
                    " ".join(
                        [
                            record.command,
                            record.description,
                            record.domain,
                            " ".join(record.tags),
                            " ".join(record.examples),
                        ]
                    )
                )
            )
            for record in records
        }
        for record_id, tokens in self._record_tokens.items():
            for token in tokens:
                self._token_index.setdefault(token, set()).add(record_id)

    @classmethod
    def packaged(cls) -> CommandKnowledgeBase:
        raw = load_json_resource("command_kb.json")
        return cls([CommandRecord.from_dict(item) for item in raw["commands"]])

    def retrieve(self, context: ShellContext, top_k: int = 3) -> list[RetrievalHit]:
        partial = normalize_space(context.partial_command)
        query_parts = [
            partial,
            " ".join(context.history[-5:]),
            " ".join(f"{key}={value}" for key, value in context.env.items()),
        ]
        cwd = normalize_space(context.cwd)
        if cwd and cwd not in {".", "/"}:
            query_parts.append(cwd)
        query = " ".join(query_parts)
        query_tokens = set(tokenize(query))
        if not query_tokens and not partial:
            return []

        candidates: set[str] = set()
        for token in query_tokens:
            candidates.update(self._token_index.get(token, set()))
        if partial:
            partial_lower = partial.lower()
            for record in self.records:
                command_tokens = tokenize(record.command)
                if record.command.lower().startswith(partial_lower) or any(
                    token.startswith(partial_lower) for token in command_tokens
                ):
                    candidates.add(record.id)
        if not candidates:
            return []

        hits: list[RetrievalHit] = []
        for record_id in candidates:
            record = self._by_id[record_id]
            score = self._score_record(record, query_tokens, partial)
            if score >= MIN_RETRIEVAL_SCORE:
                hits.append(RetrievalHit(record=record, score=score))
        hits.sort(key=lambda hit: hit.score, reverse=True)
        return hits[:top_k]

    def suggest_from_hit(self, partial: str, hit: RetrievalHit) -> Suggestion:
        candidate = hit.record.command
        normalized_partial = normalize_space(partial)
        completion = ""
        confidence = min(0.98, 0.52 + hit.score / 18.0)
        if normalized_partial and candidate.startswith(normalized_partial):
            completion = candidate[len(normalized_partial) :]
            confidence = min(0.99, confidence + 0.18)
        elif normalized_partial:
            completion = ""
        else:
            completion = candidate

        explanation = f"{hit.record.description} Domain: {hit.record.domain}."
        if hit.record.mitre_tactic:
            explanation += f" ATT&CK-style tactic: {hit.record.mitre_tactic}."

        return Suggestion(
            suggested_command=candidate,
            completion=completion,
            source="knowledge-base",
            confidence=round(confidence, 3),
            explanation=explanation,
            retrieved_id=hit.record.id,
        )

    def _score_record(
        self, record: CommandRecord, query_tokens: set[str], partial: str
    ) -> float:
        command = record.command.lower()
        partial = partial.lower().strip()
        record_tokens = self._record_tokens[record.id]
        overlap = len(query_tokens & record_tokens)
        score = float(overlap)

        if partial:
            if command.startswith(partial):
                score += 8.0
            else:
                partial_tokens = tokenize(partial)
                command_tokens = tokenize(record.command)
                if partial_tokens and any(
                    token.startswith(partial_tokens[-1]) for token in command_tokens
                ):
                    score += 5.0
                if partial_tokens and command.startswith(partial_tokens[0]):
                    score += 3.0
                if partial_tokens and partial_tokens[0] in record.tags:
                    score += 2.0
        if record.risk_level == "safe":
            score += 0.4
        elif record.risk_level == "caution":
            score -= 0.8
        else:
            score -= 2.0
        return score
