from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from typing import Any

from cybershell.kb import CommandKnowledgeBase, RetrievalHit
from cybershell.models import CommandRecord, ShellContext
from cybershell.text import tokenize


@dataclass(frozen=True, slots=True)
class BackendStatus:
    name: str
    available: bool
    import_name: str
    purpose: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "import_name": self.import_name,
            "purpose": self.purpose,
        }


OPTIONAL_BACKENDS = {
    "faiss": ("faiss", "FAISS HNSW vector retrieval"),
    "sentence-transformers": ("sentence_transformers", "local embedding model"),
    "numpy": ("numpy", "vector array operations"),
    "llama-cpp-python": ("llama_cpp", "local GGUF LLM inference"),
}


def optional_backend_status() -> list[BackendStatus]:
    statuses: list[BackendStatus] = []
    for name, (import_name, purpose) in OPTIONAL_BACKENDS.items():
        statuses.append(
            BackendStatus(
                name=name,
                import_name=import_name,
                purpose=purpose,
                available=importlib.util.find_spec(import_name) is not None,
            )
        )
    return statuses


class FaissHnswKnowledgeBase(CommandKnowledgeBase):
    """Optional FAISS HNSW retrieval backend.

    This backend is intentionally lazy-imported so the standard CyberShell
    installation remains dependency-free. Install `faiss-cpu`, `numpy`, and
    `sentence-transformers` to use it in research experiments.
    """

    def __init__(
        self,
        records: list[CommandRecord],
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        hnsw_m: int = 32,
    ) -> None:
        super().__init__(records)
        try:
            import faiss  # type: ignore
            import numpy as np  # type: ignore
            from sentence_transformers import SentenceTransformer  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "FAISS backend requires faiss-cpu, numpy, and sentence-transformers."
            ) from exc

        self._faiss = faiss
        self._np = np
        self._model = SentenceTransformer(model_name)
        self._record_ids = [record.id for record in records]
        corpus = [self._record_text(record) for record in records]
        embeddings = self._model.encode(corpus, normalize_embeddings=True)
        vectors = np.asarray(embeddings, dtype="float32")
        self._index = faiss.IndexHNSWFlat(vectors.shape[1], hnsw_m)
        self._index.hnsw.efSearch = 64
        self._index.add(vectors)

    @classmethod
    def packaged(cls) -> FaissHnswKnowledgeBase:
        raw = __import__("cybershell.data_loader", fromlist=["load_json_resource"])
        data = raw.load_json_resource("command_kb.json")
        return cls([CommandRecord.from_dict(item) for item in data["commands"]])

    def retrieve(self, context: ShellContext, top_k: int = 3) -> list[RetrievalHit]:
        query = " ".join(
            [
                context.partial_command,
                context.cwd,
                " ".join(context.history[-5:]),
                " ".join(f"{key}={value}" for key, value in context.env.items()),
            ]
        )
        if not tokenize(query):
            return []
        embedding = self._model.encode([query], normalize_embeddings=True)
        vector = self._np.asarray(embedding, dtype="float32")
        scores, indexes = self._index.search(vector, top_k)
        hits: list[RetrievalHit] = []
        for score, index in zip(scores[0], indexes[0], strict=False):
            if index < 0:
                continue
            record = self._by_id[self._record_ids[int(index)]]
            hits.append(RetrievalHit(record=record, score=float(score) * 10.0))
        return hits

    def _record_text(self, record: CommandRecord) -> str:
        return " ".join(
            [
                record.command,
                record.description,
                record.domain,
                " ".join(record.tags),
                " ".join(record.examples),
            ]
        )


class LocalGgufGenerator:
    """Optional llama.cpp wrapper for local one-command generation."""

    def __init__(self, model_path: str, n_ctx: int = 2048) -> None:
        try:
            from llama_cpp import Llama  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Local GGUF generation requires llama-cpp-python.") from exc
        self._llm = Llama(model_path=model_path, n_ctx=n_ctx, verbose=False)

    def generate(self, prompt: str, max_tokens: int = 96) -> str:
        result = self._llm(
            prompt,
            max_tokens=max_tokens,
            temperature=0.1,
            stop=["\n", "```"],
        )
        text = result["choices"][0]["text"]
        return str(text).strip().splitlines()[0].strip()

