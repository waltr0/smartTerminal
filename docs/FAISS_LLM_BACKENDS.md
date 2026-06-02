# Optional FAISS and Local LLM Backends

CyberShell's default runtime is dependency-light and deterministic. The optional
research backends are provided for experiments and ablation studies.

## Optional Dependencies

```bash
python -m pip install "cybershell-copilot[research]"
python -m pip install "cybershell-copilot[llm]"
```

From source:

```bash
python -m pip install -e ".[research,llm]"
```

## Check Backend Status

```bash
cybershell backends
cybershell backends --json
```

## FAISS HNSW Backend

`FaissHnswKnowledgeBase` lives in:

```text
src/cybershell/backends.py
```

It uses:

- `faiss-cpu`
- `numpy`
- `sentence-transformers`
- default model: `sentence-transformers/all-MiniLM-L6-v2`

The class keeps the same retrieval contract as the built-in token backend:

```python
retrieve(context, top_k=3) -> list[RetrievalHit]
```

This lets experiments compare token retrieval and vector retrieval without
changing the rest of the pipeline.

## Local GGUF LLM Backend

`LocalGgufGenerator` wraps `llama-cpp-python` for local generation.

Important safety rule:

**Generated commands must always pass through `GuardrailEngine.assess()` before
display or insertion.**

The LLM is treated as an untrusted candidate generator, not as a safety authority.

## Recommended Ablation

1. Token retrieval only.
2. FAISS retrieval only.
3. FAISS + local LLM candidate generation.
4. FAISS + local LLM + deterministic CyberShell guardrails.

