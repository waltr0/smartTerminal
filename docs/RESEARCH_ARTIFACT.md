# Research Artifact: CyberShell Copilot

CyberShell Copilot can be positioned as an IEEE-style research artifact:

**Title direction:** Offline ATT&CK-Aware Secure Terminal Copilot for Linux
Incident Response and Risk-Aware Command Recommendation.

## Core Research Problem

Linux operators frequently execute high-impact terminal commands under time
pressure. Traditional shell completion is prefix-based and does not reason about
cyber risk, system context, adversary behavior, or safer alternatives. General
LLM command assistants can generate useful commands but may hallucinate or
suggest dangerous behavior without deterministic validation.

CyberShell studies whether an offline, explainable, policy-aware assistant can
recommend useful defensive commands while suppressing high-risk command
patterns.

## Contributions

1. **Offline secure terminal assistant architecture**

   A local-only command suggestion pipeline with retrieval, deterministic
   validation, safe alternatives, and shell integration.

2. **ATT&CK-style contextual risk scoring**

   Commands are scored using pattern matches, current directory, privilege
   context, command history, environment indicators, path sensitivity, and
   shell syntax validity.

3. **Policy modes**

   Five policy profiles alter thresholds and category weights:

   - `soc`
   - `strict`
   - `admin`
   - `learner`
   - `lab`

4. **CyberShell-Bench**

   A labeled JSONL benchmark for command-risk evaluation across safe,
   warning, blocked, context-sensitive, and policy-sensitive examples.

5. **Explainable safety output**

   Each risk decision includes matched rules, evidence, score, level, ATT&CK
   tactic/technique metadata, and safer alternatives when applicable.

6. **Optional RAG/LLM extension path**

   The default system remains dependency-light, while optional FAISS HNSW and
   GGUF local LLM scaffolds support future ablation studies.

## Research Questions

RQ1. Can a deterministic context-aware risk engine block known dangerous
terminal patterns while preserving safe defensive workflows?

RQ2. How do policy profiles affect false positives and false negatives across
SOC, strict production, learner, admin, and lab settings?

RQ3. What is the latency cost of contextual risk scoring compared with the
interactive terminal budget?

RQ4. Does adding retrieval or local LLM generation improve suggestion relevance
without increasing unsafe command exposure when deterministic guardrails remain
the final authority?

## Evaluation Metrics

- Decision accuracy
- Exact label accuracy
- Block precision
- Block recall
- Warn-or-block safety precision
- Warn-or-block safety recall
- Average risk assessment latency
- Suggestion relevance accuracy
- Cache hit latency
- Retrieval latency
- End-to-end suggestion latency

## Baselines

Recommended baselines for a paper:

1. Bash/Zsh prefix completion.
2. Token-search CyberShell retrieval.
3. FAISS retrieval without local LLM.
4. FAISS + local LLM without guardrails.
5. FAISS + local LLM with CyberShell guardrails.

## Current Artifact Status

Implemented:

- deterministic guardrail engine
- contextual risk v2
- policy modes
- command knowledge base
- playbooks
- history audit
- audit reports
- benchmark evaluator
- optional backend discovery
- optional FAISS/LLM scaffolds

Not yet implemented as default runtime:

- mandatory FAISS retrieval
- mandatory local LLM generation
- user study instrumentation
- large-scale external benchmark corpus

