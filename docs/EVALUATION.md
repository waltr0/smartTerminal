# Evaluation Guide

## Unit and Integration Tests

```bash
python -m unittest discover -s tests -v
```

## Benchmark Evaluation

```bash
cybershell bench-eval --dataset benchmarks/cybershell_bench.jsonl --fail-on-miss
```

The 143-case dataset is categorized (destructive-fs, benign-cleanup,
device-destruction, reverse-shell, rce, credential-access, persistence,
privilege-escalation, defense-evasion, recon, nl-intent, evasion,
evasion-benign, evasion-advanced, benign-ops, suggestion-contract) and results
are reported failures-and-all. The headline guarantees are a 0.0 false-positive
rate over the benign set and perfect accuracy on the cases the tool claims to
handle, with three documented evasion limitations surfaced rather than hidden.
See `docs/BENCHMARK_SCHEMA.md` and `THREAT_MODEL.md`.

## CLI Smoke Matrix

Recommended release smoke commands:

```bash
cybershell doctor
cybershell policies
cybershell backends
cybershell suggest --partial "journal" --cwd /var/log
cybershell suggest --partial "docker ps" --cwd . --json
cybershell risk -- "rm -rf /"
cybershell explain -- "cat ~/.ssh/id_rsa"
cybershell kb-search ssh
cybershell rules
cybershell playbook list
cybershell playbook show ssh-bruteforce-triage
cybershell bench-eval --fail-on-miss
```

## Paper Tables

Useful tables for an IEEE-style paper:

- command-risk label distribution
- benchmark accuracy metrics
- per-policy comparison
- latency distribution
- false positive/false negative examples
- ablation results after FAISS/LLM backends are enabled

