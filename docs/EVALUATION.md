# Evaluation Guide

## Unit and Integration Tests

```bash
python -m unittest discover -s tests -v
```

## Benchmark Evaluation

```bash
cybershell bench-eval --dataset benchmarks/cybershell_bench.jsonl --fail-on-miss
```

Current benchmark categories include:

- read-only defensive commands
- credential and secret exposure
- firewall tampering
- privilege-sensitive permission changes
- Kubernetes secret access
- Docker privileged containers
- network reconnaissance
- persistence writes
- destructive filesystem commands
- disk wiping
- reverse shell patterns
- fork bomb patterns
- mode-specific lab and strict policy behavior

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

