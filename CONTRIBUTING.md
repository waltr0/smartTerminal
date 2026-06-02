# Contributing

Thanks for helping improve CyberShell Copilot.

## Development Setup

```bash
git clone https://github.com/waltr0/smartTerminal.git
cd cybershell-copilot
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Before Opening A Pull Request

Run:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m cybershell bench-eval --fail-on-miss
PYTHONPATH=src python -m compileall src tests
```

If you edit shell scripts:

```bash
bash -n scripts/cybershell.bash
zsh -n scripts/cybershell.zsh
```

`zsh` may not be available on every development machine; mention that if you
cannot run it locally.

## Contribution Areas

- new defensive command records
- new guardrail rules
- new benchmark cases
- policy-mode tuning
- Kali/Linux installer improvements
- documentation
- optional FAISS or local LLM experiments

## Guardrail Rule Guidelines

Every new high-risk command pattern should include:

- stable rule ID
- category
- score weight
- severity
- clear user-facing message
- MITRE ATT&CK-style tactic/technique where appropriate
- tests or benchmark cases

## Benchmark Guidelines

Add JSONL rows to:

```text
benchmarks/cybershell_bench.jsonl
src/cybershell/data/cybershell_bench.jsonl
```

Keep both copies synchronized until build tooling generates the packaged copy.

## Security Reports

Do not include secrets in issues, PRs, tests, or benchmark examples. For security
vulnerabilities, follow `SECURITY.md`.
