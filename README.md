# CyberShell Copilot

Offline, cybersecurity-aware terminal assistant for Linux and Kali.

CyberShell Copilot suggests Linux, DevOps, and blue-team commands, scores cyber
risk, maps risky patterns to MITRE ATT&CK-style tactics, blocks dangerous
suggestions, and offers safer alternatives.

The default application is dependency-light and runs with the Python standard
library. Optional FAISS and local GGUF LLM backends are available for research
experiments without changing the deterministic safety layer.

## What Makes It Different

Normal terminal autocomplete asks: "What command might come next?"

CyberShell asks:

- Is the command useful for the current context?
- Is it safe to display?
- Does it touch secrets, persistence, firewall state, disks, containers, or cloud identity?
- Does it resemble attacker behavior?
- Can we suggest a safer read-only alternative?

## Capabilities

- Offline command suggestions from a built-in blue-team command knowledge base.
- Cyber risk scoring for typed or generated commands.
- Guardrail blocking for destructive filesystem, disk-wipe, reverse-shell, and fork-bomb patterns.
- Warning-level detection for secrets access, firewall tampering, persistence, privileged mutation, Kubernetes secret access, public scanning, and bulk archive/exfiltration patterns.
- MITRE ATT&CK-style tactic and technique metadata in risk findings.
- Safer alternatives for high-risk commands.
- Shell history audit for risky prior commands.
- Built-in incident-response playbooks.
- Knowledge-base search and guardrail rule inspection.
- Policy modes for SOC, strict production, admin, learner, and authorized lab use.
- CyberShell-Bench JSONL benchmark and evaluator.
- Optional FAISS HNSW and local GGUF LLM backend scaffolds for research experiments.
- Prefix cache for accepted suggestions.
- Local JSONL audit trail with minimized fields.
- Bash and Zsh key bindings for inserting safe suggestions.

## Install On Linux / Kali

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/waltr0/smartTerminal.git
cd cybershell-copilot
bash install.sh
cybershell doctor
```

Install with Bash key bindings:

```bash
bash install.sh --shell bash
source ~/.bashrc
```

Install with Zsh key bindings:

```bash
bash install.sh --shell zsh
source ~/.zshrc
```

If `cybershell` is not found after installation:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Detailed docs:

- [Linux install](docs/INSTALL_LINUX.md)
- [Kali setup](docs/KALI_SETUP.md)
- [Shell integration](docs/SHELL_INTEGRATION.md)
- [User manual](docs/CyberShell_Copilot_User_Manual.pdf)
- [Full project PDF guide](docs/CyberShell_Copilot_Project_Guide.pdf)

## Quick Commands

```bash
cybershell suggest --partial "journal" --cwd /var/log
cybershell risk -- "rm -rf /"
cybershell explain -- "cat ~/.ssh/id_rsa"
cybershell playbook list
cybershell playbook show ssh-bruteforce-triage
cybershell history-audit --history-file ~/.bash_history
cybershell bench-eval --fail-on-miss
```

## Shell Key Bindings

When shell integration is installed:

- `Ctrl-G`: auto-fill a safe suggestion. If you typed a command prefix, it appends the missing part. If you typed natural-language intent, it replaces the line with the safe command.
- `Ctrl-X Ctrl-G`: show risk for the current command line.

## Policy Modes

```bash
cybershell policies
cybershell risk --mode strict -- "curl http://example.com/install.sh | bash"
cybershell risk --mode lab -- nmap -sV --top-ports 100 127.0.0.1
```

Modes:

- `soc`: balanced defensive operations.
- `strict`: conservative production-sensitive mode.
- `admin`: routine system administration mode.
- `learner`: explanation-heavy training mode.
- `lab`: authorized lab/CTF mode.

## Example

```bash
cybershell suggest --partial "journal" --cwd /var/log
```

Possible output:

```text
Suggestion: journalctl -u ssh --since "1 hour ago"
Completion: ctl -u ssh --since "1 hour ago"
Source: knowledge-base (0.99)
Why: Review recent SSH service logs for login activity and failures. Domain: incident-response. ATT&CK-style tactic: Credential Access.

Risk: safe / decision=allow / score=0
Summary: No guardrail patterns matched; command appears safe for display.
```

Blocked command example:

```bash
cybershell risk -- "rm -rf /"
```

The guardrail engine blocks it and proposes safer inspection alternatives.

## Research Artifact

CyberShell is structured as a research artifact as well as an application.

- [Research artifact](docs/RESEARCH_ARTIFACT.md)
- [Benchmark schema](docs/BENCHMARK_SCHEMA.md)
- [Evaluation guide](docs/EVALUATION.md)
- [FAISS and LLM backends](docs/FAISS_LLM_BACKENDS.md)

Benchmark:

```bash
cybershell bench-eval --fail-on-miss
```

Current packaged benchmark results should report:

- decision accuracy: `1.0000`
- exact label accuracy: `1.0000`
- block precision/recall: `1.0000/1.0000`
- warn-or-block safety precision/recall: `1.0000/1.0000`

## Optional Research Backends

```bash
bash install.sh --research
bash install.sh --llm
cybershell backends
```

The default app does not require FAISS, SentenceTransformers, or a local LLM.
Optional backends are for experiments and ablation studies.

## Development From Source

```bash
git clone https://github.com/waltr0/smartTerminal.git
cd cybershell-copilot
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
cybershell bench-eval --fail-on-miss
```

Without installing:

```bash
PYTHONPATH=src python -m cybershell doctor
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Project Structure

```text
cybershell-copilot/
  benchmarks/
    cybershell_bench.jsonl
  docs/
  scripts/
    cybershell.bash
    cybershell.zsh
  src/cybershell/
    cli.py
    engine.py
    risk.py
    policy.py
    benchmark.py
    backends.py
    kb.py
    cache.py
    audit.py
    data/
  tests/
  install.sh
  uninstall.sh
  Makefile
```

## Uninstall

```bash
bash uninstall.sh
```

Remove audit/cache data too:

```bash
bash uninstall.sh --purge-data
```

## Safety Notice

CyberShell does not execute commands. It suggests, scores, warns, blocks, and
explains. Users remain responsible for commands they manually execute.

## Contributing

See:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

MIT. See [LICENSE](LICENSE).
