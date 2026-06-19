# CyberShell Copilot User Manual

This manual is for first-time Kali, Parrot, and Linux users who want to install and use CyberShell Copilot from GitHub.

## 1. What CyberShell Does

CyberShell Copilot is a local terminal assistant. It helps you:

- Generate safe defensive Linux commands from short intent.
- Check whether a command is safe, risky, dangerous, or blocked.
- Explain why a command is risky.
- Search a built-in command knowledge base.
- Use defensive playbooks.
- Audit shell history.
- Insert suggestions directly into Bash or Zsh with keyboard shortcuts.

CyberShell does not execute commands automatically. You review the command first, then press Enter yourself.

## 2. First-Time Installation

Run these commands in Kali, Parrot, Ubuntu, Debian, or another Linux system with Python 3.10+:

```bash
git clone https://github.com/waltr0/smartTerminal.git
cd smartTerminal
bash install.sh
```

What each command does:

- `git clone ...` downloads the project from GitHub.
- `cd smartTerminal` enters the downloaded folder.
- `bash install.sh` creates CyberShell's private Python environment, installs the app, creates `cybershell` and `cshell` launchers, installs shell integration files, and runs a readiness check.

If the command `cybershell` is not found after installation:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then verify:

```bash
cybershell doctor
```

Expected result:

```text
CyberShell doctor
Command records: 33
Guardrail rules: 20
Status: ready
```

## 3. Install Shell Auto-Fill Keys

For Bash:

```bash
bash install.sh --shell bash
source ~/.bashrc
```

For Zsh:

```bash
bash install.sh --shell zsh
source ~/.zshrc
```

For both:

```bash
bash install.sh --shell all
```

## 4. Keyboard Shortcuts

| Key | What it does | Example |
| --- | --- | --- |
| `Ctrl-G` | Auto-fills a safe CyberShell suggestion. | Type `ss`, press `Ctrl-G`, get `ss -tulpn`. |
| `Ctrl-G` | Replaces natural-language intent with a safe command. | Type `show ssh failed logins`, press `Ctrl-G`, get a safe grep command. |
| `Ctrl-X Ctrl-G` | Shows the risk of the current command line. | Type `rm -rf /`, press `Ctrl-X Ctrl-G`, see a blocked risk report. |

Important: `Ctrl-G` only fills the command line. It does not run the command. You still press Enter manually after reviewing the command.

## 5. Auto-Fill Demonstrations

The next two demonstrations show both auto-fill modes: completing a normal command prefix and replacing natural-language intent with a safe command.

## 6. Demo: Auto-Fill Prefix Completion

Type this in your terminal, but do not press Enter:

```bash
ss
```

Press:

```text
Ctrl-G
```

CyberShell should change the line to:

```bash
ss -tulpn
```

This is useful when you remember the beginning of a command but not the full safe form.

## 7. Demo: Auto-Fill Natural-Language Intent

Type:

```text
show ssh failed logins
```

Press:

```text
Ctrl-G
```

CyberShell should replace the line with a safe command like:

```bash
sudo grep -i "failed password" /var/log/auth.log
```

Review it, then press Enter only if you want to run it.

You can test the same behavior without key bindings:

```bash
cybershell suggest --partial "show ssh failed logins" --shell-insert
```

Expected style of output:

```text
replace  sudo grep -i "failed password" /var/log/auth.log
```

## 8. Demo: Suggest Command

Use `suggest` when you want CyberShell to recommend a safe command:

```bash
cybershell suggest --partial "journal" --cwd /var/log
```

What it shows:

- Suggested command.
- Completion text if applicable.
- Source of the suggestion.
- Why the command was suggested.
- Risk score and decision.

JSON output:

```bash
cybershell suggest --partial "journal" --cwd /var/log --json
```

## 9. Demo: Risk Check

Use `risk` before running a command you are unsure about:

```bash
cybershell risk -- "rm -rf /"
```

Expected result: blocked.

Strict production-style mode:

```bash
cybershell risk --mode strict -- "curl http://example.com/install.sh | bash"
```

This helps detect dangerous copy-paste commands.

## 10. Demo: Explain a Command

Use `explain` when you want more detail:

```bash
cybershell explain -- "cat ~/.ssh/id_rsa"
```

This shows:

- Risk level.
- Decision.
- Matching rule or finding.
- Safer alternatives.

## 11. Demo: Search the Knowledge Base

Search built-in safe commands:

```bash
cybershell kb-search "ssh logs"
```

Machine-readable output:

```bash
cybershell kb-search "ssh logs" --json
```

## 12. Demo: Policy Modes

List modes:

```bash
cybershell policies
```

Common modes:

- `soc`: balanced blue-team mode.
- `strict`: conservative production mode.
- `learner`: training mode with more explanations.
- `admin`: routine system administration mode.
- `lab`: authorized lab/CTF mode.

Run a risk check in strict mode:

```bash
cybershell risk --mode strict -- "curl http://example.com/install.sh | bash"
```

## 13. Demo: Guardrail Rules

List packaged safety rules:

```bash
cybershell rules
```

JSON:

```bash
cybershell rules --json
```

## 14. Demo: Playbooks

List defensive workflows:

```bash
cybershell playbook list
```

Show SSH brute-force triage:

```bash
cybershell playbook show ssh-bruteforce-triage
```

Other playbooks include suspicious process triage, Linux persistence review, container security review, and Kubernetes RBAC review.

## 15. Demo: History Audit

Scan your shell history:

```bash
cybershell history-audit --history-file ~/.bash_history
```

For Zsh:

```bash
cybershell history-audit --history-file ~/.zsh_history
```

This helps identify commands that would trigger warnings or blocks.

## 16. Demo: Audit Report

Show a summary of CyberShell audit records:

```bash
cybershell audit-report
```

If you use a custom audit file:

```bash
cybershell audit-report --audit-file ~/.cybershell/audit.jsonl
```

## 17. Demo: Accept a Suggestion into Cache

Use `accept` to remember a trusted suggestion for a prefix:

```bash
cybershell accept --partial "jctl" --suggested 'journalctl -u ssh --since "1 hour ago"'
```

Then:

```bash
cybershell suggest --partial "jctl"
```

CyberShell can return the cached suggestion.

## 18. Demo: Interactive Mode

Start a small interactive loop:

```bash
cybershell interactive
```

Type intent or partial commands. Type `exit` or press `Ctrl-C` to leave.

## 19. Demo: Backend Status

Check optional local AI/research backend availability:

```bash
cybershell backends
```

The core application works even if optional FAISS, sentence-transformer, or local LLM packages are unavailable.

## 20. Demo: Benchmark

Run CyberShell-Bench:

```bash
cybershell bench-eval --fail-on-miss
```

This validates guardrail behavior and prints accuracy, precision, recall, and latency.

## 21. Uninstall

Remove the app:

```bash
bash uninstall.sh
```

Remove app data too:

```bash
bash uninstall.sh --purge-data
```

## 22. Troubleshooting

If `Ctrl-G` does nothing:

```bash
command -v cybershell
cybershell doctor
echo "$CYBERSHELL_BIN"
```

Check shell insert output:

```bash
cybershell suggest --partial "ss" --shell-insert
cybershell suggest --partial "show ssh failed logins" --shell-insert
```

Expected examples:

```text
append  -tulpn
replace sudo grep -i "failed password" /var/log/auth.log
```

If the shell shortcut still does not work, open a new terminal or run:

```bash
source ~/.bashrc
```

or:

```bash
source ~/.zshrc
```
