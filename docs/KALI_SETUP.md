# Kali Linux Setup

CyberShell Copilot is a good fit for Kali when used as a safe, offline assistant
for defensive command review, incident-response playbooks, lab workflows, and
risk-aware shell suggestions.

## Install Dependencies

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip bash zsh
```

## Clone And Install

```bash
git clone https://github.com/waltr0/smartTerminal.git
cd cybershell-copilot
bash install.sh --shell bash
```

Restart the terminal or run:

```bash
source ~/.bashrc
```

## Verify

```bash
cybershell doctor
cybershell policies
cybershell bench-eval --fail-on-miss
```

## Recommended Modes On Kali

`soc`

Default defensive mode. Best for normal use.

```bash
cybershell suggest --mode soc --partial "journal" --cwd /var/log
```

`lab`

Authorized lab/CTF mode. Reconnaissance warnings are less restrictive, but
destructive commands are still blocked.

```bash
cybershell risk --mode lab -- nmap -sV --top-ports 100 127.0.0.1
```

`strict`

Use when connected to sensitive or production-like systems.

```bash
cybershell risk --mode strict -- "curl http://example.com/install.sh | bash"
```

## Common Commands

```bash
cybershell playbook list
cybershell playbook show ssh-bruteforce-triage
cybershell kb-search docker
cybershell history-audit --history-file ~/.bash_history
cybershell audit-report
```

## Safety Reminder

CyberShell never executes commands for you. It suggests, scores, warns, blocks,
and explains. The user remains responsible for commands they manually execute.
