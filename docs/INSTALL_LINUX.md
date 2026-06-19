# Linux Installation

CyberShell Copilot is designed to install without touching system Python. The
recommended installer creates a private virtual environment under:

```text
~/.local/share/cybershell/venv
```

and launchers under:

```text
~/.local/bin
```

## Requirements

- Linux
- Python 3.10+
- `python3-venv`
- `python3-pip`
- Git

Debian/Kali/Ubuntu:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

## Install From GitHub

```bash
git clone https://github.com/waltr0/smartTerminal.git
cd cybershell-copilot
bash install.sh
```

Then run:

```bash
cybershell doctor
cybershell suggest --partial "journal" --cwd /var/log
cybershell risk -- "rm -rf /"
```

If `cybershell` is not found, add `~/.local/bin` to `PATH`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## Install With Bash Key Bindings

```bash
bash install.sh --shell bash
source ~/.bashrc
```

Key bindings:

- `Ctrl-G`: auto-fill a safe suggestion. Prefixes are completed in place; natural-language intent is replaced with the safe command.
- `Ctrl-X Ctrl-G`: show risk for the current line.

## Install With Zsh Key Bindings

```bash
bash install.sh --shell zsh
source ~/.zshrc
```

## Optional Research Backends

FAISS/vector retrieval:

```bash
bash install.sh --research
```

Local GGUF LLM support:

```bash
bash install.sh --llm
```

Both can take longer to install and may require compiler/toolchain packages.

## Uninstall

```bash
bash uninstall.sh
```

Remove cache/audit data too:

```bash
bash uninstall.sh --purge-data
```
