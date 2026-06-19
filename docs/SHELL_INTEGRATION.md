# Shell Integration

CyberShell includes optional Bash and Zsh key bindings.

## Bash

Install:

```bash
bash install.sh --shell bash
source ~/.bashrc
```

Manual source:

```bash
export CYBERSHELL_BIN="$HOME/.local/bin/cybershell"
source "$HOME/.local/share/cybershell/shell/cybershell.bash"
```

Keys:

- `Ctrl-G`: auto-fill a safe suggestion.
  - If the current line is a command prefix such as `ss`, CyberShell appends the missing text, for example ` -tulpn`.
  - If the current line is natural-language intent such as `show ssh failed logins`, CyberShell replaces the line with a safe command such as `sudo grep -i "failed password" /var/log/auth.log`.
- `Ctrl-X Ctrl-G`: print risk/explanation for the current line.

## Zsh

Install:

```zsh
bash install.sh --shell zsh
source ~/.zshrc
```

Manual source:

```zsh
export CYBERSHELL_BIN="$HOME/.local/bin/cybershell"
source "$HOME/.local/share/cybershell/shell/cybershell.zsh"
```

Keys:

- `Ctrl-G`: auto-fill a safe suggestion.
  - If the current line is a command prefix such as `ss`, CyberShell appends the missing text, for example ` -tulpn`.
  - If the current line is natural-language intent such as `show ssh failed logins`, CyberShell replaces the line with a safe command such as `sudo grep -i "failed password" /var/log/auth.log`.
- `Ctrl-X Ctrl-G`: print risk/explanation for the current line.

## Configuration

Environment variables:

```bash
export CYBERSHELL_MODE=soc
export CYBERSHELL_CACHE_FILE="$HOME/.cybershell/cache.json"
export CYBERSHELL_BIN="$HOME/.local/bin/cybershell"
```

Modes:

- `soc`
- `strict`
- `admin`
- `learner`
- `lab`

## Troubleshooting

If `Ctrl-G` does nothing:

```bash
command -v cybershell
cybershell doctor
echo "$CYBERSHELL_BIN"
```

Also check that the line has a recognizable prefix or intent:

```bash
cybershell suggest --partial "ss" --shell-insert
cybershell suggest --partial "show ssh failed logins" --shell-insert
```

If `cybershell` is not found:

```bash
export PATH="$HOME/.local/bin:$PATH"
```
