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

- `Ctrl-G`: insert a safe completion.
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

- `Ctrl-G`: insert a safe completion.
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

If `cybershell` is not found:

```bash
export PATH="$HOME/.local/bin:$PATH"
```
