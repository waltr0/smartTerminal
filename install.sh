#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="cybershell"
PROJECT_NAME="cybershell-copilot"
MIN_PYTHON="3.10"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_HOME="${CYBERSHELL_HOME:-$HOME/.local/share/cybershell}"
BIN_DIR="${CYBERSHELL_BIN_DIR:-$HOME/.local/bin}"
VENV_DIR="$APP_HOME/venv"
SHELL_DIR="$APP_HOME/shell"
INSTALL_EXTRAS=""
SHELL_INTEGRATION="none"
DEV_INSTALL=0

usage() {
  cat <<'USAGE'
CyberShell Copilot installer

Usage:
  bash install.sh [options]

Options:
  --shell bash|zsh|all     Add shell key bindings to ~/.bashrc and/or ~/.zshrc.
  --research               Install optional FAISS/vector retrieval dependencies.
  --llm                    Install optional llama.cpp/GGUF LLM dependencies.
  --dev                    Install editable from the cloned repo.
  --prefix PATH            Install app files under PATH instead of ~/.local/share/cybershell.
  --bin-dir PATH           Create launchers under PATH instead of ~/.local/bin.
  -h, --help               Show this help.

Examples:
  bash install.sh
  bash install.sh --shell bash
  bash install.sh --shell all --research

Notes:
  - The default install uses a private virtualenv and does not touch system Python.
  - On Kali/Debian, install python3-venv first if venv creation fails:
      sudo apt update && sudo apt install -y python3 python3-venv python3-pip
USAGE
}

log() {
  printf '[cybershell] %s\n' "$*"
}

die() {
  printf '[cybershell] ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --shell)
      [[ $# -ge 2 ]] || die "--shell requires bash, zsh, or all"
      SHELL_INTEGRATION="$2"
      shift 2
      ;;
    --research)
      INSTALL_EXTRAS="${INSTALL_EXTRAS}research,"
      shift
      ;;
    --llm)
      INSTALL_EXTRAS="${INSTALL_EXTRAS}llm,"
      shift
      ;;
    --dev)
      DEV_INSTALL=1
      shift
      ;;
    --prefix)
      [[ $# -ge 2 ]] || die "--prefix requires a path"
      APP_HOME="$2"
      VENV_DIR="$APP_HOME/venv"
      SHELL_DIR="$APP_HOME/shell"
      shift 2
      ;;
    --bin-dir)
      [[ $# -ge 2 ]] || die "--bin-dir requires a path"
      BIN_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

case "$SHELL_INTEGRATION" in
  none|bash|zsh|all) ;;
  *) die "--shell must be bash, zsh, or all" ;;
esac

command -v python3 >/dev/null 2>&1 || die "python3 is required"

python3 - <<PY || die "Python $MIN_PYTHON or newer is required"
import sys
required = tuple(int(x) for x in "$MIN_PYTHON".split("."))
raise SystemExit(0 if sys.version_info[:2] >= required else 1)
PY

if [[ ! -f "$REPO_ROOT/pyproject.toml" ]]; then
  die "Run install.sh from the $PROJECT_NAME repository root"
fi

log "Installing CyberShell Copilot"
log "Repository: $REPO_ROOT"
log "App home:   $APP_HOME"
log "Bin dir:    $BIN_DIR"

mkdir -p "$APP_HOME" "$BIN_DIR" "$SHELL_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating virtual environment"
  if ! python3 -m venv "$VENV_DIR"; then
    die "Failed to create venv. On Kali/Debian install python3-venv first."
  fi
fi

PYTHON="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"

log "Upgrading installer tooling"
"$PYTHON" -m pip install --upgrade pip setuptools wheel

EXTRA_SPEC=""
if [[ -n "$INSTALL_EXTRAS" ]]; then
  INSTALL_EXTRAS="${INSTALL_EXTRAS%,}"
  EXTRA_SPEC="[$INSTALL_EXTRAS]"
fi

if [[ "$DEV_INSTALL" -eq 1 ]]; then
  log "Installing editable package .$EXTRA_SPEC"
  "$PIP" install -e "$REPO_ROOT$EXTRA_SPEC"
else
  log "Installing package .$EXTRA_SPEC"
  "$PIP" install "$REPO_ROOT$EXTRA_SPEC"
fi

cp "$REPO_ROOT/scripts/cybershell.bash" "$SHELL_DIR/cybershell.bash"
cp "$REPO_ROOT/scripts/cybershell.zsh" "$SHELL_DIR/cybershell.zsh"

cat > "$BIN_DIR/cybershell" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/cybershell" "\$@"
EOF
chmod +x "$BIN_DIR/cybershell"

cat > "$BIN_DIR/cshell" <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/cshell" "\$@"
EOF
chmod +x "$BIN_DIR/cshell"

add_shell_block() {
  local rc_file="$1"
  local script_path="$2"
  local marker_begin="# >>> cybershell-copilot >>>"
  local marker_end="# <<< cybershell-copilot <<<"

  touch "$rc_file"
  if grep -Fq "$marker_begin" "$rc_file"; then
    log "Shell integration already present in $rc_file"
    return
  fi

  cat >> "$rc_file" <<EOF

$marker_begin
export CYBERSHELL_BIN="$BIN_DIR/cybershell"
source "$script_path"
$marker_end
EOF
  log "Added shell integration to $rc_file"
}

case "$SHELL_INTEGRATION" in
  bash)
    add_shell_block "$HOME/.bashrc" "$SHELL_DIR/cybershell.bash"
    ;;
  zsh)
    add_shell_block "$HOME/.zshrc" "$SHELL_DIR/cybershell.zsh"
    ;;
  all)
    add_shell_block "$HOME/.bashrc" "$SHELL_DIR/cybershell.bash"
    add_shell_block "$HOME/.zshrc" "$SHELL_DIR/cybershell.zsh"
    ;;
esac

log "Running doctor"
"$BIN_DIR/cybershell" doctor

cat <<EOF

CyberShell Copilot installed successfully.

Run:
  cybershell doctor
  cybershell suggest --partial "journal" --cwd /var/log
  cybershell risk -- "rm -rf /"

If '$BIN_DIR' is not on PATH, add this to your shell rc file:
  export PATH="$BIN_DIR:\$PATH"

To uninstall:
  bash uninstall.sh
EOF
