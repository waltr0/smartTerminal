#!/usr/bin/env bash
set -Eeuo pipefail

APP_HOME="${CYBERSHELL_HOME:-$HOME/.local/share/cybershell}"
BIN_DIR="${CYBERSHELL_BIN_DIR:-$HOME/.local/bin}"
PURGE_DATA=0

usage() {
  cat <<'USAGE'
CyberShell Copilot uninstaller

Usage:
  bash uninstall.sh [options]

Options:
  --purge-data     Remove ~/.cybershell cache/audit data too.
  --prefix PATH    Remove app files under PATH instead of ~/.local/share/cybershell.
  --bin-dir PATH   Remove launchers under PATH instead of ~/.local/bin.
  -h, --help       Show this help.
USAGE
}

log() {
  printf '[cybershell] %s\n' "$*"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-data)
      PURGE_DATA=1
      shift
      ;;
    --prefix)
      [[ $# -ge 2 ]] || { echo "--prefix requires a path" >&2; exit 1; }
      APP_HOME="$2"
      shift 2
      ;;
    --bin-dir)
      [[ $# -ge 2 ]] || { echo "--bin-dir requires a path" >&2; exit 1; }
      BIN_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

remove_block() {
  local rc_file="$1"
  [[ -f "$rc_file" ]] || return 0
  python3 - "$rc_file" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="ignore").splitlines()
out = []
inside = False
changed = False
for line in text:
    if line.strip() == "# >>> cybershell-copilot >>>":
        inside = True
        changed = True
        continue
    if line.strip() == "# <<< cybershell-copilot <<<":
        inside = False
        continue
    if not inside:
        out.append(line)
if changed:
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
PY
}

log "Removing launchers"
rm -f "$BIN_DIR/cybershell" "$BIN_DIR/cshell"

log "Removing shell integration blocks"
remove_block "$HOME/.bashrc"
remove_block "$HOME/.zshrc"

if [[ -d "$APP_HOME" ]]; then
  log "Removing app home: $APP_HOME"
  rm -rf "$APP_HOME"
fi

if [[ "$PURGE_DATA" -eq 1 && -d "$HOME/.cybershell" ]]; then
  log "Purging user data: $HOME/.cybershell"
  rm -rf "$HOME/.cybershell"
fi

log "Uninstall complete"
