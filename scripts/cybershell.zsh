# CyberShell Copilot Zsh integration.
#
# Install from a Zsh shell:
#   source /path/to/cybershell-copilot/scripts/cybershell.zsh
#
# Key bindings:
#   Ctrl-G        Insert a safe CyberShell suggestion.
#   Ctrl-X Ctrl-G Show an explanation/risk preview for the current line.

export CYBERSHELL_CACHE_FILE="${CYBERSHELL_CACHE_FILE:-$HOME/.cybershell/cache.json}"
export CYBERSHELL_MODE="${CYBERSHELL_MODE:-soc}"
export CYBERSHELL_BIN="${CYBERSHELL_BIN:-cybershell}"
typeset -g __CYBERSHELL_LAST_STATUS=0

_cybershell_precmd() {
  __CYBERSHELL_LAST_STATUS="$?"
}

autoload -Uz add-zsh-hook
add-zsh-hook precmd _cybershell_precmd

_cybershell_insert_suggestion() {
  local completion
  completion="$("$CYBERSHELL_BIN" suggest \
    --partial "$LBUFFER$RBUFFER" \
    --cwd "$PWD" \
    --history-file "${HISTFILE:-$HOME/.zsh_history}" \
    --last-status "$__CYBERSHELL_LAST_STATUS" \
    --shell "zsh" \
    --mode "$CYBERSHELL_MODE" \
    --cache-file "$CYBERSHELL_CACHE_FILE" \
    --safe-only \
    --completion-only 2>/dev/null)"
  if [ -n "$completion" ]; then
    LBUFFER="${LBUFFER}${completion}"
  fi
  zle reset-prompt
}

_cybershell_explain_line() {
  print
  "$CYBERSHELL_BIN" risk -- "$LBUFFER$RBUFFER"
  print
  zle reset-prompt
}

zle -N cybershell-insert-suggestion _cybershell_insert_suggestion
zle -N cybershell-explain-line _cybershell_explain_line
bindkey '^G' cybershell-insert-suggestion
bindkey '^X^G' cybershell-explain-line

