# CyberShell Copilot Bash integration.
#
# Install from a Bash shell:
#   source /path/to/cybershell-copilot/scripts/cybershell.bash
#
# Key bindings:
#   Ctrl-G        Auto-fill a safe CyberShell suggestion.
#   Ctrl-X Ctrl-G Show an explanation/risk preview for the current line.

export CYBERSHELL_CACHE_FILE="${CYBERSHELL_CACHE_FILE:-$HOME/.cybershell/cache.json}"
export CYBERSHELL_MODE="${CYBERSHELL_MODE:-soc}"
export CYBERSHELL_BIN="${CYBERSHELL_BIN:-cybershell}"
__CYBERSHELL_LAST_STATUS=0

_cybershell_prompt_hook() {
  __CYBERSHELL_LAST_STATUS="$?"
}

case "$PROMPT_COMMAND" in
  *_cybershell_prompt_hook*) ;;
  "") PROMPT_COMMAND="_cybershell_prompt_hook" ;;
  *) PROMPT_COMMAND="_cybershell_prompt_hook; $PROMPT_COMMAND" ;;
esac

_cybershell_insert_suggestion() {
  local partial before after response action insert
  partial="${READLINE_LINE:0:$READLINE_POINT}"
  response="$("$CYBERSHELL_BIN" suggest \
    --partial "$partial" \
    --cwd "$PWD" \
    --history-file "${HISTFILE:-$HOME/.bash_history}" \
    --last-status "$__CYBERSHELL_LAST_STATUS" \
    --shell "bash" \
    --mode "$CYBERSHELL_MODE" \
    --cache-file "$CYBERSHELL_CACHE_FILE" \
    --safe-only \
    --shell-insert 2>/dev/null)"
  if [ -n "$response" ]; then
    action="${response%%	*}"
    insert="${response#*	}"
    if [ "$action" = "$response" ]; then
      return
    fi
    if [ "$action" = "replace" ]; then
      READLINE_LINE="$insert"
      READLINE_POINT=${#READLINE_LINE}
      return
    fi
    before="${READLINE_LINE:0:$READLINE_POINT}"
    after="${READLINE_LINE:$READLINE_POINT}"
    READLINE_LINE="${before}${insert}${after}"
    READLINE_POINT=$((READLINE_POINT + ${#insert}))
  fi
}

_cybershell_explain_line() {
  printf '\n'
  "$CYBERSHELL_BIN" risk -- "$READLINE_LINE"
  printf '\n'
}

if [ -n "$BASH_VERSION" ]; then
  bind -x '"\C-g": _cybershell_insert_suggestion'
  bind -x '"\C-x\C-g": _cybershell_explain_line'
fi
