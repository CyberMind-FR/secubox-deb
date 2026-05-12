# shellcheck shell=bash
# scripts/lib/agent-worktree-lib.sh
# Helpers for scripts/agent-worktree.sh. Sourced, never executed.

set -uo pipefail

# Slugify a free-text title into a branch-safe slug.
# Rules: lowercase, ASCII-fold via iconv, non-[a-z0-9] -> '-', collapse runs,
# trim leading/trailing '-', max 40 chars, fallback 'issue' when empty.
derive_slug() {
  local raw="${1:-}"
  local s
  s=$(printf '%s' "$raw" | iconv -f UTF-8 -t ASCII//TRANSLIT 2>/dev/null || printf '%s' "$raw")
  s=$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')
  s=$(printf '%s' "$s" | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')
  if [[ ${#s} -gt 40 ]]; then
    s="${s:0:40}"
    s="${s%-}"
  fi
  if [[ -z "$s" ]]; then s="issue"; fi
  printf '%s' "$s"
}

# Map a comma-separated label list to a branch prefix.
# Mapping: bug|fix -> fix/, documentation -> docs/, infra|chore -> chore/,
# everything else (including empty) -> feature/. First matching label wins.
prefix_from_labels() {
  local labels="${1:-}"
  local IFS=','
  local label
  for label in $labels; do
    case "$label" in
      bug|fix)             printf 'fix/';     return 0 ;;
      documentation)       printf 'docs/';    return 0 ;;
      infra|chore)         printf 'chore/';   return 0 ;;
    esac
  done
  printf 'feature/'
}
