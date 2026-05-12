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
