# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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

# Extract title and label list from gh JSON (no jq required — minimal parse).
# Expects the exact shape produced by `gh issue view --json title,labels`.
_extract_title() {
  # Match `"title":"..."` allowing escaped quotes inside.
  printf '%s' "$1" | sed -E 's/.*"title":"((\\.|[^"\\])*)".*/\1/'
}

_extract_labels() {
  # Print comma-separated label names from `[{"name":"a"},{"name":"b"}]`.
  printf '%s' "$1" \
    | grep -oE '"name":"[^"]+"' \
    | sed -E 's/"name":"([^"]+)"/\1/' \
    | paste -sd, -
}

branch_from_issue() {
  local num="$1" json="$2"
  local title labels prefix slug
  title=$(_extract_title "$json")
  labels=$(_extract_labels "$json")
  prefix=$(prefix_from_labels "$labels")
  slug=$(derive_slug "$title")
  printf '%s%s-%s' "$prefix" "$num" "$slug"
}
