#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/agent-worktree.sh
# Multi-agent worktree workflow helper.
# See docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/agent-worktree-lib.sh
source "$SCRIPT_DIR/lib/agent-worktree-lib.sh"

WORKTREE_ROOT="${WORKTREE_ROOT:-$HOME/CyberMindStudio/secubox-deb-worktrees}"
GH_BIN="${GH_BIN:-gh}"
GIT_BIN="${GIT_BIN:-git}"

usage() {
  cat <<'USAGE'
agent-worktree.sh — multi-agent worktree workflow helper

Usage:
  agent-worktree.sh start  --issue <N> [--dry-run] [--verbose]
  agent-worktree.sh list   [--verbose]
  agent-worktree.sh sync   [<N>]
  agent-worktree.sh finish [--dry-run]
  agent-worktree.sh clean  <N> [--force]
  agent-worktree.sh --help

Environment:
  WORKTREE_ROOT   override worktree root (default: ~/CyberMindStudio/secubox-deb-worktrees)
  GH_BIN, GIT_BIN override CLI binaries (used by tests)

Exit codes:
  0 success
  1 generic / usage
  2 precondition (issue missing, gh not authed, etc.)
  3 bad state (dirty tree, conflict, non-merged PR)
  4 network / remote error
USAGE
}

cmd_start() {
  local issue=""
  local dry_run=0
  local verbose=0
  while (($#)); do
    case "$1" in
      --issue) issue="$2"; shift 2 ;;
      --issue=*) issue="${1#--issue=}"; shift ;;
      --dry-run) dry_run=1; shift ;;
      --verbose|-v) verbose=1; shift ;;
      *) echo "start: unexpected arg: $1" >&2 ; return 1 ;;
    esac
  done
  if [[ -z "$issue" ]]; then
    echo "start: --issue <N> required" >&2 ; return 1
  fi

  # Preconditions
  if ! "$GH_BIN" auth status >/dev/null 2>&1; then
    echo "start: gh not authenticated. Run: gh auth login" >&2 ; return 2
  fi
  if ! "$GIT_BIN" diff-index --quiet HEAD --; then
    echo "start: working tree is dirty. Commit or stash first." >&2 ; return 3
  fi

  # Refuse if we are already inside the worktree root
  local cwd ; cwd=$(pwd)
  if [[ "$cwd" == "$WORKTREE_ROOT/"* ]]; then
    echo "start: already inside a worktree under $WORKTREE_ROOT" >&2 ; return 3
  fi

  local json
  if ! json=$("$GH_BIN" issue view "$issue" --json title,labels 2>/dev/null); then
    echo "start: issue #$issue not found" >&2 ; return 2
  fi

  local branch dir slug
  branch=$(branch_from_issue "$issue" "$json")
  slug="${branch#*/}"   # strip prefix dir
  slug="${slug#*-}"     # strip the issue number prefix
  dir="$WORKTREE_ROOT/${issue}-${slug}"

  if [[ -e "$dir" ]]; then
    echo "start: worktree path already exists: $dir" >&2 ; return 3
  fi
  if "$GIT_BIN" show-ref --verify --quiet "refs/heads/$branch"; then
    echo "start: branch already exists: $branch" >&2 ; return 3
  fi

  if (( dry_run )); then
    echo "dry-run: would create branch=$branch dir=$dir"
    return 0
  fi

  mkdir -p "$WORKTREE_ROOT"
  "$GIT_BIN" fetch -q origin master 2>/dev/null || true
  "$GIT_BIN" worktree add -b "$branch" "$dir" origin/master >/dev/null

  # Copy local Claude settings, if present
  if [[ -f .claude/settings.local.json ]]; then
    mkdir -p "$dir/.claude"
    cp .claude/settings.local.json "$dir/.claude/settings.local.json"
  fi

  "$GH_BIN" issue comment "$issue" \
    --body "Worktree created at \`$dir\`, branch \`$branch\`." >/dev/null

  echo "branch:   $branch"
  echo "worktree: $dir"
  echo "next:     cd $dir"
}
cmd_list() {
  local porcelain
  porcelain=$("$GIT_BIN" worktree list --porcelain)
  local path="" branch=""
  while IFS= read -r line; do
    case "$line" in
      worktree\ *) path="${line#worktree }" ;;
      branch\ refs/heads/*)
        branch="${line#branch refs/heads/}"
        _list_emit_row "$path" "$branch"
        path=""; branch="" ;;
      "") path=""; branch="" ;;
    esac
  done <<< "$porcelain"
}

_list_emit_row() {
  local path="$1" branch="$2"
  local tag=""
  if [[ "$path" != "$WORKTREE_ROOT"* ]]; then tag="[primary] "; fi
  local ahead=0 behind=0
  if "$GIT_BIN" -C "$path" rev-parse --verify -q origin/master >/dev/null 2>&1; then
    read -r behind ahead < <(
      "$GIT_BIN" -C "$path" rev-list --left-right --count "origin/master...$branch" 2>/dev/null \
        | awk '{print $1, $2}'
    )
  fi
  local state="clean"
  if ! "$GIT_BIN" -C "$path" diff --quiet HEAD -- 2>/dev/null; then state="dirty"; fi
  printf '%s%s  %s  ahead:%s behind:%s %s\n' "$tag" "$branch" "$path" "${ahead:-0}" "${behind:-0}" "$state"
}
cmd_sync() {
  local target_issue=""
  if (($#)); then target_issue="$1"; fi

  local wt_path
  if [[ -n "$target_issue" ]]; then
    wt_path=$(_resolve_worktree_path_by_issue "$target_issue") \
      || { echo "sync: no worktree for issue #$target_issue" >&2; return 2; }
  else
    wt_path=$("$GIT_BIN" rev-parse --show-toplevel)
  fi

  ( cd "$wt_path"
    "$GIT_BIN" fetch -q origin master 2>/dev/null || true
    if ! "$GIT_BIN" rebase origin/master; then
      "$GIT_BIN" rebase --abort 2>/dev/null || true
      echo "sync: rebase conflict; aborted. Resolve manually." >&2
      return 3
    fi
  )
}

_resolve_worktree_path_by_issue() {
  local n="$1"
  local d
  for d in "$WORKTREE_ROOT"/"$n"-*; do
    if [[ -d "$d" ]]; then printf '%s' "$d"; return 0; fi
  done
  return 1
}
cmd_finish() {
  local dry_run=0
  while (($#)); do
    case "$1" in
      --dry-run) dry_run=1; shift ;;
      *) echo "finish: unexpected arg: $1" >&2; return 1 ;;
    esac
  done

  if ! "$GIT_BIN" diff-index --quiet HEAD --; then
    echo "finish: working tree dirty; commit or stash first" >&2; return 3
  fi

  local branch ; branch=$("$GIT_BIN" rev-parse --abbrev-ref HEAD)
  case "$branch" in
    feature/*|fix/*|docs/*|chore/*) : ;;
    *) echo "finish: not on an agent branch ($branch)" >&2; return 1 ;;
  esac

  local ahead
  ahead=$("$GIT_BIN" rev-list --count origin/master.."$branch" 2>/dev/null || echo 0)
  if [[ "$ahead" -eq 0 ]]; then
    echo "finish: branch has no commits ahead of origin/master" >&2; return 3
  fi

  local issue
  issue=$(printf '%s' "$branch" | sed -E 's|^[^/]+/([0-9]+)-.*|\1|')
  if [[ -z "$issue" || "$issue" == "$branch" ]]; then
    echo "finish: cannot parse issue number from branch '$branch'" >&2; return 1
  fi

  local issue_title
  issue_title=$("$GH_BIN" issue view "$issue" --json title 2>/dev/null \
    | sed -E 's/.*"title":"((\\.|[^"\\])*)".*/\1/')
  if [[ -z "$issue_title" || "$issue_title" == *'"title"'* ]]; then
    issue_title="$branch"
  fi

  if (( dry_run )); then
    echo "dry-run: would push $branch and open PR closing #$issue with title '$issue_title'"
    return 0
  fi

  if ! "$GIT_BIN" push -u origin "$branch" >/dev/null; then
    echo "finish: git push failed" >&2; return 4
  fi
  "$GH_BIN" pr create --base master --head "$branch" \
    --title "$issue_title" --body "Closes #$issue" \
    || return 4
}
cmd_clean() {
  local force=0
  local issue=""
  while (($#)); do
    case "$1" in
      --force) force=1; shift ;;
      -*) echo "clean: unknown flag $1" >&2; return 1 ;;
      *) issue="$1"; shift ;;
    esac
  done
  if [[ -z "$issue" ]]; then
    echo "clean: usage: clean <issue#>" >&2; return 1
  fi

  local wt_path
  wt_path=$(_resolve_worktree_path_by_issue "$issue") \
    || { echo "clean: no worktree for issue #$issue" >&2; return 2; }

  if ! "$GIT_BIN" -C "$wt_path" diff-index --quiet HEAD --; then
    echo "clean: worktree dirty: $wt_path" >&2; return 3
  fi

  local branch
  branch=$("$GIT_BIN" -C "$wt_path" rev-parse --abbrev-ref HEAD)

  if (( ! force )); then
    local pr_json state
    pr_json=$("$GH_BIN" pr view --head "$branch" --json state,mergedAt 2>/dev/null || true)
    state=$(printf '%s' "$pr_json" | sed -E 's/.*"state":"([^"]+)".*/\1/')
    if [[ "$state" != "MERGED" ]]; then
      echo "clean: PR for $branch is '$state', refusing (use --force)" >&2; return 3
    fi
  fi

  "$GIT_BIN" worktree remove "$wt_path"
  "$GIT_BIN" branch -d "$branch" 2>/dev/null \
    || "$GIT_BIN" branch -D "$branch"
  echo "removed: $wt_path branch=$branch"
}

main() {
  local sub="${1:-}"
  shift || true
  case "$sub" in
    -h|--help|help|"") usage ; return 0 ;;
    start)  cmd_start  "$@" ;;
    list)   cmd_list   "$@" ;;
    sync)   cmd_sync   "$@" ;;
    finish) cmd_finish "$@" ;;
    clean)  cmd_clean  "$@" ;;
    *) echo "unknown sub-command: $sub" >&2 ; usage >&2 ; return 1 ;;
  esac
}

main "$@"
