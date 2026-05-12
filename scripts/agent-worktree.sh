#!/usr/bin/env bash
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

cmd_start()  { echo "start: not implemented" >&2 ; return 1; }
cmd_list()   { echo "list: not implemented"  >&2 ; return 1; }
cmd_sync()   { echo "sync: not implemented"  >&2 ; return 1; }
cmd_finish() { echo "finish: not implemented" >&2; return 1; }
cmd_clean()  { echo "clean: not implemented" >&2 ; return 1; }

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
