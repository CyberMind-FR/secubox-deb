#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Minimal `gh` stand-in for agent-worktree tests.
# Implements just the verbs the script invokes.
set -u

cmd="${1:-}"; shift || true

case "$cmd" in
  auth)
    sub="${1:-}"
    if [[ "$sub" == "status" ]]; then
      if [[ "${GH_MOCK_AUTH:-ok}" == "ok" ]]; then exit 0; else exit 1; fi
    fi
    ;;
  issue)
    sub="${1:-}"; shift || true
    case "$sub" in
      view)
        num="${1:-}"; shift || true
        var_exit="GH_MOCK_ISSUE_${num}_EXIT"
        if [[ -n "${!var_exit:-}" ]]; then exit "${!var_exit}"; fi
        var_title="GH_MOCK_ISSUE_${num}_TITLE"
        var_labels="GH_MOCK_ISSUE_${num}_LABELS"
        title="${!var_title:-Missing title}"
        labels="${!var_labels:-}"
        labels_json=""
        if [[ -n "$labels" ]]; then
          IFS=',' read -r -a arr <<< "$labels"
          for l in "${arr[@]}"; do
            labels_json+="{\"name\":\"$l\"},"
          done
          labels_json="${labels_json%,}"
        fi
        printf '{"title":%s,"labels":[%s]}\n' "$(printf '"%s"' "$title")" "$labels_json"
        exit 0
        ;;
      comment)
        # always succeed; record the body in a side file if requested
        if [[ -n "${GH_MOCK_RECORD:-}" ]]; then
          echo "comment $*" >> "$GH_MOCK_RECORD"
        fi
        exit 0
        ;;
    esac
    ;;
  pr)
    sub="${1:-}"; shift || true
    case "$sub" in
      view|list)
        # Look up by --head or by branch arg
        branch=""
        _prev=""
        for arg in "$@"; do
          if [[ "$_prev" == "--head" ]]; then branch="$arg"; fi
          case "$arg" in --head=*) branch="${arg#--head=}";; esac
          _prev="$arg"
        done
        if [[ -z "$branch" ]]; then branch="${1:-}"; fi
        sanitized="${branch//\//_}"
        sanitized="${sanitized//-/_}"
        var_state="GH_MOCK_PR_${sanitized}_STATE"
        var_merged="GH_MOCK_PR_${sanitized}_MERGED"
        state="${!var_state:-MERGED}"
        merged="${!var_merged:-2026-05-12T10:00:00Z}"
        printf '{"state":"%s","mergedAt":"%s"}\n' "$state" "$merged"
        exit 0
        ;;
      create)
        if [[ -n "${GH_MOCK_RECORD:-}" ]]; then
          echo "pr create $*" >> "$GH_MOCK_RECORD"
        fi
        echo "https://github.com/test/repo/pull/999"
        exit 0
        ;;
    esac
    ;;
esac
echo "gh-mock: unhandled invocation: $cmd $*" >&2
exit 2
