#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Test harness for scripts/agent-worktree.sh
# Each `test_*` function is auto-discovered and run in a subshell.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/agent-worktree-lib.sh"
SCRIPT="$REPO_ROOT/scripts/agent-worktree.sh"
GH_MOCK="$REPO_ROOT/scripts/tests/fixtures/gh-mock.sh"
GIT_BIN="${GIT_BIN:-git}"

pass=0
fail=0
failed_names=()

run_test() {
  local name="$1"
  local out
  if out=$(set -e; "$name" 2>&1); then
    echo "OK   $name"
    pass=$((pass+1))
  else
    echo "FAIL $name"
    echo "$out" | sed 's/^/     /'
    fail=$((fail+1))
    failed_names+=("$name")
  fi
}

assert_eq() {
  local expected="$1" actual="$2" label="${3:-value}"
  if [[ "$expected" != "$actual" ]]; then
    echo "$label mismatch: expected '$expected' got '$actual'" >&2
    return 1
  fi
}

assert_contains() {
  local haystack="$1" needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected to contain '$needle' in: $haystack" >&2
    return 1
  fi
}

# Make a throwaway repo with one commit on master; returns its path on stdout.
make_sandbox_repo() {
  local dir
  dir=$(mktemp -d)
  (
    cd "$dir"
    "$GIT_BIN" init -q -b master
    git config user.email "t@t" ; git config user.name "t"
    echo "hello" > README.md
    git add README.md
    git commit -q -m "init"
    # Simulate an origin/master so worktree-add can use it
    git update-ref refs/remotes/origin/master HEAD
  )
  printf '%s' "$dir"
}

# Tests below

test_derive_slug_basic() {
  source "$LIB"
  assert_eq "add-tier-manifest-helper-for-apt-staging" "$(derive_slug 'Add tier-manifest helper for APT staging')" "basic slug"
}

test_derive_slug_accents() {
  source "$LIB"
  assert_eq "migration-verification-a-valider" "$(derive_slug 'Migration vérification à valider')" "accents"
}

test_derive_slug_truncate_40() {
  source "$LIB"
  local out
  out=$(derive_slug 'this title is intentionally far too long to fit in forty characters')
  assert_eq "40" "${#out}" "length"
  assert_eq "this-title-is-intentionally-far-too-long" "$out" "truncated value"
}

test_derive_slug_empty_falls_back() {
  source "$LIB"
  assert_eq "issue" "$(derive_slug '')" "empty input"
  assert_eq "issue" "$(derive_slug '日本語のみ')" "all non-ASCII"
}

test_prefix_default_when_no_labels() {
  source "$LIB"
  assert_eq "feature/" "$(prefix_from_labels '')" "no labels"
}

test_prefix_bug_label() {
  source "$LIB"
  assert_eq "fix/" "$(prefix_from_labels 'bug')" "bug label"
  assert_eq "fix/" "$(prefix_from_labels 'fix')" "fix label"
}

test_prefix_documentation_label() {
  source "$LIB"
  assert_eq "docs/" "$(prefix_from_labels 'documentation')" "documentation label"
}

test_prefix_infra_chore_label() {
  source "$LIB"
  assert_eq "chore/" "$(prefix_from_labels 'infra')" "infra label"
  assert_eq "chore/" "$(prefix_from_labels 'chore')" "chore label"
}

test_prefix_unknown_label_defaults_feature() {
  source "$LIB"
  assert_eq "feature/" "$(prefix_from_labels 'enhancement,question')" "unknown labels"
}

test_prefix_first_match_wins() {
  source "$LIB"
  # bug appears first → fix/, even if documentation also present
  assert_eq "fix/" "$(prefix_from_labels 'bug,documentation')" "first match"
}

test_script_help_exits_zero() {
  local out
  out=$(bash "$SCRIPT" --help 2>&1)
  assert_eq "0" "$?" "help exit"
  assert_contains "$out" "agent-worktree.sh"
  assert_contains "$out" "start"
  assert_contains "$out" "list"
  assert_contains "$out" "sync"
  assert_contains "$out" "finish"
  assert_contains "$out" "clean"
}

test_script_unknown_subcommand_exits_1() {
  local out rc
  out=$(bash "$SCRIPT" wibble 2>&1) ; rc=$?
  if [[ $rc -ne 1 ]]; then echo "expected rc=1, got $rc; out=$out" >&2; return 1; fi
  assert_contains "$out" "unknown"
}

test_branch_from_issue_chore() {
  source "$LIB"
  local json='{"title":"Add tier-manifest helper for APT staging","labels":[{"name":"infra"}]}'
  assert_eq "chore/80-add-tier-manifest-helper-for-apt-staging" "$(branch_from_issue 80 "$json")" "infra issue"
}

test_branch_from_issue_default_feature() {
  source "$LIB"
  local json='{"title":"Multi-agent worktree workflow","labels":[{"name":"enhancement"}]}'
  assert_eq "feature/83-multi-agent-worktree-workflow" "$(branch_from_issue 83 "$json")" "default feature"
}

test_start_happy_path() {
  local repo wt_root
  repo=$(make_sandbox_repo)
  wt_root="$(mktemp -d)"
  trap "rm -rf $repo $wt_root" RETURN

  export GH_BIN="$GH_MOCK"
  export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_42_TITLE="Hello world"
  export GH_MOCK_ISSUE_42_LABELS="bug"
  export WORKTREE_ROOT="$wt_root"

  (cd "$repo" && bash "$SCRIPT" start --issue 42) >/dev/null

  # Branch exists locally
  (cd "$repo" && git rev-parse --verify "fix/42-hello-world") >/dev/null \
    || { echo "branch fix/42-hello-world missing" >&2; return 1; }

  # Worktree dir exists
  test -d "$wt_root/42-hello-world" \
    || { echo "worktree dir missing" >&2; return 1; }
}

test_start_missing_issue_flag() {
  export GH_BIN="$GH_MOCK"
  local out rc
  out=$(bash "$SCRIPT" start 2>&1) ; rc=$?
  if [[ $rc -ne 1 ]]; then echo "rc=$rc out=$out" >&2; return 1; fi
  assert_contains "$out" "--issue"
}

test_start_unknown_issue_exits_2() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_999_EXIT=2
  export WORKTREE_ROOT="$wt"
  local rc
  (cd "$repo" && bash "$SCRIPT" start --issue 999) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 2 ]]; then echo "expected rc=2 got $rc" >&2; return 1; fi
}

test_start_dirty_repo_exits_3() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  (cd "$repo" && echo dirty > newfile && git add newfile)
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_1_TITLE="t"; export GH_MOCK_ISSUE_1_LABELS=""
  export WORKTREE_ROOT="$wt"
  local rc
  (cd "$repo" && bash "$SCRIPT" start --issue 1) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 3 ]]; then echo "expected rc=3 got $rc" >&2; return 1; fi
}

test_start_twice_same_issue_refuses() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_7_TITLE="Same"; export GH_MOCK_ISSUE_7_LABELS=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 7) >/dev/null
  local rc
  (cd "$repo" && bash "$SCRIPT" start --issue 7) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 3 ]]; then echo "expected rc=3 got $rc" >&2; return 1; fi
}

test_start_dry_run_no_side_effects() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_5_TITLE="Dry"; export GH_MOCK_ISSUE_5_LABELS=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 5 --dry-run) >/dev/null
  # No branch should exist
  (cd "$repo" && git show-ref --verify --quiet refs/heads/feature/5-dry) \
    && { echo "branch leaked in dry-run" >&2; return 1; }
  test -d "$wt/5-dry" && { echo "worktree leaked in dry-run" >&2; return 1; }
  return 0
}

test_list_shows_worktree() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_3_TITLE="L"; export GH_MOCK_ISSUE_3_LABELS=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 3) >/dev/null
  local out
  out=$(cd "$repo" && bash "$SCRIPT" list)
  assert_contains "$out" "feature/3-l"
  assert_contains "$out" "$wt/3-l"
}

test_sync_clean_rebase() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_9_TITLE="Sync"; export GH_MOCK_ISSUE_9_LABELS=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 9) >/dev/null
  # Advance origin/master by one commit
  (cd "$repo" && echo more >> README.md && git commit -aq -m "more" && \
     git update-ref refs/remotes/origin/master HEAD~0)
  # Move HEAD back so origin/master is "ahead" of the worktree branch
  (cd "$repo" && git update-ref refs/remotes/origin/master HEAD)
  local rc
  (cd "$wt/9-sync" && bash "$SCRIPT" sync) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 0 ]]; then echo "expected rc=0 got $rc" >&2; return 1; fi
}

test_finish_refuses_zero_commits() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_4_TITLE="F"; export GH_MOCK_ISSUE_4_LABELS=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 4) >/dev/null
  local rc
  (cd "$wt/4-f" && bash "$SCRIPT" finish) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 3 ]]; then echo "expected rc=3 got $rc" >&2; return 1; fi
}

test_finish_dirty_refuses() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_6_TITLE="F"; export GH_MOCK_ISSUE_6_LABELS=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 6) >/dev/null
  (cd "$wt/6-f" && echo dirty > new && git add new)
  local rc
  (cd "$wt/6-f" && bash "$SCRIPT" finish) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 3 ]]; then echo "expected rc=3 got $rc" >&2; return 1; fi
}

test_clean_refuses_open_pr() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_11_TITLE="C"; export GH_MOCK_ISSUE_11_LABELS=""
  export GH_MOCK_PR_feature_11_c_STATE="OPEN"
  export GH_MOCK_PR_feature_11_c_MERGED=""
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 11) >/dev/null
  local rc
  (cd "$repo" && bash "$SCRIPT" clean 11) >/dev/null 2>&1 ; rc=$?
  if [[ $rc -ne 3 ]]; then echo "expected rc=3 got $rc" >&2; return 1; fi
}

test_clean_merged_pr_removes() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_12_TITLE="C"; export GH_MOCK_ISSUE_12_LABELS=""
  export GH_MOCK_PR_feature_12_c_STATE="MERGED"
  export WORKTREE_ROOT="$wt"
  (cd "$repo" && bash "$SCRIPT" start --issue 12) >/dev/null
  # Make a real commit on the branch then fold into master so branch is "merged"
  (cd "$wt/12-c" && echo x > x && git add x && git commit -q -m "x")
  (cd "$repo" && git merge --no-ff -q feature/12-c)
  (cd "$repo" && bash "$SCRIPT" clean 12) >/dev/null
  test -d "$wt/12-c" && { echo "worktree still present" >&2; return 1; }
  (cd "$repo" && git show-ref --verify --quiet refs/heads/feature/12-c) \
    && { echo "branch still present" >&2; return 1; }
  return 0
}

# Auto-discover and run
mapfile -t tests < <(declare -F | awk '{print $3}' | grep '^test_')
for t in "${tests[@]}"; do run_test "$t"; done

echo "---"
echo "passed: $pass  failed: $fail"
exit $((fail > 0))
