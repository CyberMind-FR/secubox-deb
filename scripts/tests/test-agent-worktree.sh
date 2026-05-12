#!/usr/bin/env bash
# Test harness for scripts/agent-worktree.sh
# Each `test_*` function is auto-discovered and run in a subshell.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/agent-worktree-lib.sh"
SCRIPT="$REPO_ROOT/scripts/agent-worktree.sh"
GH_MOCK="$REPO_ROOT/scripts/tests/fixtures/gh-mock.sh"

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

# Auto-discover and run
mapfile -t tests < <(declare -F | awk '{print $3}' | grep '^test_')
for t in "${tests[@]}"; do run_test "$t"; done

echo "---"
echo "passed: $pass  failed: $fail"
exit $((fail > 0))
