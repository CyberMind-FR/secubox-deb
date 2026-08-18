<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Multi-Agent Worktree Workflow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `scripts/agent-worktree.sh` (sub-commands `start`/`list`/`sync`/`finish`/`clean`), its test script, and add a `CLAUDE.md` doctrine section, so that every non-trivial task can be run in its own branch and isolated git worktree under `~/CyberMindStudio/secubox-deb-worktrees/`.

**Architecture:** One self-contained Bash script with sub-command dispatch. Helper functions (`derive_slug`, `prefix_from_labels`, etc.) are split into a small sourced library `scripts/lib/agent-worktree-lib.sh` to keep both file sizes manageable and unit-testable in isolation. `gh` and `git` are the only external dependencies and are mockable via `GH_BIN` / `GIT_BIN` env vars for tests.

**Tech Stack:** Bash (POSIX-leaning, `set -euo pipefail`), `gh` CLI for GitHub I/O, `git` for branch/worktree ops, plain shell tests (no bats, since it is not installed on this dev host).

**Spec:** `docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md`
**Tracking issue:** [#83 — Multi-agent worktree workflow](https://github.com/CyberMind-FR/secubox-deb/issues/83)

---

## File Structure

| Path | Responsibility |
|---|---|
| `scripts/agent-worktree.sh` | CLI entry point: arg parsing, sub-command dispatch, top-level error handling |
| `scripts/lib/agent-worktree-lib.sh` | Pure-ish helpers: slug derivation, label→prefix map, path resolution, gh/git wrappers |
| `scripts/tests/test-agent-worktree.sh` | Test harness; runs each test in a temporary throwaway repo with shimmed `gh` and `git` where appropriate |
| `scripts/tests/fixtures/gh-mock.sh` | Stub `gh` binary used by tests; emits canned JSON based on `GH_MOCK_*` env vars |
| `CLAUDE.md` | Add `## 🌿 Multi-Agent Worktree Workflow — Obligatoire` section |
| `scripts/README.md` | Add "Multi-Agent Worktrees" subsection pointing at the script |
| `.claude/HISTORY.md` | Final session entry on completion |

`scripts/lib/` already exists (per `ls scripts/`); the new library file slots into it without restructuring.

---

## Conventions used in every task

- Working directory: repo root (`/home/reepost/CyberMindStudio/secubox-deb/secubox-deb`).
- The whole feature is implemented on branch `feature/83-multi-agent-worktree-workflow` (created in Task 0).
- Run the test harness via `bash scripts/tests/test-agent-worktree.sh` from the repo root. The harness prints `OK <name>` / `FAIL <name>` per test and exits non-zero if any fail.
- Commit messages use conventional prefixes (`feat:`, `test:`, `docs:`, `chore:`) and reference the issue, e.g. `feat(scripts): add agent-worktree skeleton (ref #83)`.
- Every commit ends with the project Co-Authored-By line (per `CLAUDE.md`):

  ```
  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- All file paths in the plan are repo-relative.
- Shell library functions are tested by *sourcing* the library file in a sub-shell, not by spawning a child process — keeps tests fast and lets us assert on internal variables.

---

## Task 0: Branch, baseline, and helper directories

**Files:**
- Create: `scripts/lib/` (already exists — verify)
- Create: `scripts/tests/` (new directory)

- [ ] **Step 1: Create and switch to the feature branch**

```bash
git fetch origin
git checkout -b feature/83-multi-agent-worktree-workflow origin/master
```

Expected: `Switched to a new branch 'feature/83-multi-agent-worktree-workflow'`.

- [ ] **Step 2: Verify `scripts/lib/` exists, create `scripts/tests/`**

```bash
test -d scripts/lib && echo "lib OK" || mkdir -p scripts/lib
mkdir -p scripts/tests/fixtures
ls -d scripts/lib scripts/tests scripts/tests/fixtures
```

Expected: all three paths printed.

- [ ] **Step 3: Comment the GitHub issue**

```bash
gh issue comment 83 --body "Implementation started on branch \`feature/83-multi-agent-worktree-workflow\`. Plan: docs/superpowers/plans/2026-05-12-multi-agent-worktree-workflow.md"
```

Expected: a URL to the comment.

- [ ] **Step 4: Commit the empty test directory (with `.gitkeep`)**

```bash
echo "# test fixtures for agent-worktree.sh" > scripts/tests/README.md
git add scripts/tests/README.md
git commit -m "$(cat <<'EOF'
chore(scripts): scaffold tests directory for agent-worktree (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected: 1 file changed.

---

## Task 1: Mock `gh` fixture for tests

**Files:**
- Create: `scripts/tests/fixtures/gh-mock.sh`

The mock honors `GH_MOCK_ISSUE_<N>_TITLE`, `GH_MOCK_ISSUE_<N>_LABELS`, `GH_MOCK_ISSUE_<N>_EXIT`, `GH_MOCK_PR_<branch>_STATE`, `GH_MOCK_PR_<branch>_MERGED`. Anything not configured returns exit 2.

- [ ] **Step 1: Create the fixture**

```bash
cat > scripts/tests/fixtures/gh-mock.sh <<'SHELL'
#!/usr/bin/env bash
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
        for arg in "$@"; do
          case "$arg" in --head=*) branch="${arg#--head=}";; esac
        done
        if [[ -z "$branch" ]]; then branch="${1:-}"; fi
        var_state="GH_MOCK_PR_${branch//\//_}_STATE"
        var_merged="GH_MOCK_PR_${branch//\//_}_MERGED"
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
SHELL
chmod +x scripts/tests/fixtures/gh-mock.sh
```

- [ ] **Step 2: Smoke-check the mock manually**

```bash
GH_MOCK_ISSUE_42_TITLE="Hello world" \
GH_MOCK_ISSUE_42_LABELS="bug,documentation" \
  scripts/tests/fixtures/gh-mock.sh issue view 42 --json title,labels
```

Expected (single line JSON):
```
{"title":"Hello world","labels":[{"name":"bug"},{"name":"documentation"}]}
```

- [ ] **Step 3: Commit**

```bash
git add scripts/tests/fixtures/gh-mock.sh
git commit -m "$(cat <<'EOF'
test(scripts): add gh CLI mock for agent-worktree tests (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Library skeleton + `derive_slug`

**Files:**
- Create: `scripts/lib/agent-worktree-lib.sh`
- Create: `scripts/tests/test-agent-worktree.sh`

The library is sourced, never executed. `derive_slug` lowercases, transliterates accents to ASCII via `iconv`, replaces non-`[a-z0-9]` runs with `-`, trims dashes, truncates to 40 chars, and falls back to `issue` when empty.

- [ ] **Step 1: Write the test harness skeleton + first failing test**

```bash
cat > scripts/tests/test-agent-worktree.sh <<'SHELL'
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
  assert_eq "add-tier-manifest-helper-for-apt" "$(derive_slug 'Add tier-manifest helper for APT staging')" "basic slug"
}

# Auto-discover and run
mapfile -t tests < <(declare -F | awk '{print $3}' | grep '^test_')
for t in "${tests[@]}"; do run_test "$t"; done

echo "---"
echo "passed: $pass  failed: $fail"
exit $((fail > 0))
SHELL
chmod +x scripts/tests/test-agent-worktree.sh
```

- [ ] **Step 2: Run the harness to confirm the test fails**

```bash
bash scripts/tests/test-agent-worktree.sh
```

Expected: `FAIL test_derive_slug_basic` with error mentioning `derive_slug: command not found`. Exit code 1.

- [ ] **Step 3: Implement the library minimally to pass the test**

```bash
cat > scripts/lib/agent-worktree-lib.sh <<'SHELL'
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
  s="${s:0:40}"
  s="${s%-}"
  if [[ -z "$s" ]]; then s="issue"; fi
  printf '%s' "$s"
}
SHELL
```

- [ ] **Step 4: Re-run the harness; confirm the test passes**

```bash
bash scripts/tests/test-agent-worktree.sh
```

Expected: `OK   test_derive_slug_basic`. Exit 0.

- [ ] **Step 5: Add the remaining slug edge-case tests, watch them fail then pass**

Append to `scripts/tests/test-agent-worktree.sh` *before* the auto-discover block:

```bash
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
```

Run:
```bash
bash scripts/tests/test-agent-worktree.sh
```

All four `test_derive_slug_*` tests must pass. If `iconv` returns empty for fully non-ASCII inputs, the `[[ -z "$s" ]]` fallback handles it — verify the `日本語のみ` case prints `issue`.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/agent-worktree-lib.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): add agent-worktree library with derive_slug (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `prefix_from_labels` helper

**Files:**
- Modify: `scripts/lib/agent-worktree-lib.sh`
- Modify: `scripts/tests/test-agent-worktree.sh`

Spec mapping: `bug|fix` → `fix/`, `documentation` → `docs/`, `infra|chore` → `chore/`, default → `feature/`. First matching label wins (in the order returned by `gh`).

- [ ] **Step 1: Add failing tests**

Append to `scripts/tests/test-agent-worktree.sh` (before the auto-discover block):

```bash
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
```

Run; expect 6 failures with `prefix_from_labels: command not found`.

- [ ] **Step 2: Implement**

Append to `scripts/lib/agent-worktree-lib.sh`:

```bash
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
```

- [ ] **Step 3: Re-run, all tests pass**

```bash
bash scripts/tests/test-agent-worktree.sh
```

Expected: 10 OK, 0 FAIL.

- [ ] **Step 4: Commit**

```bash
git add scripts/lib/agent-worktree-lib.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): add prefix_from_labels helper (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Main script skeleton + `--help` + dispatch

**Files:**
- Create: `scripts/agent-worktree.sh`
- Modify: `scripts/tests/test-agent-worktree.sh`

- [ ] **Step 1: Failing tests for help and unknown sub-command**

Append before the auto-discover block in `scripts/tests/test-agent-worktree.sh`:

```bash
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
```

Run; expect failures because the script does not exist.

- [ ] **Step 2: Create the script with sub-command dispatch**

```bash
cat > scripts/agent-worktree.sh <<'SHELL'
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
SHELL
chmod +x scripts/agent-worktree.sh
```

- [ ] **Step 3: Re-run the harness**

```bash
bash scripts/tests/test-agent-worktree.sh
```

Expected: `test_script_help_exits_zero` and `test_script_unknown_subcommand_exits_1` both OK. Previous library tests still OK.

- [ ] **Step 4: Commit**

```bash
git add scripts/agent-worktree.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): add agent-worktree CLI skeleton with help and dispatch (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `start` sub-command — happy path

**Files:**
- Modify: `scripts/agent-worktree.sh`
- Modify: `scripts/lib/agent-worktree-lib.sh` (add `branch_from_issue`)
- Modify: `scripts/tests/test-agent-worktree.sh`

This task implements `start` on a sandbox repo created inside each test. The library exposes `branch_from_issue <N> <gh_json>` that returns the branch name string.

- [ ] **Step 1: Add a sandbox-repo helper to the test harness**

Append above the `# Tests below` line in `scripts/tests/test-agent-worktree.sh`:

```bash
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
```

- [ ] **Step 2: Failing test for `branch_from_issue`**

Append before the discovery loop:

```bash
test_branch_from_issue_chore() {
  source "$LIB"
  local json='{"title":"Add tier-manifest helper for APT staging","labels":[{"name":"infra"}]}'
  assert_eq "chore/80-add-tier-manifest-helper-for-apt-stagi" "$(branch_from_issue 80 "$json")" "infra issue"
}

test_branch_from_issue_default_feature() {
  source "$LIB"
  local json='{"title":"Multi-agent worktree workflow","labels":[{"name":"enhancement"}]}'
  assert_eq "feature/83-multi-agent-worktree-workflow" "$(branch_from_issue 83 "$json")" "default feature"
}
```

Run; both fail (`branch_from_issue` undefined).

- [ ] **Step 3: Implement `branch_from_issue` in the library**

Append to `scripts/lib/agent-worktree-lib.sh`:

```bash
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
```

Verify the truncation math: `chore/` + `80-` + slug (max 40) → 6 + 3 + 40 = 49 chars max. The test asserts the exact 40-char truncated slug.

- [ ] **Step 4: Re-run; both tests pass**

```bash
bash scripts/tests/test-agent-worktree.sh
```

- [ ] **Step 5: Failing test for `start` happy path**

Append before the discovery loop:

```bash
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
```

Run; fails (`start: not implemented`).

- [ ] **Step 6: Implement `cmd_start`**

Replace the stub `cmd_start()` in `scripts/agent-worktree.sh` with:

```bash
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
```

- [ ] **Step 7: Re-run; happy path passes**

```bash
bash scripts/tests/test-agent-worktree.sh
```

If the harness reports "branch fix/42-hello-world missing", confirm that the sandbox `make_sandbox_repo` indeed sets `origin/master` (Step 1) and that `cmd_start` uses `origin/master` as the start-point.

- [ ] **Step 8: Commit**

```bash
git add scripts/agent-worktree.sh scripts/lib/agent-worktree-lib.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): implement agent-worktree start sub-command (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `start` edge cases

**Files:**
- Modify: `scripts/tests/test-agent-worktree.sh`

- [ ] **Step 1: Add edge-case tests, expect them to pass against current implementation**

Append before the discovery loop:

```bash
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
```

- [ ] **Step 2: Run; verify all five new tests pass**

```bash
bash scripts/tests/test-agent-worktree.sh
```

If a test fails, fix the corresponding logic in `cmd_start` (most likely cause: an exit code mismatch). Re-run until all pass.

- [ ] **Step 3: Commit**

```bash
git add scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
test(scripts): cover agent-worktree start edge cases (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `list` sub-command

**Files:**
- Modify: `scripts/agent-worktree.sh`
- Modify: `scripts/tests/test-agent-worktree.sh`

`list` calls `git worktree list --porcelain`, prints one line per worktree under `WORKTREE_ROOT`: `<branch>  <path>  ahead:<N> behind:<N> <clean|dirty>`. Worktrees outside `WORKTREE_ROOT` (e.g. the primary checkout) are listed too but tagged `[primary]`.

- [ ] **Step 1: Failing test**

```bash
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
```

- [ ] **Step 2: Implement `cmd_list`**

Replace the stub:

```bash
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
```

- [ ] **Step 3: Run; new test passes, no regressions**

```bash
bash scripts/tests/test-agent-worktree.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/agent-worktree.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): implement agent-worktree list sub-command (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `sync` sub-command

**Files:**
- Modify: `scripts/agent-worktree.sh`
- Modify: `scripts/tests/test-agent-worktree.sh`

`sync` rebases the current branch on `origin/master`. Optional positional `<N>` resolves the worktree by issue number and `git -C` operates on it. On rebase conflict, abort and exit 3.

- [ ] **Step 1: Failing tests**

```bash
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
```

- [ ] **Step 2: Implement `cmd_sync`**

```bash
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
    "$GIT_BIN" fetch -q origin master
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
```

- [ ] **Step 3: Run; verify**

```bash
bash scripts/tests/test-agent-worktree.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/agent-worktree.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): implement agent-worktree sync sub-command (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `finish` sub-command

**Files:**
- Modify: `scripts/agent-worktree.sh`
- Modify: `scripts/tests/test-agent-worktree.sh`

`finish` must be run inside a worktree. Refuses if dirty or zero commits ahead of `origin/master`. Otherwise pushes (`git push -u`) and creates the PR with `Closes #<N>` in the body, where `<N>` is parsed from the branch name `<prefix>/<N>-<slug>`. Worktree is NOT removed.

- [ ] **Step 1: Failing tests**

```bash
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
```

- [ ] **Step 2: Implement `cmd_finish`**

```bash
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

  if (( dry_run )); then
    echo "dry-run: would push $branch and open PR closing #$issue"
    return 0
  fi

  "$GIT_BIN" push -u origin "$branch" >/dev/null
  "$GH_BIN" pr create --base master --head "$branch" \
    --title "$branch" --body "Closes #$issue" \
    || return 4
}
```

- [ ] **Step 3: Run; both tests pass**

```bash
bash scripts/tests/test-agent-worktree.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/agent-worktree.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): implement agent-worktree finish sub-command (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: `clean` sub-command

**Files:**
- Modify: `scripts/agent-worktree.sh`
- Modify: `scripts/tests/test-agent-worktree.sh`

`clean <N>` resolves the worktree by issue, refuses if dirty, checks PR state (via mock), removes worktree, deletes the branch.

- [ ] **Step 1: Failing tests**

```bash
test_clean_refuses_open_pr() {
  local repo wt
  repo=$(make_sandbox_repo); wt=$(mktemp -d)
  trap "rm -rf $repo $wt" RETURN
  export GH_BIN="$GH_MOCK"; export GH_MOCK_AUTH=ok
  export GH_MOCK_ISSUE_11_TITLE="C"; export GH_MOCK_ISSUE_11_LABELS=""
  export GH_MOCK_PR_feature_11-c_STATE="OPEN"
  export GH_MOCK_PR_feature_11-c_MERGED=""
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
  export GH_MOCK_PR_feature_12-c_STATE="MERGED"
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
```

(Note: the mock env-var name dot/slash mangling — `feature/11-c` becomes `feature_11-c`. Match exactly.)

- [ ] **Step 2: Implement `cmd_clean`**

```bash
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
```

- [ ] **Step 3: Run; verify**

```bash
bash scripts/tests/test-agent-worktree.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/agent-worktree.sh scripts/tests/test-agent-worktree.sh
git commit -m "$(cat <<'EOF'
feat(scripts): implement agent-worktree clean sub-command (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: CLAUDE.md doctrine section

**Files:**
- Modify: `CLAUDE.md` (insert new section after `## 🔑 Règles impératives`)

- [ ] **Step 1: Locate the insertion point**

```bash
grep -n "🔑 Règles impératives" CLAUDE.md
```

Expected: one line number. The new section is inserted immediately *after* that section and *before* the next `## ` heading.

- [ ] **Step 2: Insert the section**

Use `Edit` on `CLAUDE.md`. Identify the unique line that ends the existing "Règles impératives" block (the next `## ` heading line — e.g. `## 🔒 Security Policies — Héritées …`). Insert the following block immediately before that next heading:

```markdown
---

## 🌿 Multi-Agent Worktree Workflow — Obligatoire

Chaque travail non-trivial doit s'exécuter dans un worktree dédié, créé via
`scripts/agent-worktree.sh start --issue <#>`. Le checkout principal
(`~/CyberMindStudio/secubox-deb/secubox-deb/`) est réservé au `master`
housekeeping et au travail humain — pas aux agents.

### Quand créer un worktree

- Toute issue GitHub avec label `bug`, `enhancement`, `documentation`,
  `eye-remote`, ou tout label métier (migration, hardware, api, frontend,
  security, infra)
- Toute tâche estimée > 30 min ou touchant ≥ 3 fichiers
- Toute feature/fix qui finira en PR

### Quand NE PAS en créer

- Édition triviale d'un seul fichier de suivi (`HISTORY.md`, `WIP.md`,
  `TODO.md`)
- Exploration read-only, réponse à une question
- Commits administratifs sur master (tags, bumps de version)

### Cycle obligatoire

```
gh issue create
  → scripts/agent-worktree.sh start --issue <#>
  → cd ~/CyberMindStudio/secubox-deb-worktrees/<#>-<slug>
  → code + commits (chaque message: "(ref #<#>)")
  → scripts/agent-worktree.sh finish     # push + PR avec "Closes #<#>"
  → [user valide et merge la PR]
  → scripts/agent-worktree.sh clean <#>  # supprime worktree + branche
```

### Parallélisme

`start` refuse de créer un second worktree pour la même issue. Deux sessions
Claude (deux terminaux) peuvent travailler simultanément sur deux issues
distinctes sans collision.

### Source de vérité opérationnelle

`scripts/agent-worktree.sh --help`

---
```

- [ ] **Step 3: Verify the file still parses as Markdown (smoke check)**

```bash
grep -c "^## " CLAUDE.md
```

Compare to the value before the edit: expect exactly +1.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs: add multi-agent worktree workflow doctrine to CLAUDE.md (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: scripts/README.md update

**Files:**
- Modify: `scripts/README.md`

- [ ] **Step 1: Add a new section after "Package Scaffolding"**

Use `Edit` on `scripts/README.md`. Locate the section header `## Package Scaffolding` and the next `## ` heading after it. Insert this block before that next heading:

```markdown
---

## Multi-Agent Worktrees

| Script | Description |
|--------|-------------|
| `agent-worktree.sh` | Lifecycle helper for one-branch-per-issue work in isolated git worktrees |

### Usage

```bash
# Create a worktree bound to GitHub issue #83
bash scripts/agent-worktree.sh start --issue 83
cd ~/CyberMindStudio/secubox-deb-worktrees/83-multi-agent-worktree-workflow

# List active worktrees + ahead/behind/dirty status
bash scripts/agent-worktree.sh list

# Rebase the current worktree on origin/master
bash scripts/agent-worktree.sh sync

# Push and open the PR (`Closes #83` in body)
bash scripts/agent-worktree.sh finish

# After merge, remove the worktree and local branch
bash scripts/agent-worktree.sh clean 83
```

See `scripts/agent-worktree.sh --help` for the full reference and
`docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md`
for the design rationale.
```

- [ ] **Step 2: Commit**

```bash
git add scripts/README.md
git commit -m "$(cat <<'EOF'
docs(scripts): document agent-worktree in scripts/README (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: HISTORY.md entry + final test run

**Files:**
- Modify: `.claude/HISTORY.md`

- [ ] **Step 1: Run the full test suite one last time**

```bash
bash scripts/tests/test-agent-worktree.sh
```

Expected: all tests OK, `passed: <N>  failed: 0`.

- [ ] **Step 2: Prepend an entry to `.claude/HISTORY.md`**

Open `.claude/HISTORY.md` with `Edit`. Find the most recent date heading (`## 2026-05-12` or whatever is at the top), and insert a new `### Session N+1` block above the previous session under that date — or under a new date heading if today differs.

```markdown
### Session 152 — Multi-Agent Worktree Workflow

**Goal:** Enable parallel multi-agent work via one-branch-per-issue isolated worktrees.

**Delivered:**

- `scripts/agent-worktree.sh` with sub-commands `start`, `list`, `sync`, `finish`, `clean`
- `scripts/lib/agent-worktree-lib.sh` (slug + label→prefix helpers)
- Test suite `scripts/tests/test-agent-worktree.sh` (~15 cases, no bats dep)
- `gh` CLI mock at `scripts/tests/fixtures/gh-mock.sh`
- New section in `CLAUDE.md`: `## 🌿 Multi-Agent Worktree Workflow — Obligatoire`
- `scripts/README.md` updated with usage

**Issue:** #83. **Spec:** `docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md`. **Plan:** `docs/superpowers/plans/2026-05-12-multi-agent-worktree-workflow.md`.
```

- [ ] **Step 3: Commit**

```bash
git add .claude/HISTORY.md
git commit -m "$(cat <<'EOF'
docs: add HISTORY.md entry for multi-agent worktree workflow (ref #83)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Push the branch and open the PR via the new script (dogfood)**

```bash
bash scripts/agent-worktree.sh finish
```

Expected output: PR URL printed. The PR body will contain `Closes #83`.

If `finish` complains about being run outside the worktree root (because we implemented the feature *inside* the primary checkout — the chicken-and-egg case), fall back to:

```bash
git push -u origin feature/83-multi-agent-worktree-workflow
gh pr create --base master --title "Multi-agent worktree workflow" --body "Closes #83"
```

- [ ] **Step 5: Comment on the issue summarizing completion**

```bash
gh issue comment 83 --body "Implementation complete on branch \`feature/83-multi-agent-worktree-workflow\`, PR opened. Pending user validation."
```

---

## Final Self-Review (run by author of the plan, not by an executor)

- **Spec coverage:** every section of the spec maps to a task — script (Tasks 4–10), slug/prefix (Tasks 2–3), CLAUDE.md doctrine (Task 11), tests (interleaved), README update (Task 12), HISTORY entry (Task 13). ✓
- **Type/name consistency:** `branch_from_issue` is defined Task 5 Step 3 and reused as-is in `cmd_start`. `_resolve_worktree_path_by_issue` defined Task 8 Step 2, reused Task 10. ✓
- **No placeholders:** all steps contain literal commands or code blocks. Where the plan tells the executor to insert a section into an existing file, the exact Markdown to insert is shown verbatim. ✓
- **Chicken-and-egg note:** Task 13 Step 4 explicitly handles the case where the script cannot dogfood itself because development happened in the primary checkout. ✓
