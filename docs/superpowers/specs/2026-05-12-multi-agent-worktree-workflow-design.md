<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Multi-Agent Worktree Workflow — Design

**Date:** 2026-05-12
**Status:** Approved (brainstorming complete)
**Author:** Gérald Kerma (Gandalf) + Claude
**Topic:** Enable parallel multi-agent work via git worktrees, one branch per task

---

## 1. Context & Motivation

The SecuBox-DEB repo hosts multiple long-running feature branches (`feature/eye-remote-auto-mode`, `feature/license-headers`, etc.) and a strict GitHub Issues workflow defined in `CLAUDE.md`. Today, all agent work happens in the single primary checkout at `~/CyberMindStudio/secubox-deb/secubox-deb/`. This prevents two Claude sessions (or any two agents) from working in parallel without stepping on each other's working tree, and makes context-switching slow (stash/checkout/stash).

**Goal:** allow each task to live in its own branch *and* its own working directory (git worktree), with a single helper script enforcing a consistent lifecycle bound to GitHub issues.

## 2. Scope

**In scope**
- One bash helper script (`scripts/agent-worktree.sh`) with sub-commands `start`, `list`, `sync`, `finish`, `clean`.
- External worktree root at `~/CyberMindStudio/secubox-deb-worktrees/`.
- Mandatory GitHub Issue before any branch is created.
- New section in `CLAUDE.md` (`## 🌿 Multi-Agent Worktree Workflow — Obligatoire`) documenting the doctrine.
- Test suite covering happy path and edge cases (~12 tests).

**Out of scope (YAGNI)**
- No Claude Code session-start hook enforcing worktree usage.
- No CI guard rejecting PRs without a linked issue.
- No multi-user support (the path is per-developer).
- No auto-merge, no auto-close of issues.
- No deep integration with `superpowers:using-git-worktrees` (that skill remains usable independently).

## 3. Architecture

### 3.1 File layout

```
secubox-deb/
├── scripts/
│   ├── agent-worktree.sh          ← new, executable
│   └── tests/
│       └── test-agent-worktree.bats   ← new (or .sh fallback)
├── CLAUDE.md                      ← new section added
└── docs/superpowers/specs/
    └── 2026-05-12-multi-agent-worktree-workflow-design.md  ← this file
```

### 3.2 Worktree layout on disk

```
~/CyberMindStudio/
├── secubox-deb/secubox-deb/              ← primary checkout (master / human work)
└── secubox-deb-worktrees/                ← created on first `start`
    ├── 80-apt-tier-manifest-helper/      ← worktree for issue #80
    ├── 77-hyperpixel-init/
    └── 78-eye-agent-imports/
```

Each subfolder is a real git worktree (`git worktree add`), pointing to the same `.git/` as the primary checkout.

### 3.3 Branch naming

`<prefix>/<issue#>-<slug>` — derived from issue labels:

| GitHub label                         | Prefix     |
|--------------------------------------|------------|
| `bug`, `fix`                         | `fix/`     |
| `documentation`                      | `docs/`    |
| `infra`, `chore`                     | `chore/`   |
| anything else (default)              | `feature/` |

`<slug>` is the issue title, lowercased, ASCII-folded, non-alphanumerics → `-`, collapsed dashes, trimmed, **max 40 chars**. Empty slug → fallback `issue`. Collision with existing branch → suffix `-2`, `-3`, …

Examples:
- Issue #80 "Add tier-manifest helper for APT staging" + label `infra` → `chore/80-add-tier-manifest-helper-for-apt`
- Issue #77 "Hyperpixel init fails on cold boot" + label `bug` → `fix/77-hyperpixel-init-fails-on-cold-boot`

## 4. Script Interface (`scripts/agent-worktree.sh`)

### 4.1 `start --issue <N>`

1. Validate preconditions:
   - `gh` is on `PATH` and authenticated (`gh auth status`)
   - Current repo working tree is clean (no uncommitted changes)
   - We are NOT already inside a worktree under `~/CyberMindStudio/secubox-deb-worktrees/`
2. Fetch issue metadata: `gh issue view <N> --json title,labels`
3. Compute prefix (from labels) and slug (from title), assemble `<branch>`.
4. `git fetch origin master`
5. `git worktree add ~/CyberMindStudio/secubox-deb-worktrees/<#>-<slug> -b <branch> origin/master`
6. Copy `.claude/settings.local.json` from primary into the new worktree (so per-tool permissions carry over).
7. `gh issue comment <N> --body "Worktree created at \`<path>\`, branch \`<branch>\`"`
8. Print `cd <path>` for the user / agent to execute.

### 4.2 `list`

Run `git worktree list --porcelain`, decorate each entry with:
- branch name
- ahead/behind master count (`git rev-list --left-right --count origin/master...<branch>`)
- dirty marker (any modified or untracked files)
- `[orphan]` if the branch is gone from remote and never merged

### 4.3 `sync [<N>]`

Inside the worktree (or by issue number → resolve path):
- `git fetch origin master`
- `git rebase origin/master`
- On conflict: `git rebase --abort`, print message, exit code 3.

### 4.4 `finish`

Must run inside a worktree.
1. Refuse if working tree dirty or zero commits ahead of master.
2. `git push -u origin <branch>` (idempotent).
3. `gh pr create --base master --head <branch> --title "<title-from-issue>" --body "Closes #<N>\n\n<auto-body>"`
4. Print PR URL.
5. **Do NOT remove the worktree** — leaves room for review feedback fixes.

### 4.5 `clean <N>`

1. Resolve worktree path from issue number.
2. Refuse if worktree dirty (list modified files).
3. Refuse if `gh pr view <branch> --json state,mergedAt` shows non-merged.
4. `git worktree remove <path>`
5. `git branch -d <branch>` (safe delete, refuses unmerged).

### 4.6 Common flags

- `--verbose` / `-v` — extra debug output
- `--dry-run` — print intended actions, perform none
- `--help` / `-h` — usage

### 4.7 Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Generic error / usage |
| `2`  | Precondition failure (missing issue, gh not authed, etc.) |
| `3`  | Bad state (dirty tree, conflict, non-merged PR) |
| `4`  | Network / remote error (gh API, git push) |

## 5. CLAUDE.md Doctrine Section

A new section is inserted in `CLAUDE.md` after `## 🔑 Règles impératives` (or in an analogous location), titled `## 🌿 Multi-Agent Worktree Workflow — Obligatoire`. Its content:

1. **Base rule** — Any non-trivial work MUST happen in a dedicated worktree created via `scripts/agent-worktree.sh start --issue <#>`. The primary checkout is reserved for `master` housekeeping and human work.
2. **When to create a worktree:**
   - Any GitHub issue labeled `migration`, `hardware`, `api`, `frontend`, `security`, `infra`
   - Any task estimated > 30 min or touching ≥ 3 files
   - Any feature / fix that will end in a PR
3. **When NOT to create a worktree:**
   - Trivial single-file edits to tracking docs (`HISTORY.md`, `WIP.md`, `TODO.md`)
   - Read-only exploration, answering questions
   - Administrative commits on master (tags, version bumps)
4. **Mandatory cycle:**
   `gh issue create → agent-worktree.sh start → code+commits → agent-worktree.sh finish → user validates and merges → agent-worktree.sh clean`
5. **Parallel safety** — `start` refuses if another worktree already targets the same issue. Two Claude sessions in two terminals can safely work on two different issues at the same time.
6. **Commit messages** must include `(ref #<issue>)`. Co-authorship line stays as defined elsewhere in `CLAUDE.md`.
7. **Tracking files** — `WIP.md` is updated inside the worktree; `HISTORY.md` is updated on master after PR merge.
8. **Source of truth** for operational details: `scripts/agent-worktree.sh --help`.

## 6. Error Handling & Edge Cases

| Case | Behavior |
|------|----------|
| Issue does not exist (`gh issue view` fails) | Exit 2, clear message, no branch created |
| Issue already has an active worktree | Refuse, print existing path, suggest `cd` |
| Repo dirty at `start` time | Refuse, suggest commit/stash in current worktree |
| `gh` not authenticated | Detect early, point to `gh auth login` |
| Title is fully non-ASCII (empty slug) | Fallback `<prefix>/<#>-issue` |
| Slug collides with existing branch | Append `-2`, `-3`, … |
| `finish` with zero commits | Refuse |
| `finish` with branch not pushed | Auto `git push -u origin <branch>` |
| `clean` on dirty worktree | Refuse, list modified files |
| `clean` on open / unmerged PR | Refuse, print PR status |
| Rebase conflict during `sync` | `git rebase --abort`, exit 3, leave resolution to user |
| Orphan worktree (branch deleted upstream) | `list` marks `[orphan]`, `clean` detects and offers `--force` removal |
| `--dry-run` on any sub-command | Print planned commands, run none |

All error messages are in English (matches existing scripts under `scripts/`).

## 7. Testing

**Framework:** prefer `bats-core` if already present in `scripts/tests/`; otherwise a flat shell test script using `set -e` and trap-based assertions.

**Mocking:** Inject `GH_BIN` and `GIT_BIN` environment variables (or function shims) so tests run without hitting the real GitHub API and without polluting the actual repo. Use a temporary scratch repo per test via `git init` in `mktemp -d`.

**Test cases (target 12+):**

1. `start` happy path — valid issue → branch + worktree created, issue commented
2. `start` invalid issue (`gh` returns non-zero) → exit 2, no side effects
3. `start` with dirty repo → exit 3
4. `start` twice on same issue → second invocation refuses
5. Slug derivation: accented French title (`"Migration vérification à valider"`) → ASCII slug
6. Slug collision: pre-existing branch with same slug → suffix `-2`
7. `list` shows worktrees with ahead/behind and dirty markers
8. `sync` clean → rebase succeeds
9. `sync` with conflict → aborts, exit 3
10. `finish` zero commits → refuse
11. `clean` on open PR → refuse
12. `clean` on merged PR → removes worktree and local branch
13. `--dry-run start` → prints commands, leaves no branch / worktree
14. `--help` on each sub-command → non-zero only for unknown sub-commands

## 8. Implementation Order

1. Write `scripts/agent-worktree.sh` skeleton with sub-command dispatch and `--help`.
2. Implement `start` (slug derivation, label→prefix mapping, worktree add, issue comment).
3. Implement `list`.
4. Implement `sync`.
5. Implement `finish`.
6. Implement `clean`.
7. Write tests; iterate until all pass.
8. Add the new section to `CLAUDE.md`.
9. Update `scripts/README.md` with a "Multi-agent worktrees" section pointing at the script.
10. Create a tracking entry in `.claude/HISTORY.md` (date + summary).

## 9. Open Questions

None at design time. Any new question raised during implementation should be logged as a comment on the implementing GitHub issue and resolved before merging the corresponding PR.

## 10. References

- Existing `CLAUDE.md` section `## Synchronisation GitHub Issues — Workflow Obligatoire` — this design extends it with a worktree dimension.
- `superpowers:using-git-worktrees` skill — usable as a manual fallback, not invoked by this script.
- `git-worktree(1)` man page.
