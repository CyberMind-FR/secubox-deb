<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — CMSD-1.0 License Headers Across the Codebase

**Date:** 2026-05-12
**Status:** Approved by user (sections 1–5), pending plan
**Author:** Claude (brainstormed with @CyberMind-FR)
**Tracking:** GitHub Issue TBD (created at start of Phase A)

---

## 1. Goal

Add the CyberMind Source-Disclosed License v1.0 (CMSD-1.0) SPDX header to every first-party source file in the `secubox-deb` repository, and keep it that way going forward with a CI check.

Today the canonical header template lives in `LICENSING.md` (lines 70–75) but **zero of ~2,170 first-party code files** carry it. This design closes that gap mechanically, idempotently, and reviewably.

## 2. Scope

### 2.1 File types in scope

| Extension(s) | Comment style | Count (approx.) |
|---|---|---|
| `.py` | `#` line comments | 865 |
| `.sh` | `#` line comments | 122 |
| `.js`, `.mjs`, `.ts` | `//` line comments | 613 |
| `.c`, `.h` | `/* ... */` block (C89-safe) | 86 |
| `.css` | `/* ... */` block | 100 |
| `.html` | `<!-- ... -->` block | 384 |
| `.md` | `<!-- ... -->` block | (many) |
| `.toml`, `.yaml`, `.yml`, `.conf` | `#` line comments | (some) |

JSON is **out of scope** (no comment syntax).

### 2.2 Paths excluded (skip-list)

Hard-coded directory prefixes the walker never descends into:

- `kernel-build/`, `redroid/`, `tools/Tow-Boot/` — vendor/upstream code with its own licenses
- `output/`, `cache/`, `backups/`, `apt/`, `repo/` — generated/build artifacts
- `node_modules/`, `.venv/`, `.git/`, `__pycache__/`, `dist/`, `build/` — tool-managed trees

Glob excludes:

- `*.min.js`, `*.min.css` — minified bundles
- `package-lock.json`, `*.lock` — lockfiles
- Any file whose first 10 lines already contain `SPDX-License-Identifier: ` followed by **something other than** `LicenseRef-CMSD-1.0` → skipped with a warning to stderr (do not overwrite third-party licenses)

### 2.3 Out of scope (explicitly)

- Modifying the CMSD-1.0 license terms themselves
- Adding the header to the LICENSE files (they already define the license)
- Re-licensing any third-party code
- A "remove header" mode — not needed

## 3. Header content

The canonical 4-line header, parameterized by language comment marker (`<CM>`):

```
<CM> SPDX-License-Identifier: LicenseRef-CMSD-1.0
<CM> Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
<CM> Source-Disclosed License — All rights reserved except as expressly granted.
<CM> See LICENCE-CMSD-1.0.md for terms.
```

Followed by **one blank line**, then the file's pre-existing content.

### 3.1 Per-language rendering

| Language | Rendered as |
|---|---|
| Python, Bash, YAML, TOML, conf | Four `# ` prefixed lines |
| JS, TS, MJS | Four `// ` prefixed lines |
| C, H | Single `/* ... */` block, internal lines prefixed ` * ` |
| CSS | Single `/* ... */` block, internal lines prefixed ` * ` |
| HTML, Markdown | Single `<!-- ... -->` block, internal lines indented 2 spaces |

### 3.2 Placement rules

The header MUST appear at the top of the file, with the following exceptions:

| File type | Header goes... |
|---|---|
| Python with `#!` shebang | Immediately after the shebang line |
| Python with `# -*- coding: ... -*-` | Immediately after the encoding declaration |
| Bash with `#!` shebang | Immediately after the shebang line |
| JS/TS with `"use strict"` or top-level directive | Above the directive (header at line 1) |
| HTML with `<!DOCTYPE html>` | Immediately after the doctype, on its own line |
| Markdown with YAML frontmatter `---` | Immediately after the closing `---` |
| All others | Line 1 |

## 4. The tool — `scripts/license-headers.py`

Single-file Python 3.11+ utility, **stdlib only** (`argparse`, `pathlib`, `re`, `sys`).

### 4.1 CLI

```
license-headers.py --check [PATHS...]    # exit 0 if all good, 1 if missing
license-headers.py --fix   [PATHS...]    # add headers in place; idempotent
license-headers.py --list  [PATHS...]    # dry-run: list files that would be modified
license-headers.py --diff  [PATHS...]    # unified diff per file, no writes
```

- Default `PATHS` = repo root (cwd-relative).
- The repo root is detected by walking up from cwd to the nearest `.git/`.
- Mode flags are mutually exclusive; exactly one is required.
- During `--check`, the enrollment allowlist (see §5) constrains which paths are evaluated.

### 4.2 Internal structure (~300 LOC, one file)

| Component | Responsibility |
|---|---|
| `SKIP_DIRS: frozenset[str]` | Dirnames the walker prunes (§2.2 directory list) |
| `SKIP_GLOBS: tuple[str, ...]` | Glob patterns for excluded files |
| `LANG_TABLE: dict[str, LangSpec]` | Maps `.ext` → `(comment_style, placement_rule, header_renderer)` |
| `detect_existing(text) -> Status` | Returns `MATCH` / `FOREIGN` / `NONE` based on first 10 lines |
| `render_header(comment_style) -> str` | Builds the 4-line block for one language |
| `apply(text, ext) -> str` | Pure function: input file content → output content with header inserted at correct position |
| `walk(paths, enrolled) -> Iterator[Path]` | Yields in-scope files, honoring skip-list and enrollment allowlist |
| `main()` | Argparse dispatch |

### 4.3 Idempotence contract

```
apply(apply(text, ext), ext) == apply(text, ext)
```

Explicitly tested. Detection is based on matching the literal token `SPDX-License-Identifier: LicenseRef-CMSD-1.0` anywhere in the first 10 lines, tolerant of comment-marker variation and whitespace.

### 4.4 Tests — `tests/test_license_headers.py` (pytest)

1. `apply` is idempotent for every extension in `LANG_TABLE`.
2. Shebang, doctype, frontmatter, and encoding declarations are preserved in their original position.
3. Foreign SPDX (e.g., `GPL-2.0-or-later`, `MIT`) → file returned unchanged; warning emitted.
4. Existing CMSD header is not duplicated, regardless of comment style variation.
5. `--check` exits 1 when any in-scope file lacks the header.
6. `SKIP_DIRS` are pruned: a file under `kernel-build/` is never yielded by `walk`.

All tests run without filesystem side effects (use `tmp_path` fixtures and string inputs to `apply`).

## 5. CI integration

### 5.1 Workflow — `.github/workflows/license-check.yml`

```yaml
name: License Headers
on:
  pull_request:
  push:
    branches: [master]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: python3 scripts/license-headers.py --check
```

No `pip install`; runs in <10s.

### 5.2 Enrollment allowlist

To avoid breaking CI before Phase B is complete, the `--check` mode reads an **enrollment allowlist** at `scripts/license-headers-enrolled.txt`:

- One glob pattern per line (e.g., `common/**`, `packages/secubox-hub/**`).
- Lines starting with `#` are comments.
- Empty/missing file → nothing is enforced (Phase A initial state).
- File contains `**` only → repo-wide enforcement (Phase C final state).
- File deleted at end of Phase C; tool then defaults to repo-wide.

Phase B PRs each add one line to this file as they enroll a path.

### 5.3 Optional pre-commit hook

Documented in `scripts/README.md`; not installed by default:

```yaml
- repo: local
  hooks:
    - id: license-headers
      name: License Headers (CMSD-1.0)
      entry: python3 scripts/license-headers.py --fix
      language: system
      pass_filenames: true
```

## 6. Rollout

### 6.1 Phase A — Foundation (1 PR, GitHub Issue, label: `infra`)

Deliverables:
1. `scripts/license-headers.py` (the tool)
2. `tests/test_license_headers.py` (unit tests)
3. `.github/workflows/license-check.yml` (CI)
4. `scripts/license-headers-enrolled.txt` (initial empty enrollment)
5. `scripts/README.md` updated to document the tool and pre-commit hook
6. `CLAUDE.md` Python and Bash convention examples updated to show the SPDX block above the existing docstring/shebang preamble (replaces the current "License: Proprietary / ANSSI CSPN candidate" line in the Python example)
7. The tool's own files (`license-headers.py`, test file, workflow) carry the CMSD header (sanity check of `--fix`)

CI passes because the enrollment allowlist is empty.

### 6.2 Phase B — Per-package enrollment (~16 PRs, label: `migration`)

One PR per scope, each PR:
1. Runs `python3 scripts/license-headers.py --fix <path>`
2. Adds `<path>/**` to `scripts/license-headers-enrolled.txt`
3. Commits with message `chore(license): enroll <path> in CMSD header check (ref #NNN)`
4. PR description summarizes file counts touched

PR list:
- 14 PRs for `packages/secubox-*` (one per package)
- 1 PR for `common/` + `api/`
- 1 PR for `scripts/` + `image/` + `board/` + top-level files (`*.py`, `*.sh` at root)
- 1 PR for `docs/` + `.claude/` + Markdown files repo-wide
- (Optional) 1 PR for commentable configs (`*.toml`, `*.yaml`, `*.conf` outside packages already covered)

### 6.3 Phase C — Closure (1 PR, label: `infra`)

1. Delete `scripts/license-headers-enrolled.txt`
2. Update `LICENSING.md` with a note: *"All source files carry the CMSD-1.0 SPDX header; see `scripts/license-headers.py`."*
3. Run `--check` repo-wide locally before merging.

## 7. Verification

### 7.1 Phase A smoke tests (before merging the PR)

| # | Command | Expected |
|---|---|---|
| 1 | `python3 scripts/license-headers.py --diff common/secubox_core/auth.py` | Clean 5-line addition above the docstring |
| 2 | `python3 scripts/license-headers.py --diff scripts/deploy.sh` | Header lands after `#!/usr/bin/env bash` |
| 3 | `python3 scripts/license-headers.py --diff packages/secubox-hub/www/index.html` | Header lands after `<!DOCTYPE html>` |
| 4 | Run `--fix` on a file, then `--fix` again | Second run produces no changes (idempotence) |
| 5 | Create temp file with `# SPDX-License-Identifier: MIT` | Tool skips with stderr warning |
| 6 | `pytest tests/test_license_headers.py` | All 6 tests pass |

### 7.2 Per-PR verification in Phase B

1. Reviewer eyeballs ~5 randomly-sampled files in the PR diff for correct placement.
2. For Python packages with existing `pytest` suites: run the package's tests after applying headers — confirms no syntactic breakage.
3. For Bash scripts touched: `bash -n <file>` for each, no syntax errors.
4. CI's `--check` step passes (with the newly enrolled path).

### 7.3 Phase C verification

1. Locally: with the allowlist file removed, `python3 scripts/license-headers.py --check` exits 0.
2. Create a deliberately header-less throwaway file → CI fails as expected → remove it before merging.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Header insertion breaks file syntax (e.g., HTML doctype, Bash shebang) | Placement rules in §3.2; tested case-by-case in §4.4 |
| Third-party file accidentally gets re-licensed | Foreign SPDX detection skips and warns (§2.2) |
| Future contributors forget headers | CI check on every PR (§5.1) |
| Tool itself has bugs that corrupt files | Pure `apply()` function fully unit-tested; `--diff` mode lets reviewers eyeball before any write |
| OpenWrt frontend parity diffs grow noisy | Acceptable trade-off accepted in clarifying questions; mitigated by per-package PR shape |
| Vendor/build trees accidentally enrolled | `SKIP_DIRS` enforced even when `**` is in the allowlist |

## 9. Open questions

None at design time. Any deviations during implementation should be raised as comments on the tracking GitHub Issue.

## 10. References

- `LICENSING.md` — canonical license summary and header template
- `LICENCE-CMSD-1.0.md` (FR, authoritative) / `LICENSE-CMSD-1.0.en.md` (EN, informative)
- `CLAUDE.md` — project conventions (to be updated in Phase A)
- REUSE specification: <https://reuse.software/spec/> (informational; we use a custom `LicenseRef-` SPDX identifier)
