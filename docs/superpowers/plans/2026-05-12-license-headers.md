<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CMSD-1.0 License Headers — Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `scripts/license-headers.py` tool, its tests, the CI workflow, and update conventions docs — so that subsequent per-package PRs can simply run the tool and enroll their paths in the allowlist.

**Architecture:** A single-file stdlib Python tool with four CLI modes (`--check`/`--fix`/`--list`/`--diff`), language-aware comment rendering, idempotent `apply()`, and a per-path enrollment allowlist read by `--check`. CI runs `--check` on every PR. Phase B (per-package rollout) and Phase C (allowlist removal) are operational and out of scope for this plan.

**Tech Stack:** Python 3.11+ stdlib only (`argparse`, `pathlib`, `re`, `sys`, `difflib`, `fnmatch`), pytest for tests, GitHub Actions for CI.

**Spec:** `docs/superpowers/specs/2026-05-12-license-headers-design.md`

---

## File Structure

| Path | Responsibility |
|---|---|
| `scripts/license-headers.py` | The CLI tool: walk → detect → apply → write/check |
| `tests/test_license_headers.py` | pytest suite covering rendering, placement, idempotence, walker, CLI |
| `scripts/license-headers-enrolled.txt` | Empty allowlist file (one glob per line); read by `--check` |
| `.github/workflows/license-check.yml` | CI: runs `python3 scripts/license-headers.py --check` on PRs and pushes to master |
| `scripts/README.md` | Add a section documenting the tool, modes, and optional pre-commit hook |
| `CLAUDE.md` | Update Python and Bash convention examples to show the SPDX block above docstring/shebang |

The tool is intentionally one file. The plan keeps internal functions (`render_header`, `detect_existing`, `apply`, `walk`, `main`) testable as module-level callables — no class hierarchy.

---

## Conventions used in every task

- Working directory: repo root (`/home/reepost/CyberMindStudio/secubox-deb/secubox-deb`).
- Run pytest with `python3 -m pytest tests/test_license_headers.py -v` (or scope to one test with `::test_name`).
- Commit messages follow `feat:` / `test:` / `chore:` / `docs:` / `ci:` conventional prefixes, no Co-Authored-By unless the project standard requires it (CLAUDE.md does — include it).
- Every commit references the GitHub Issue created in Task 0 (e.g. `(ref #NN)`).

---

## Task 0: Create tracking GitHub Issue

**Files:** none yet.

- [ ] **Step 1: Create the issue**

```bash
gh issue create --title "Add CMSD-1.0 SPDX header to all first-party source files" \
  --body "$(cat <<'EOF'
## Context

Spec: docs/superpowers/specs/2026-05-12-license-headers-design.md
Plan: docs/superpowers/plans/2026-05-12-license-headers.md

Today 0 of ~2,170 first-party source files carry the CMSD-1.0 SPDX header documented in LICENSING.md. This issue tracks Phase A (tool + CI + conventions) and the subsequent per-package enrollment PRs.

## Phase A tasks

- [ ] Tool: scripts/license-headers.py
- [ ] Tests: tests/test_license_headers.py
- [ ] CI: .github/workflows/license-check.yml
- [ ] Empty enrollment allowlist: scripts/license-headers-enrolled.txt
- [ ] scripts/README.md documents the tool
- [ ] CLAUDE.md convention examples updated

## Phase B (separate PRs, one per package; tracked by sub-issues)

- [ ] 14 PRs for packages/secubox-* (one per package)
- [ ] common/ + api/
- [ ] scripts/ + image/ + board/ + top-level
- [ ] docs/ + .claude/ + Markdown

## Phase C (closure)

- [ ] Delete scripts/license-headers-enrolled.txt
- [ ] Note in LICENSING.md
EOF
)" --label "infra,documentation"
```

Expected: prints the issue URL. Capture the issue number into your scratch space (call it `$ISSUE`) — every subsequent commit message references it.

- [ ] **Step 2: Confirm**

```bash
gh issue list --state open | head -5
```

Expected: the new issue appears at the top.

---

## Task 1: Scaffold the tool file and the test file

**Files:**
- Create: `scripts/license-headers.py`
- Create: `tests/test_license_headers.py`

- [ ] **Step 1: Create the tool stub**

```python
# scripts/license-headers.py
"""CMSD-1.0 license header tool.

Adds and verifies the SPDX-License-Identifier: LicenseRef-CMSD-1.0 header
on every first-party source file. See docs/superpowers/specs/2026-05-12-license-headers-design.md.
"""
from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("see Task 9")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 2: Create the test file with one smoke test**

```python
# tests/test_license_headers.py
"""Tests for scripts/license-headers.py.

The tool's filename contains a hyphen so it is loaded via
importlib.util.spec_from_file_location rather than a normal import.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_TOOL_PATH = REPO_ROOT / "scripts" / "license-headers.py"

_spec = importlib.util.spec_from_file_location("license_headers", _TOOL_PATH)
license_headers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(license_headers)


def test_module_imports():
    assert hasattr(license_headers, "main")
```

- [ ] **Step 3: Run the smoke test**

```bash
python3 -m pytest tests/test_license_headers.py::test_module_imports -v
```

Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
chore(license): scaffold license-headers tool and test module (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `render_header()` for hash-comment languages (Python, Bash, YAML, TOML, conf)

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_license_headers.py`:

```python
EXPECTED_HASH_HEADER = (
    "# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "# Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "# See LICENCE-CMSD-1.0.md for terms.\n"
)


def test_render_header_hash():
    assert license_headers.render_header("hash") == EXPECTED_HASH_HEADER
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py::test_render_header_hash -v
```

Expected: FAIL with `AttributeError: module 'license-headers' has no attribute 'render_header'`.

- [ ] **Step 3: Implement `render_header()` minimally**

Add to `scripts/license-headers.py`, above `main()`:

```python
HEADER_LINES = (
    "SPDX-License-Identifier: LicenseRef-CMSD-1.0",
    "Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>",
    "Source-Disclosed License — All rights reserved except as expressly granted.",
    "See LICENCE-CMSD-1.0.md for terms.",
)


def render_header(style: str) -> str:
    if style == "hash":
        return "".join(f"# {line}\n" for line in HEADER_LINES)
    raise ValueError(f"unknown comment style: {style}")
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py::test_render_header_hash -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): render_header for hash-comment languages (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `render_header()` for slash, block, and HTML styles

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write three failing tests**

Append to `tests/test_license_headers.py`:

```python
EXPECTED_SLASH_HEADER = (
    "// SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "// Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "// See LICENCE-CMSD-1.0.md for terms.\n"
)

EXPECTED_BLOCK_HEADER = (
    "/*\n"
    " * SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    " * Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    " * Source-Disclosed License — All rights reserved except as expressly granted.\n"
    " * See LICENCE-CMSD-1.0.md for terms.\n"
    " */\n"
)

EXPECTED_HTML_HEADER = (
    "<!--\n"
    "  SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "  Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "  See LICENCE-CMSD-1.0.md for terms.\n"
    "-->\n"
)


def test_render_header_slash():
    assert license_headers.render_header("slash") == EXPECTED_SLASH_HEADER


def test_render_header_block():
    assert license_headers.render_header("block") == EXPECTED_BLOCK_HEADER


def test_render_header_html():
    assert license_headers.render_header("html") == EXPECTED_HTML_HEADER
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "render_header_slash or render_header_block or render_header_html" -v
```

Expected: 3 FAILs with `ValueError: unknown comment style`.

- [ ] **Step 3: Extend `render_header()`**

In `scripts/license-headers.py`, replace `render_header` with:

```python
def render_header(style: str) -> str:
    if style == "hash":
        return "".join(f"# {line}\n" for line in HEADER_LINES)
    if style == "slash":
        return "".join(f"// {line}\n" for line in HEADER_LINES)
    if style == "block":
        body = "".join(f" * {line}\n" for line in HEADER_LINES)
        return f"/*\n{body} */\n"
    if style == "html":
        body = "".join(f"  {line}\n" for line in HEADER_LINES)
        return f"<!--\n{body}-->\n"
    raise ValueError(f"unknown comment style: {style}")
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 5 passed (test_module_imports + 4 render tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): render_header for slash/block/html comment styles (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `detect_existing()` — MATCH / FOREIGN / NONE

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def test_detect_existing_none_on_empty():
    assert license_headers.detect_existing("") == "NONE"


def test_detect_existing_none_on_plain_code():
    assert license_headers.detect_existing("print('hello')\n") == "NONE"


def test_detect_existing_match_hash():
    text = EXPECTED_HASH_HEADER + "\nprint('hello')\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_match_slash():
    text = EXPECTED_SLASH_HEADER + "\nconsole.log('hi');\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_match_block():
    text = EXPECTED_BLOCK_HEADER + "\nint main(void) { return 0; }\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_match_html():
    text = EXPECTED_HTML_HEADER + "\n<html></html>\n"
    assert license_headers.detect_existing(text) == "MATCH"


def test_detect_existing_foreign_mit():
    text = "# SPDX-License-Identifier: MIT\nprint('hello')\n"
    assert license_headers.detect_existing(text) == "FOREIGN"


def test_detect_existing_foreign_gpl():
    text = "// SPDX-License-Identifier: GPL-2.0-or-later\nint x;\n"
    assert license_headers.detect_existing(text) == "FOREIGN"


def test_detect_existing_only_checks_first_10_lines():
    """A CMSD line buried deep in the file should NOT be treated as MATCH."""
    text = "\n".join(["# unrelated"] * 20) + "\n# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    assert license_headers.detect_existing(text) == "NONE"
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "detect_existing" -v
```

Expected: 9 FAILs.

- [ ] **Step 3: Implement `detect_existing()`**

Add to `scripts/license-headers.py`, near the top:

```python
import re

_SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
_CMSD_ID = "LicenseRef-CMSD-1.0"


def detect_existing(text: str) -> str:
    """Return 'MATCH', 'FOREIGN', or 'NONE' based on the first 10 lines."""
    head = "\n".join(text.splitlines()[:10])
    match = _SPDX_RE.search(head)
    if not match:
        return "NONE"
    return "MATCH" if match.group(1) == _CMSD_ID else "FOREIGN"
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: all tests pass (5 prior + 9 new = 14).

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): detect_existing distinguishes CMSD/foreign/none (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `LANG_TABLE` + `apply()` for plain Python

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def test_apply_python_plain():
    src = '"""Docstring."""\nprint("hi")\n'
    out = license_headers.apply(src, ".py")
    assert out == EXPECTED_HASH_HEADER + "\n" + src


def test_apply_python_idempotent():
    src = '"""Docstring."""\nprint("hi")\n'
    once = license_headers.apply(src, ".py")
    twice = license_headers.apply(once, ".py")
    assert once == twice


def test_apply_foreign_python_unchanged():
    src = "# SPDX-License-Identifier: MIT\nprint('x')\n"
    out = license_headers.apply(src, ".py")
    assert out == src
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "apply_python or apply_foreign" -v
```

Expected: 3 FAILs with `AttributeError: ... 'apply'`.

- [ ] **Step 3: Implement `LANG_TABLE` and `apply()` for `.py`**

Add to `scripts/license-headers.py`, above `main()`:

```python
# Maps file extension → (comment_style, placement_handler_name)
LANG_TABLE: dict[str, tuple[str, str]] = {
    ".py": ("hash", "python"),
}


def _place_python(header: str, text: str) -> str:
    lines = text.splitlines(keepends=True)
    insert_at = 0
    # Skip shebang
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    # Skip encoding declaration (PEP 263) on first or second line
    if insert_at < len(lines) and re.match(r"^#.*coding[:=]", lines[insert_at]):
        insert_at += 1
    return "".join(lines[:insert_at]) + header + "\n" + "".join(lines[insert_at:])


_PLACERS = {
    "python": _place_python,
}


def apply(text: str, ext: str) -> str:
    """Insert the CMSD header into `text` for files with extension `ext`.

    Returns `text` unchanged if a CMSD header is already present or if a
    foreign SPDX header is detected.
    """
    if ext not in LANG_TABLE:
        return text
    status = detect_existing(text)
    if status in ("MATCH", "FOREIGN"):
        return text
    style, placer_name = LANG_TABLE[ext]
    header = render_header(style)
    return _PLACERS[placer_name](header, text)
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 17 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): apply() for plain Python, with idempotence and foreign-skip (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `apply()` Python placement — shebang and encoding declaration

**Files:**
- Modify: `tests/test_license_headers.py`

The implementation in Task 5 already handles shebang and encoding declarations. This task is **verification tests only**.

- [ ] **Step 1: Write the placement tests**

Append to `tests/test_license_headers.py`:

```python
def test_apply_python_with_shebang():
    src = '#!/usr/bin/env python3\nprint("x")\n'
    out = license_headers.apply(src, ".py")
    assert out.startswith("#!/usr/bin/env python3\n")
    assert out.splitlines()[1] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_python_with_encoding():
    src = '# -*- coding: utf-8 -*-\nprint("x")\n'
    out = license_headers.apply(src, ".py")
    assert out.startswith("# -*- coding: utf-8 -*-\n")
    assert out.splitlines()[1] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_python_with_shebang_and_encoding():
    src = '#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\nprint("x")\n'
    out = license_headers.apply(src, ".py")
    lines = out.splitlines()
    assert lines[0] == "#!/usr/bin/env python3"
    assert lines[1] == "# -*- coding: utf-8 -*-"
    assert lines[2] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"
```

- [ ] **Step 2: Run**

```bash
python3 -m pytest tests/test_license_headers.py -k "shebang or encoding" -v
```

Expected: 3 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/test_license_headers.py
git commit -m "$(cat <<EOF
test(license): cover Python shebang and encoding-declaration placement (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `apply()` for Bash (shebang-aware)

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def test_apply_bash_with_shebang():
    src = '#!/usr/bin/env bash\nset -euo pipefail\necho "hi"\n'
    out = license_headers.apply(src, ".sh")
    assert out.startswith("#!/usr/bin/env bash\n")
    assert out.splitlines()[1] == "# SPDX-License-Identifier: LicenseRef-CMSD-1.0"


def test_apply_bash_without_shebang():
    src = 'echo "hi"\n'
    out = license_headers.apply(src, ".sh")
    assert out.startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n")


def test_apply_bash_idempotent():
    src = '#!/usr/bin/env bash\nset -e\n'
    once = license_headers.apply(src, ".sh")
    twice = license_headers.apply(once, ".sh")
    assert once == twice
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "apply_bash" -v
```

Expected: 3 FAILs (since `.sh` not yet in `LANG_TABLE`, `apply` returns input unchanged).

- [ ] **Step 3: Add Bash to `LANG_TABLE` and reuse the Python placer**

In `scripts/license-headers.py`:

```python
def _place_shebang_hash(header: str, text: str) -> str:
    """Hash-comment language with a shebang line on line 1."""
    lines = text.splitlines(keepends=True)
    insert_at = 1 if lines and lines[0].startswith("#!") else 0
    return "".join(lines[:insert_at]) + header + "\n" + "".join(lines[insert_at:])
```

Rename `_place_python` so the shebang+encoding logic stays Python-specific, and wire Bash to the new helper:

```python
LANG_TABLE: dict[str, tuple[str, str]] = {
    ".py": ("hash", "python"),
    ".sh": ("hash", "shebang_hash"),
}

_PLACERS = {
    "python": _place_python,
    "shebang_hash": _place_shebang_hash,
}
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 23 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): apply() for Bash with shebang-aware placement (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `apply()` for JS/TS, CSS, C/H

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def test_apply_javascript():
    src = 'console.log("hi");\n'
    out = license_headers.apply(src, ".js")
    assert out == EXPECTED_SLASH_HEADER + "\n" + src


def test_apply_typescript():
    src = 'const x: number = 1;\n'
    out = license_headers.apply(src, ".ts")
    assert out == EXPECTED_SLASH_HEADER + "\n" + src


def test_apply_css():
    src = 'body { color: red; }\n'
    out = license_headers.apply(src, ".css")
    assert out == EXPECTED_BLOCK_HEADER + "\n" + src


def test_apply_c():
    src = 'int main(void) { return 0; }\n'
    out = license_headers.apply(src, ".c")
    assert out == EXPECTED_BLOCK_HEADER + "\n" + src


def test_apply_idempotent_all_styles():
    cases = [
        (".js", 'console.log("x");\n'),
        (".ts", 'const x = 1;\n'),
        (".css", 'a { color: red; }\n'),
        (".c", 'int x;\n'),
        (".h", '#pragma once\n'),
    ]
    for ext, src in cases:
        once = license_headers.apply(src, ext)
        twice = license_headers.apply(once, ext)
        assert once == twice, f"non-idempotent for {ext}"
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "apply_javascript or apply_typescript or apply_css or apply_c or idempotent_all" -v
```

Expected: 5 FAILs.

- [ ] **Step 3: Extend `LANG_TABLE` and add a `top` placer**

In `scripts/license-headers.py`:

```python
def _place_top(header: str, text: str) -> str:
    """Insert header at line 1 with one blank line separator."""
    return header + "\n" + text


LANG_TABLE: dict[str, tuple[str, str]] = {
    ".py": ("hash", "python"),
    ".sh": ("hash", "shebang_hash"),
    ".js": ("slash", "top"),
    ".mjs": ("slash", "top"),
    ".ts": ("slash", "top"),
    ".css": ("block", "top"),
    ".c": ("block", "top"),
    ".h": ("block", "top"),
}

_PLACERS = {
    "python": _place_python,
    "shebang_hash": _place_shebang_hash,
    "top": _place_top,
}
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 28 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): apply() for JS/TS/CSS/C/H with idempotence (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `apply()` for HTML (doctype) and Markdown (frontmatter)

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def test_apply_html_no_doctype():
    src = '<html><body>hi</body></html>\n'
    out = license_headers.apply(src, ".html")
    assert out == EXPECTED_HTML_HEADER + "\n" + src


def test_apply_html_with_doctype():
    src = '<!DOCTYPE html>\n<html><body>hi</body></html>\n'
    out = license_headers.apply(src, ".html")
    lines = out.splitlines(keepends=True)
    assert lines[0] == "<!DOCTYPE html>\n"
    assert lines[1] == "<!--\n"
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in lines[2]


def test_apply_html_idempotent():
    src = '<!DOCTYPE html>\n<html></html>\n'
    once = license_headers.apply(src, ".html")
    twice = license_headers.apply(once, ".html")
    assert once == twice


def test_apply_markdown_plain():
    src = '# Title\n\nBody.\n'
    out = license_headers.apply(src, ".md")
    assert out == EXPECTED_HTML_HEADER + "\n" + src


def test_apply_markdown_with_frontmatter():
    src = '---\ntitle: Foo\n---\n\n# Body\n'
    out = license_headers.apply(src, ".md")
    lines = out.splitlines(keepends=True)
    assert lines[0] == "---\n"
    assert lines[1] == "title: Foo\n"
    assert lines[2] == "---\n"
    assert lines[3] == "<!--\n"


def test_apply_markdown_idempotent_with_frontmatter():
    src = '---\ntitle: Foo\n---\n\nBody.\n'
    once = license_headers.apply(src, ".md")
    twice = license_headers.apply(once, ".md")
    assert once == twice
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "apply_html or apply_markdown" -v
```

Expected: 6 FAILs.

- [ ] **Step 3: Implement HTML and Markdown placers**

In `scripts/license-headers.py`:

```python
def _place_html(header: str, text: str) -> str:
    lines = text.splitlines(keepends=True)
    insert_at = 0
    if lines and lines[0].lstrip().lower().startswith("<!doctype"):
        insert_at = 1
    return "".join(lines[:insert_at]) + header + "\n" + "".join(lines[insert_at:])


def _place_markdown(header: str, text: str) -> str:
    """Place after YAML frontmatter if present, else at top."""
    lines = text.splitlines(keepends=True)
    insert_at = 0
    if lines and lines[0].rstrip() == "---":
        for i in range(1, len(lines)):
            if lines[i].rstrip() == "---":
                insert_at = i + 1
                break
    return "".join(lines[:insert_at]) + header + "\n" + "".join(lines[insert_at:])
```

Extend the tables:

```python
LANG_TABLE: dict[str, tuple[str, str]] = {
    ".py": ("hash", "python"),
    ".sh": ("hash", "shebang_hash"),
    ".js": ("slash", "top"),
    ".mjs": ("slash", "top"),
    ".ts": ("slash", "top"),
    ".css": ("block", "top"),
    ".c": ("block", "top"),
    ".h": ("block", "top"),
    ".html": ("html", "html"),
    ".htm": ("html", "html"),
    ".md": ("html", "markdown"),
    ".toml": ("hash", "top"),
    ".yaml": ("hash", "top"),
    ".yml": ("hash", "top"),
    ".conf": ("hash", "top"),
}

_PLACERS = {
    "python": _place_python,
    "shebang_hash": _place_shebang_hash,
    "top": _place_top,
    "html": _place_html,
    "markdown": _place_markdown,
}
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 34 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): apply() for HTML (doctype) and Markdown (frontmatter), plus TOML/YAML/conf (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: `walk()` — skip-list and enrollment allowlist

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def test_walk_finds_python(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.txt").write_text("ignore me\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "a.py" in result
    assert tmp_path / "b.txt" not in result


def test_walk_prunes_kernel_build(tmp_path):
    (tmp_path / "kernel-build").mkdir()
    (tmp_path / "kernel-build" / "a.c").write_text("int x;\n")
    (tmp_path / "real.c").write_text("int y;\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "real.c" in result
    assert tmp_path / "kernel-build" / "a.c" not in result


def test_walk_prunes_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("// vendor\n")
    (tmp_path / "src.js").write_text("// app\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "src.js" in result
    assert tmp_path / "node_modules" / "lib.js" not in result


def test_walk_skips_minified(tmp_path):
    (tmp_path / "app.min.js").write_text("// min\n")
    (tmp_path / "app.js").write_text("// raw\n")
    result = list(license_headers.walk([tmp_path], enrolled=["**"]))
    assert tmp_path / "app.js" in result
    assert tmp_path / "app.min.js" not in result


def test_walk_respects_empty_allowlist(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = list(license_headers.walk([tmp_path], enrolled=[]))
    assert result == []


def test_walk_respects_glob_allowlist(tmp_path):
    (tmp_path / "common").mkdir()
    (tmp_path / "common" / "a.py").write_text("x = 1\n")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "b.py").write_text("y = 1\n")
    result = list(license_headers.walk([tmp_path], enrolled=["common/**"]))
    rel = sorted(p.relative_to(tmp_path).as_posix() for p in result)
    assert rel == ["common/a.py"]
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "walk" -v
```

Expected: 6 FAILs with `AttributeError: ... 'walk'`.

- [ ] **Step 3: Implement `walk()`**

Add to `scripts/license-headers.py`:

```python
import fnmatch

SKIP_DIRS = frozenset({
    "kernel-build", "redroid", "Tow-Boot",
    "output", "cache", "backups", "apt", "repo",
    "node_modules", ".venv", ".git", "__pycache__", "dist", "build",
})

SKIP_GLOBS = (
    "*.min.js",
    "*.min.css",
    "package-lock.json",
    "*.lock",
)


def _is_in_scope(path: Path) -> bool:
    """True iff `path` has an extension in LANG_TABLE and matches no skip glob."""
    if path.suffix not in LANG_TABLE:
        return False
    name = path.name
    for pat in SKIP_GLOBS:
        if fnmatch.fnmatch(name, pat):
            return False
    return True


def _matches_allowlist(rel: Path, enrolled: list[str]) -> bool:
    """True iff `rel` matches any glob in `enrolled`."""
    rel_str = rel.as_posix()
    for pat in enrolled:
        if fnmatch.fnmatch(rel_str, pat):
            return True
        # Allow "common/**" to match "common/a.py"
        if pat.endswith("/**") and (
            rel_str == pat[:-3] or rel_str.startswith(pat[:-2])
        ):
            return True
    return False


def walk(paths: list[Path], enrolled: list[str]):
    """Yield in-scope files under each path, honoring SKIP_DIRS, SKIP_GLOBS, allowlist."""
    for root in paths:
        root = Path(root)
        if root.is_file():
            if _is_in_scope(root):
                yield root
            continue
        for p in root.rglob("*"):
            # Prune skip-dirs
            if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
                continue
            if not p.is_file():
                continue
            if not _is_in_scope(p):
                continue
            rel = p.relative_to(root)
            if not _matches_allowlist(rel, enrolled):
                continue
            yield p
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 40 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): walk() with skip-list and enrollment allowlist (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: CLI dispatch — `--check`, `--fix`, `--list`, `--diff`

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_license_headers.py`:

```python
def _write_enrolled(tmp_path: Path, patterns: list[str]) -> Path:
    f = tmp_path / "scripts" / "license-headers-enrolled.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("\n".join(patterns) + "\n")
    return f


def test_main_check_clean_repo(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text(EXPECTED_HASH_HEADER + "\nx = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--check"])
    assert rc == 0


def test_main_check_dirty_repo(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--check"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "a.py" in out


def test_main_fix_writes_files(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    f = tmp_path / "a.py"
    f.write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--fix"])
    assert rc == 0
    text = f.read_text()
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in text


def test_main_list(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "a.py" in out


def test_main_diff(tmp_path, monkeypatch, capsys):
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, ["**"])
    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--diff"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in out
    # File was not modified by --diff
    assert (tmp_path / "a.py").read_text() == "x = 1\n"


def test_main_modes_mutually_exclusive():
    rc = license_headers.main(["--check", "--fix"])
    assert rc == 2


def test_main_requires_a_mode():
    rc = license_headers.main([])
    assert rc == 2


def test_main_empty_allowlist_passes_check(tmp_path, monkeypatch):
    """An empty enrollment file means nothing is checked — Phase A initial state."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir(exist_ok=True)
    _write_enrolled(tmp_path, [])
    (tmp_path / "a.py").write_text("x = 1\n")  # no header, but not enrolled
    monkeypatch.chdir(tmp_path)
    rc = license_headers.main(["--check"])
    assert rc == 0
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_license_headers.py -k "main_" -v
```

Expected: 8 FAILs (`NotImplementedError` from the Task 1 stub).

- [ ] **Step 3: Implement the CLI**

Replace `main()` in `scripts/license-headers.py`. Also add helper for repo-root detection and allowlist reading.

```python
import argparse
import difflib

ENROLLMENT_FILE = "scripts/license-headers-enrolled.txt"


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / ".git").exists():
            return cur
        cur = cur.parent
    return start


def _read_enrollment(repo_root: Path) -> list[str]:
    f = repo_root / ENROLLMENT_FILE
    if not f.exists():
        return []
    patterns: list[str] = []
    for raw in f.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CMSD-1.0 license header tool")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--fix", action="store_true")
    mode.add_argument("--list", dest="list_", action="store_true")
    mode.add_argument("--diff", action="store_true")
    parser.add_argument("paths", nargs="*")

    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 2

    repo_root = _find_repo_root(Path.cwd())
    enrolled = _read_enrollment(repo_root)
    paths = [Path(p) for p in args.paths] if args.paths else [repo_root]

    missing: list[Path] = []
    for p in walk(paths, enrolled):
        text = p.read_text(encoding="utf-8", errors="replace")
        status = detect_existing(text)

        if status == "FOREIGN":
            print(f"skip (foreign SPDX): {p}", file=sys.stderr)
            continue

        if args.list_:
            if status == "NONE":
                print(p)
            continue

        if args.diff:
            if status == "NONE":
                new = apply(text, p.suffix)
                for line in difflib.unified_diff(
                    text.splitlines(keepends=True),
                    new.splitlines(keepends=True),
                    fromfile=str(p),
                    tofile=str(p),
                ):
                    sys.stdout.write(line)
            continue

        if args.fix:
            if status == "NONE":
                p.write_text(apply(text, p.suffix), encoding="utf-8")
            continue

        if args.check:
            if status == "NONE":
                missing.append(p)

    if args.check and missing:
        print("Files missing CMSD-1.0 header:")
        for p in missing:
            print(f"  {p}")
        return 1
    return 0
```

- [ ] **Step 4: Run to verify pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 48 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py
git commit -m "$(cat <<EOF
feat(license): CLI dispatch with --check/--fix/--list/--diff (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Self-host — apply header to the tool and the test file

**Files:**
- Modify: `scripts/license-headers.py`
- Modify: `tests/test_license_headers.py`
- Create: `scripts/license-headers-enrolled.txt`

- [ ] **Step 1: Create the empty enrollment file**

```bash
cat > scripts/license-headers-enrolled.txt <<'EOF'
# CMSD-1.0 license header enrollment allowlist.
# One glob per line (paths relative to repo root).
# Phase A initial state: empty — CI does not enforce headers yet.
# Phase B adds one line per package as they're enrolled.
# Phase C: this file is deleted; CI then enforces repo-wide.
EOF
```

- [ ] **Step 2: Temporarily enroll the tool's own files**

Append to `scripts/license-headers-enrolled.txt`:

```
scripts/license-headers.py
tests/test_license_headers.py
```

- [ ] **Step 3: Apply the header to itself**

```bash
python3 scripts/license-headers.py --diff scripts/license-headers.py tests/test_license_headers.py
```

Eyeball the diff. Then:

```bash
python3 scripts/license-headers.py --fix scripts/license-headers.py tests/test_license_headers.py
```

- [ ] **Step 4: Verify `--check` passes and tests still pass**

```bash
python3 scripts/license-headers.py --check
python3 -m pytest tests/test_license_headers.py -v
```

Expected: `--check` exits 0; pytest still 48 passed.

- [ ] **Step 5: Commit**

```bash
git add scripts/license-headers.py tests/test_license_headers.py scripts/license-headers-enrolled.txt
git commit -m "$(cat <<EOF
chore(license): self-host header on tool and tests + initial allowlist (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: GitHub Actions workflow

**Files:**
- Create: `.github/workflows/license-check.yml`

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/license-check.yml
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
        with:
          python-version: '3.11'
      - name: Verify CMSD-1.0 headers
        run: python3 scripts/license-headers.py --check
```

- [ ] **Step 2: Lint locally**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/license-check.yml'))"
```

Expected: no output (valid YAML). If `pyyaml` is missing: `pip install pyyaml --user` or skip — GitHub will validate on push.

- [ ] **Step 3: Apply the CMSD header to the workflow file**

The workflow is a YAML file in scope. Enroll it and apply:

Append to `scripts/license-headers-enrolled.txt`:

```
.github/workflows/license-check.yml
```

Then:

```bash
python3 scripts/license-headers.py --fix .github/workflows/license-check.yml
python3 scripts/license-headers.py --check
```

Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/license-check.yml scripts/license-headers-enrolled.txt
git commit -m "$(cat <<EOF
ci(license): add License Headers workflow (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Update `scripts/README.md`

**Files:**
- Modify: `scripts/README.md`

- [ ] **Step 1: Read the current README**

```bash
head -50 scripts/README.md
```

Locate the table of scripts (the file already documents each script in `scripts/`).

- [ ] **Step 2: Add a new section**

Append (or insert in the appropriate alphabetical position):

```markdown
## license-headers.py

CMSD-1.0 SPDX header tool. Adds, verifies, or previews license headers
on all first-party source files. Pure stdlib; no dependencies.

**Usage:**

```bash
python3 scripts/license-headers.py --check        # CI mode; exit 1 if missing
python3 scripts/license-headers.py --fix          # add headers in place
python3 scripts/license-headers.py --list         # list files that would be touched
python3 scripts/license-headers.py --diff         # unified diff per file (no writes)
python3 scripts/license-headers.py --fix common/  # scope to a path
```

**Enrollment allowlist:** `scripts/license-headers-enrolled.txt`. One glob
per line; `#`-prefixed lines are comments. Empty means no enforcement.
Phase A leaves it nearly empty; Phase B adds lines per package; Phase C
deletes it to enforce repo-wide.

**Optional pre-commit hook** (off by default):

```yaml
- repo: local
  hooks:
    - id: license-headers
      name: License Headers (CMSD-1.0)
      entry: python3 scripts/license-headers.py --fix
      language: system
      pass_filenames: true
```

**Spec:** `docs/superpowers/specs/2026-05-12-license-headers-design.md`.
```

- [ ] **Step 3: Commit**

```bash
git add scripts/README.md
git commit -m "$(cat <<EOF
docs(license): document license-headers.py in scripts/README (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Update `CLAUDE.md` convention examples

**Files:**
- Modify: `.claude/CLAUDE.md`

- [ ] **Step 1: Read the current Python and Bash convention blocks**

```bash
grep -n -A 8 "^### Python$" .claude/CLAUDE.md
grep -n -A 7 "^### Bash$" .claude/CLAUDE.md
```

- [ ] **Step 2: Replace the Python example**

Find this block in `.claude/CLAUDE.md`:

````markdown
### Python
```python
# Entête standard SecuBox-Deb
"""
SecuBox-Deb :: <NomModule>
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
```
````

Replace it with:

````markdown
### Python
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: <NomModule>
CyberMind — https://cybermind.fr
"""
```

The SPDX block is added/verified by `scripts/license-headers.py`.
````

- [ ] **Step 3: Replace the Bash example**

Find:

````markdown
### Bash
```bash
#!/usr/bin/env bash
# SecuBox-Deb :: <nom_script>
# CyberMind — Gérald Kerma
set -euo pipefail
readonly MODULE="<nom>"
readonly VERSION="<semver>"
```
````

Replace with:

````markdown
### Bash
```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: <nom_script>
set -euo pipefail
readonly MODULE="<nom>"
readonly VERSION="<semver>"
```
````

- [ ] **Step 4: Commit**

```bash
git add .claude/CLAUDE.md
git commit -m "$(cat <<EOF
docs(license): update Python/Bash convention examples to CMSD SPDX header (ref #$ISSUE)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Final smoke tests

**Files:** none modified.

- [ ] **Step 1: Tool runs cleanly on the whole repo**

```bash
python3 scripts/license-headers.py --check
echo "exit=$?"
```

Expected: `exit=0` (only the tool/test/workflow are enrolled and they're done).

- [ ] **Step 2: `--diff` on a real Python module shows clean addition**

```bash
python3 scripts/license-headers.py --diff common/secubox_core/auth.py
```

Expected: unified diff inserting 5 lines (4 header + 1 blank) at the top, above the existing docstring. No other changes.

Note: this file is **not** enrolled in the allowlist, so `--diff` will produce nothing. Temporarily test by overriding:

```bash
python3 -c "
import sys; sys.path.insert(0, 'scripts')
import importlib; m = importlib.import_module('license-headers')
src = open('common/secubox_core/auth.py').read()
new = m.apply(src, '.py')
import difflib
for l in difflib.unified_diff(src.splitlines(keepends=True), new.splitlines(keepends=True), fromfile='auth.py', tofile='auth.py'): sys.stdout.write(l)
"
```

Expected: shows the planned 5-line addition.

- [ ] **Step 3: `--diff` on a real Bash script places after shebang**

Same trick:

```bash
python3 -c "
import sys; sys.path.insert(0, 'scripts')
import importlib; m = importlib.import_module('license-headers')
src = open('scripts/deploy.sh').read()
new = m.apply(src, '.sh')
import difflib
for l in difflib.unified_diff(src.splitlines(keepends=True), new.splitlines(keepends=True), fromfile='deploy.sh', tofile='deploy.sh'): sys.stdout.write(l)
"
```

Expected: header inserted between `#!/usr/bin/env bash` (line 1) and the next comment block.

- [ ] **Step 4: `--diff` on a real HTML file places after doctype**

Find one HTML file with a doctype:

```bash
HTML=$(grep -rl "^<!DOCTYPE" packages/secubox-hub/www/ 2>/dev/null | head -1)
python3 -c "
import sys; sys.path.insert(0, 'scripts')
import importlib; m = importlib.import_module('license-headers')
src = open('$HTML').read()
new = m.apply(src, '.html')
import difflib
for l in difflib.unified_diff(src.splitlines(keepends=True), new.splitlines(keepends=True), fromfile='x', tofile='x'): sys.stdout.write(l)
"
```

Expected: doctype on line 1, `<!--` on line 2, header body, `-->`.

- [ ] **Step 5: Foreign SPDX is skipped**

```bash
cat > /tmp/mit_test.js <<'EOF'
// SPDX-License-Identifier: MIT
const x = 1;
EOF
python3 -c "
import sys; sys.path.insert(0, 'scripts')
import importlib; m = importlib.import_module('license-headers')
src = open('/tmp/mit_test.js').read()
print('detect:', m.detect_existing(src))
print('apply unchanged:', m.apply(src, '.js') == src)
"
rm /tmp/mit_test.js
```

Expected: `detect: FOREIGN`, `apply unchanged: True`.

- [ ] **Step 6: Idempotence on the tool itself**

```bash
python3 scripts/license-headers.py --fix scripts/license-headers.py
git diff --stat scripts/license-headers.py
```

Expected: no diff (tool already has its own header from Task 12).

- [ ] **Step 7: All unit tests pass**

```bash
python3 -m pytest tests/test_license_headers.py -v
```

Expected: 48 passed.

- [ ] **Step 8: No commit needed** — smoke tests only.

---

## Task 17: Update Issue and open Phase A PR

**Files:** none.

- [ ] **Step 1: Push the branch**

```bash
git push -u origin HEAD
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat(license): CMSD-1.0 header tool, CI, and conventions (Phase A)" \
  --body "$(cat <<EOF
## Summary

- Adds \`scripts/license-headers.py\`: stdlib-only tool with --check/--fix/--list/--diff
- Adds \`.github/workflows/license-check.yml\`: CI runs --check on PRs and master pushes
- Adds \`scripts/license-headers-enrolled.txt\`: enrollment allowlist (Phase A enrolls only the tool, its tests, and the workflow itself)
- Adds \`tests/test_license_headers.py\`: 48 pytest cases covering rendering, placement, idempotence, walker, CLI
- Updates \`scripts/README.md\` and \`.claude/CLAUDE.md\` to document the new SPDX convention

Phase B (per-package enrollment) will follow as separate PRs.

Spec: docs/superpowers/specs/2026-05-12-license-headers-design.md
Plan: docs/superpowers/plans/2026-05-12-license-headers.md
Refs #$ISSUE

## Test plan

- [ ] CI's License Headers workflow passes
- [ ] \`python3 -m pytest tests/test_license_headers.py -v\` → 48 passed
- [ ] \`python3 scripts/license-headers.py --check\` exits 0 locally
- [ ] \`--diff\` on a sample Python, Bash, and HTML file produces sane output (smoke-tested manually)
- [ ] Idempotence: running --fix twice on the same file produces no second diff
EOF
)"
```

- [ ] **Step 3: Comment on the tracking issue**

```bash
gh issue comment $ISSUE --body "Phase A implementation complete. PR: $(gh pr view --json url -q .url)"
```

---

## Phase B/C operational note (not in this plan)

After this plan ships, Phase B is mechanical per-package work. Each Phase B PR:

```bash
git checkout -b license/enroll-<package>
python3 scripts/license-headers.py --fix packages/secubox-<package>
echo "packages/secubox-<package>/**" >> scripts/license-headers-enrolled.txt
git add -A
git commit -m "chore(license): enroll secubox-<package> in CMSD header check (ref #$ISSUE)"
gh pr create --title "chore(license): enroll secubox-<package>" --body "..."
```

Phase C is one PR that deletes `scripts/license-headers-enrolled.txt` and adds a note to `LICENSING.md`.

---

## Self-review notes (post-write)

1. **Spec coverage:** §2 scope → Task 5-9. §3 header content → Task 2-3. §3.2 placement → Task 5-9 placers. §4 tool → Task 5-11. §4.4 6 test cases → all covered (idempotence, shebang/doctype/frontmatter preservation, foreign skip, no duplication, --check exit code, skip-dir pruning). §5 CI → Task 13 + 12 (allowlist). §6.1 Phase A deliverables → all 7 covered. §7.1 smoke tests → Task 16.
2. **Type consistency:** `apply(text, ext)`, `detect_existing(text)`, `render_header(style)`, `walk(paths, enrolled)`, `main(argv)`, `_PLACERS`, `LANG_TABLE` — names match across tasks. Comment styles `"hash"/"slash"/"block"/"html"` consistent. Placer names `"python"/"shebang_hash"/"top"/"html"/"markdown"` consistent.
3. **No placeholders:** every code/test block is concrete and runnable. No TODO/TBD.

## Execution Handoff

Plan complete and saved to [docs/superpowers/plans/2026-05-12-license-headers.md](docs/superpowers/plans/2026-05-12-license-headers.md).
