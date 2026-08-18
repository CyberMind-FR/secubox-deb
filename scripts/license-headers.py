# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/license-headers.py
"""CMSD-1.0 license header tool.

Adds and verifies the SPDX-License-Identifier: LicenseRef-CMSD-1.0 header
on every first-party source file. See docs/superpowers/specs/2026-05-12-license-headers-design.md.
"""
from __future__ import annotations

import argparse
import difflib
import fnmatch
import re
import sys
from pathlib import Path


HEADER_LINES = (
    "SPDX-License-Identifier: LicenseRef-CMSD-1.0",
    "Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>",
    "Source-Disclosed License — All rights reserved except as expressly granted.",
    "See LICENCE-CMSD-1.0.md for terms.",
)


_CMSD_ID = "LicenseRef-CMSD-1.0"
# Matches an SPDX line only when preceded by comment markers and/or
# whitespace. Prevents false-matches when a docstring mentions the
# token "SPDX-License-Identifier:" in prose.
_SPDX_LINE_RE = re.compile(
    r"^[\s/*#<!\->]*\s*SPDX-License-Identifier:\s*(\S+)"
)

ENROLLMENT_FILE = "scripts/license-headers-enrolled.txt"


def detect_existing(text: str) -> str:
    """Return 'MATCH', 'FOREIGN', or 'NONE' based on the first 10 lines.

    Only lines whose non-whitespace content begins with comment markers
    (#, //, *, <!--, -->) and then an SPDX identifier count as a license
    declaration. Prose mentions inside docstrings are ignored.

    A leading YAML frontmatter block (``---`` … ``---``) is skipped first, so a
    header placed AFTER the frontmatter (where _place_markdown puts it) is still
    detected even when the frontmatter is longer than the scan window — without
    this, long-frontmatter Markdown gets a duplicate header on every run.
    """
    lines = text.splitlines()
    start = 0
    if lines and lines[0].rstrip() == "---":
        for i in range(1, len(lines)):
            if lines[i].rstrip() == "---":
                start = i + 1
                break
    for line in lines[start:start + 10]:
        match = _SPDX_LINE_RE.match(line)
        if match:
            return "MATCH" if match.group(1) == _CMSD_ID else "FOREIGN"
    return "NONE"


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


SKIP_DIRS = frozenset({
    "kernel-build", "redroid", "Tow-Boot",
    "output", "cache", "backups", "apt", "repo",
    "node_modules", ".venv", ".git", "__pycache__", "dist", "build",
    "vendor",  # code tiers vendore — jamais estampiller ni verifier
})

SKIP_GLOBS = (
    "*.min.js",
    "*.min.css",
    "package-lock.json",
    "*.lock",
)


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


def _place_python(header: str, text: str) -> str:
    lines = text.splitlines(keepends=True)
    insert_at = 0
    # Skip shebang
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    # Skip encoding declaration (PEP 263)
    if insert_at < len(lines) and re.match(r"^#.*coding[:=]", lines[insert_at]):
        insert_at += 1
    return "".join(lines[:insert_at]) + header + "\n" + "".join(lines[insert_at:])


def _place_shebang_hash(header: str, text: str) -> str:
    """Hash-comment language with a shebang line on line 1."""
    lines = text.splitlines(keepends=True)
    insert_at = 1 if lines and lines[0].startswith("#!") else 0
    return "".join(lines[:insert_at]) + header + "\n" + "".join(lines[insert_at:])


def _place_top(header: str, text: str) -> str:
    """Insert header at line 1 with one blank line separator."""
    return header + "\n" + text


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


_PLACERS = {
    "python": _place_python,
    "shebang_hash": _place_shebang_hash,
    "top": _place_top,
    "html": _place_html,
    "markdown": _place_markdown,
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


def walk(paths: list[Path], enrolled: list[str], repo_root: Path | None = None):
    """Yield in-scope files under each path, honoring SKIP_DIRS, SKIP_GLOBS, allowlist.

    `repo_root` (when provided) is the base for allowlist pattern matching.
    Allowlist patterns are repo-relative, so a caller walking a subdirectory
    must pass `repo_root` separately for the patterns to match. When omitted,
    paths are matched relative to their walk root (backwards-compatible).
    """
    allowlist_base = repo_root.resolve() if repo_root is not None else None
    for root in paths:
        root = Path(root)
        if root.is_file():
            if not _is_in_scope(root):
                continue
            rel = (
                root.resolve().relative_to(allowlist_base)
                if allowlist_base is not None
                else root
            )
            if _matches_allowlist(rel, enrolled):
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
            if allowlist_base is not None:
                try:
                    rel = p.resolve().relative_to(allowlist_base)
                except ValueError:
                    continue
            else:
                rel = p.relative_to(root)
            if not _matches_allowlist(rel, enrolled):
                continue
            yield p


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    while cur != cur.parent:
        if (cur / ".git").exists():
            return cur
        cur = cur.parent
    return start


def _read_enrollment(repo_root: Path) -> list[str]:
    """Return enrollment patterns from scripts/license-headers-enrolled.txt.

    Phase semantics (per spec §5.2):
      * Missing file → ["**"]  — repo-wide enforcement (Phase C final state)
      * File exists, empty / only comments → []  — nothing enforced (Phase A initial)
      * File with patterns → those patterns
    """
    f = repo_root / ENROLLMENT_FILE
    if not f.exists():
        return ["**"]
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
    for p in walk(paths, enrolled, repo_root=repo_root):
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
