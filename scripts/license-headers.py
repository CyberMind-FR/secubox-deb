# scripts/license-headers.py
"""CMSD-1.0 license header tool.

Adds and verifies the SPDX-License-Identifier: LicenseRef-CMSD-1.0 header
on every first-party source file. See docs/superpowers/specs/2026-05-12-license-headers-design.md.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


HEADER_LINES = (
    "SPDX-License-Identifier: LicenseRef-CMSD-1.0",
    "Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>",
    "Source-Disclosed License — All rights reserved except as expressly granted.",
    "See LICENCE-CMSD-1.0.md for terms.",
)


_SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
_CMSD_ID = "LicenseRef-CMSD-1.0"


def detect_existing(text: str) -> str:
    """Return 'MATCH', 'FOREIGN', or 'NONE' based on the first 10 lines."""
    head = "\n".join(text.splitlines()[:10])
    match = _SPDX_RE.search(head)
    if not match:
        return "NONE"
    return "MATCH" if match.group(1) == _CMSD_ID else "FOREIGN"


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


LANG_TABLE: dict[str, tuple[str, str]] = {
    ".py": ("hash", "python"),
    ".sh": ("hash", "shebang_hash"),
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


_PLACERS = {
    "python": _place_python,
    "shebang_hash": _place_shebang_hash,
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


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("see Task 11")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
