# scripts/license-headers.py
"""CMSD-1.0 license header tool.

Adds and verifies the SPDX-License-Identifier: LicenseRef-CMSD-1.0 header
on every first-party source file. See docs/superpowers/specs/2026-05-12-license-headers-design.md.
"""
from __future__ import annotations

import sys
from pathlib import Path


HEADER_LINES = (
    "SPDX-License-Identifier: LicenseRef-CMSD-1.0",
    "Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>",
    "Source-Disclosed License — All rights reserved except as expressly granted.",
    "See LICENCE-CMSD-1.0.md for terms.",
)


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


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("see Task 11")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
