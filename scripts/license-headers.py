# scripts/license-headers.py
"""CMSD-1.0 license header tool.

Adds and verifies the SPDX-License-Identifier: LicenseRef-CMSD-1.0 header
on every first-party source file. See docs/superpowers/specs/2026-05-12-license-headers-design.md.
"""
from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("see Task 11")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
