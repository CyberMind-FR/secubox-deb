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


EXPECTED_HASH_HEADER = (
    "# SPDX-License-Identifier: LicenseRef-CMSD-1.0\n"
    "# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>\n"
    "# Source-Disclosed License — All rights reserved except as expressly granted.\n"
    "# See LICENCE-CMSD-1.0.md for terms.\n"
)


def test_render_header_hash():
    assert license_headers.render_header("hash") == EXPECTED_HASH_HEADER
