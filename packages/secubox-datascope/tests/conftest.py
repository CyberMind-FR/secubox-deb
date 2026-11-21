# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests DataScope : marqueur `playwright` (tests navigateur, sautés sans Playwright ni Chromium)."""


def pytest_configure(config):
    config.addinivalue_line("markers", "playwright: test dans un vrai navigateur (Playwright + Chromium)")
