# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.test_prompt_lines — découpage du prompt en lignes pour
le composer (une ligne = un `type()`, une transition = une touche saut de
ligne).
"""

from __future__ import annotations

from webllm.session import split_prompt_lines


def test_single_line_prompt_is_not_split():
    assert split_prompt_lines("bonjour") == ["bonjour"]


def test_multiline_unix_prompt_splits_on_newline():
    assert split_prompt_lines("ligne1\nligne2\nligne3") == [
        "ligne1",
        "ligne2",
        "ligne3",
    ]


def test_windows_line_endings_are_normalized_before_splitting():
    assert split_prompt_lines("ligne1\r\nligne2\r\n") == ["ligne1", "ligne2", ""]


def test_empty_prompt_yields_a_single_empty_line():
    assert split_prompt_lines("") == [""]


def test_blank_lines_in_the_middle_are_preserved():
    assert split_prompt_lines("a\n\nb") == ["a", "", "b"]
