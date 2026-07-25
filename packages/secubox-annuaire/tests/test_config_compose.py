# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_config_compose.py
Tests for annuaire.config_compose — deep-merge layering (baseline < override < local).
All tests follow TDD: written before implementation.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import tomllib

from annuaire.config_compose import compose, deep_merge


def test_deep_merge_tables_recursive_scalars_replaced():
    base = {"net": {"a": 1, "b": 2}, "x": 1, "lst": [1, 2]}
    over = {"net": {"b": 9, "c": 3}, "x": 5, "lst": [7]}
    assert deep_merge(base, over) == {"net": {"a": 1, "b": 9, "c": 3}, "x": 5, "lst": [7]}


def test_compose_precedence_local_top():
    baseline = 'x = 1\n[net]\na = 1\nb = 1\n'
    override = '[net]\nb = 2\n'
    local = 'x = 9\n'
    out = tomllib.loads(compose([baseline, override, local]))
    assert out["x"] == 9              # local wins
    assert out["net"]["a"] == 1       # baseline survives
    assert out["net"]["b"] == 2       # override wins over baseline


def test_compose_empty_layers():
    assert compose([]).strip() == ""
