# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: config_compose
Pure deep-merge composition of layered TOML config texts (#768 follow-on).

Three named layers stack in increasing precedence: baseline < override < local.
``deep_merge`` recurses into tables (dicts) so nested keys from a lower layer
survive unless a higher layer redefines them; scalars and lists are never
merged element-wise — the higher layer's value replaces the lower layer's
value outright. ``compose`` folds an ordered list of raw TOML texts (index 0
is the lowest precedence, the last is the highest) through ``deep_merge`` and
re-serializes the result to TOML text.

This module performs no file I/O and holds no state — callers (config_apply,
CLI, API) are responsible for reading layer texts from disk/mesh and writing
the composed result out.
"""
from __future__ import annotations

import tomllib

import tomli_w


def deep_merge(base: dict, over: dict) -> dict:
    """Recursively merge ``over`` on top of ``base``.

    Keys present only in ``base`` are kept. Keys present only in ``over`` are
    added. Keys present in both are merged recursively when both values are
    dicts; otherwise ``over``'s value replaces ``base``'s value verbatim
    (this includes lists — they are replaced, never concatenated).

    Neither input is mutated; a new dict is returned.
    """
    result = dict(base)
    for key, over_value in over.items():
        base_value = result.get(key)
        if isinstance(base_value, dict) and isinstance(over_value, dict):
            result[key] = deep_merge(base_value, over_value)
        else:
            result[key] = over_value
    return result


def compose(ordered_texts: list[str]) -> str:
    """Deep-merge a list of raw TOML texts and re-serialize to TOML.

    ``ordered_texts[0]`` has the lowest precedence, ``ordered_texts[-1]`` the
    highest. Empty or blank texts are skipped. An empty (or all-blank) list
    composes to the empty string.
    """
    merged: dict = {}
    for text in ordered_texts:
        if not text or not text.strip():
            continue
        layer = tomllib.loads(text)
        merged = deep_merge(merged, layer)
    if not merged:
        return ""
    return tomli_w.dumps(merged)
