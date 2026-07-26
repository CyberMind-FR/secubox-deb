# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: release.boxapply — 4R ring switch for the box's apt sources.

Writes ONLY the ring drop-in (/etc/apt/sources.list.d/secubox-ring.list), never
the main sources.list. Shadow → validate (apt update) → atomic swap → rollback
on failure, so a bad ring never bricks the box.
"""
from __future__ import annotations

import os
import shutil

from annuaire.model import RINGS  # ring names

RING_LIST_PATH = "/etc/apt/sources.list.d/secubox-ring.list"
APT_BASE_URL = "https://apt.secubox.in"


class ApplyError(Exception):
    """apt validation failed; the prior ring was restored."""


def sources_line(ring: str) -> str:
    if ring not in RINGS:
        raise ValueError(f"ring must be one of {RINGS}")
    return f"deb {APT_BASE_URL} {ring} main contrib"


def apply_4r(ring, target_path, apt_update_fn) -> dict:
    shadow = target_path + ".shadow"
    rollback = target_path + ".rollback"
    prior = None
    if os.path.exists(target_path):
        prior = open(target_path).read()
        shutil.copy(target_path, rollback)
    with open(shadow, "w") as fh:
        fh.write(sources_line(ring) + "\n")
    ok = False
    try:
        ok = bool(apt_update_fn(shadow))
    except Exception:
        ok = False
    if not ok:
        # restore prior ring; drop the shadow
        if prior is not None:
            with open(target_path, "w") as fh:
                fh.write(prior)
        try:
            os.remove(shadow)
        except OSError:
            pass
        raise ApplyError(f"apt validation failed for ring {ring!r}; restored prior")
    os.replace(shadow, target_path)  # atomic
    return {"ring": ring, "applied": True}
