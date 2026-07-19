# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — snapshot 4R (état pré-apply, pour rollback)
CyberMind — https://cybermind.fr

Avant tout apply on capture l'état réel des modules DU PLAN (pas toute la box)
dans R1, en décalant R1→R2→R3→R4 (R1 = le plus récent). Pour un module portail
on capture aussi la valeur de sa route WAF, sinon le rollback ne saurait pas la
recréer.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .observe import is_on

SNAP_DIR = Path("/var/lib/secubox/profiles/rollback")
_SLOTS = ["R1", "R2", "R3", "R4"]


def _write_atomic(path: Path, data: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".snap-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def capture(plan, manifests, actuals, *, now, routes, root: Path = SNAP_DIR) -> dict:
    root = Path(root)
    ids = [c.id for c in plan]
    modules = {}
    for mid in ids:
        m = manifests.get(mid)
        a = actuals.get(mid)
        if m is None or a is None:
            continue
        entry = {"on": is_on(a)}
        if m.portal_domain:
            entry["route"] = routes.get(m.portal_domain) if isinstance(routes, dict) else None
        modules[mid] = entry
    snap = {"ts": now, "modules": modules}

    # rotate R3→R4, R2→R3, R1→R2 (drop old R4), then write R1.
    for older, newer in zip(reversed(_SLOTS[1:]), reversed(_SLOTS[:-1])):
        src = root / f"{newer}.json"
        if src.exists():
            _write_atomic(root / f"{older}.json", json.loads(src.read_text(encoding="utf-8")))
    _write_atomic(root / "R1.json", snap)
    return snap


def read(target: str = "R1", *, root: Path = SNAP_DIR) -> dict:
    if target not in _SLOTS:
        raise ValueError(f"cible de rollback inconnue: {target} (attendu {_SLOTS})")
    p = Path(root) / f"{target}.json"
    return json.loads(p.read_text(encoding="utf-8"))
